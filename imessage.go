// beeper-imessage - A Matrix-iMessage puppeting bridge.
// Copyright (C) 2021 Tulir Asokan
// Copyright (C) 2023 Beeper, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/google/uuid"
	"golang.org/x/exp/slices"
	"maunium.net/go/mautrix/bridge/status"
	"maunium.net/go/mautrix/event"

	"github.com/beeper/imessage/imessage"
	"github.com/beeper/imessage/imessage/direct"
)

func init() {
	status.BridgeStateHumanErrors.Update(status.BridgeStateErrorMap{
		"im-ids-register-fail":       "Internal error registering with iMessage.",
		"im-ids-not-registered":      "Missing iMessage registration.",
		"im-ids-refresh-credentials": "Credentials expired. Please use the Reconnect button to log in again.",
		"im-nacserv-not-configured":  "Please enter an iMessage registration code to use the bridge.",
		"im-nacserv-fail":            "Registration provider couldn't be reached when trying to reregister with iMessage.",
	})
}

func (user *User) HandleEvent(evt any) {
	start := time.Now()
	switch typedEvt := evt.(type) {
	case *imessage.Message:
		user.HandleMessage(typedEvt)
	case *imessage.MessageEdit:
		user.HandleMessageEdit(typedEvt)
	case *imessage.MessageUnsend:
		user.HandleMessageUnsend(typedEvt)
	case *imessage.GroupInfoChange:
		user.HandleGroupInfoChange(typedEvt)
	case *imessage.ReadReceipt:
		user.sendToPortalForGUID(typedEvt.ReadUpTo, typedEvt, "read receipt")
	case *imessage.MarkUnread:
		user.sendToPortalForGUID(typedEvt.MessageID, typedEvt, "mark unread")
	case *imessage.TypingNotification:
		user.HandleTypingNotification(typedEvt)
	case *imessage.SendMessageStatus:
		user.sendToPortalForGUID(typedEvt.GUID, typedEvt, "message status")
	case *direct.MessageDelivered:
		user.sendToPortalForGUID(typedEvt.ID, typedEvt, "message delivered")
	case *imessage.ChatDeleted:
		user.HandleChatDeleted(typedEvt)
	case *direct.IDSRegisterSuccess:
		user.BridgeState.Send(status.BridgeState{StateEvent: status.StateConnected})
	case *direct.IDSRegisterFail:
		user.BridgeState.Send(status.BridgeState{StateEvent: status.StateUnknownError, Error: "im-ids-register-fail"})
	case *direct.NACServFail:
		user.BridgeState.Send(status.BridgeState{StateEvent: status.StateBadCredentials, Error: "im-nacserv-fail"})
	case *direct.RefreshCredentialsRequired:
		user.BridgeState.Send(status.BridgeState{
			StateEvent: status.StateBadCredentials,
			Error:      "im-ids-refresh-credentials",
			Info: map[string]any{
				"refresh_profile_id": typedEvt.UserID,
			},
		})
	case *direct.InvalidSignature:
		payload := typedEvt.Payload
		user.sendBridgeNotice(
			false,
			"Failed to validate %s signature in message from %s/%s to %s of type %s. Reason: %v",
			payload.EncryptionType, payload.SenderID.String(),
			base64.StdEncoding.EncodeToString(payload.Token),
			payload.DestinationID.String(), payload.Command.String(),
			typedEvt.Error,
		)
	case *direct.SMSForwardingEnableRequestCode:
		user.sendBridgeNotice(true, "Code to enable SMS forwarding: %d", typedEvt.Code)
	case *direct.SMSForwardingToggled:
		if typedEvt.UD && typedEvt.G != nil {
			// This triggers a SendMessageStatus event too
		} else if typedEvt.UE {
			user.sendBridgeNotice(false, "SMS forwarding disabled")
		} else if typedEvt.AR {
			user.sendBridgeNotice(false, "SMS forwarding enabled")
		}
		user.BridgeState.Send(status.BridgeState{StateEvent: status.StateConnected})
	case *direct.ConfigUpdated:
		err := user.Update(context.TODO())
		if err != nil {
			user.zlog.Err(err).Msg("Failed to save user after apple registration update")
		}
	}
	user.zlog.Debug().
		Dur("handle_duration", time.Since(start)).
		Type("event_type", evt).
		Msg("Handled iMessage event")
}

func (user *User) sendBridgeNotice(important bool, text string, args ...any) {
	if !user.bridge.Config.Bridge.EnableBridgeNotices {
		return
	}
	msgtype := event.MsgNotice
	if important {
		msgtype = event.MsgText
	} else if !user.bridge.Config.Bridge.UnimportantBridgeNotices {
		return
	}
	_, _ = user.bridge.Bot.SendMessageEvent(user.GetOrCreateManagementRoom(), event.EventMessage, &event.MessageEventContent{
		MsgType: msgtype,
		Body:    fmt.Sprintf(text, args...),
	})
}

const PortalBufferTimeout = 10 * time.Second

func (user *User) HandleMessage(msg *imessage.Message) {
	user.log.Debugfln("Received incoming message %s in %s (%s)", msg.ID, msg.Chat, msg.GroupID)
	// This log is way too big when receiving attachments
	//user.zlog.Trace().Any("msg", msg).Msg("Received incoming message")
	portal := user.GetPortalByURI(msg.Chat)
	if len(portal.MXID) == 0 {
		portal.log.Infoln("Creating Matrix room to handle message")
		err := portal.CreateMatrixRoom(msg)
		if err != nil {
			user.log.Warnfln("Failed to create Matrix room to handle message: %v", err)
			return
		}
	}
	// TODO move this to a more sensible place
	changed := false
	if !slices.Equal(portal.Participants, msg.Participants) {
		portal.zlog.Debug().
			Any("old_participants", portal.Participants).
			Any("new_participants", msg.Participants).
			Msg("Participant list for portal changed")
		portal.Participants = msg.Participants
		portal.SyncParticipants(portal.Participants)
		changed = true
	}
	if portal.GroupID != msg.GroupID && msg.GroupID != "" {
		portal.zlog.Debug().
			Str("old_group_id", portal.GroupID).
			Str("new_group_id", msg.GroupID).
			Msg("Group ID for portal changed")
		portal.GroupID = msg.GroupID
		changed = true
	}
	if portal.Service != msg.Service {
		portal.zlog.Debug().
			Str("old_service", portal.Service.String()).
			Str("new_service", msg.Service.String()).
			Msg("Service for portal changed")
		portal.Service = msg.Service
		changed = true
	}
	if portal.OutgoingHandle != msg.Receiver {
		// TODO this may cause flipping if the user has multiple handles in the group
		//      -> only change outgoing handle if the previous outgoing handle isn't in the group?
		// Also applies to IPC side
		portal.OutgoingHandle = msg.Receiver
		changed = true
		portal.zlog.Debug().
			Str("old_handle", portal.OutgoingHandle.String()).
			Str("new_handle", msg.Receiver.String()).
			Msg("Outgoing handle for portal changed")
	}
	if changed {
		portal.UpdateBridgeInfo()
		// TODO don't ignore errors
		portal.Update(context.TODO())
	}
	select {
	case portal.Messages <- msg:
	case <-time.After(PortalBufferTimeout):
		user.log.Errorln("Portal message buffer is still full after 10 seconds, dropping message %s", msg.ID)
	}
}
func (user *User) HandleGroupInfoChange(msg *imessage.GroupInfoChange) {
	user.log.Debugfln("Received group info change %s in %s (%s)", msg.ID, msg.Chat, msg.GroupID)
	portal := user.GetPortalByURI(msg.Chat)
	select {
	case portal.Messages <- msg:
	case <-time.After(PortalBufferTimeout):
		user.log.Errorln("Portal message buffer is still full after 10 seconds, dropping message %s", msg.ID)
	}
}

func (user *User) sendToPortalForGUID(guid uuid.UUID, msg any, item string) {
	log := user.zlog.With().Str("message_id", guid.String()).Str("item", item).Logger()
	portalURI, err := user.bridge.DB.Message.GetPortalURIByID(context.TODO(), guid, user.RowID)
	if err != nil {
		log.Err(err).Msg("Failed to get portal URI")
		return
	} else if portalURI.IsEmpty() {
		log.Warn().Msg("Unknown message")
		return
	}
	portal := user.GetPortalByURI(portalURI)
	uriString := portalURI.String()
	if len(portal.MXID) == 0 {
		log.Debug().Str("portal_uri", uriString).Msg("Ignoring item in unknown portal")
		return
	}
	select {
	case portal.Messages <- msg:
	case <-time.After(PortalBufferTimeout):
		log.Error().Str("portalURI", uriString).Msg("Portal buffer is still full after 10 seconds, dropping")
	}
}

func (user *User) HandleMessageEdit(edit *imessage.MessageEdit) {
	log := user.zlog.With().Str("edit_message_id", edit.EditMessageID.String()).Logger()
	log.Debug().Msg("Received message edit")

	portalURI, err := user.bridge.DB.Message.GetPortalURIByID(context.TODO(), edit.EditMessageID, user.RowID)
	if err != nil {
		log.Err(err).Msg("Failed to get portal URI for message status")
		return
	} else if portalURI.IsEmpty() {
		log.Warn().Msg("Got message status for unknown message")
		return
	}
	log = log.With().Str("portal_uri", portalURI.String()).Logger()
	portal := user.GetPortalByURI(portalURI)
	if len(portal.MXID) == 0 {
		log.Debug().Msg("Ignoring message status for message from unknown portal")
		return
	}
	select {
	case portal.Messages <- edit:
	case <-time.After(PortalBufferTimeout):
		log.Error().Msg("Portal message status buffer is still full after 10 seconds, dropping")
	}
}

func (user *User) HandleMessageUnsend(unsend *imessage.MessageUnsend) {
	log := user.zlog.With().Str("unsend_message_id", unsend.UnsendMessageID.String()).Logger()
	log.Debug().Msg("Received message unsend")

	portalURI, err := user.bridge.DB.Message.GetPortalURIByID(context.TODO(), unsend.UnsendMessageID, user.RowID)
	if err != nil {
		log.Err(err).Msg("Failed to get portal URI for message status")
		return
	} else if portalURI.IsEmpty() {
		log.Warn().Msg("Got message status for unknown message")
		return
	}
	log = log.With().Str("portal_uri", portalURI.String()).Logger()
	portal := user.GetPortalByURI(portalURI)
	if len(portal.MXID) == 0 {
		log.Debug().Msg("Ignoring message status for message from unknown portal")
		return
	}
	select {
	case portal.Messages <- unsend:
	case <-time.After(PortalBufferTimeout):
		log.Error().Msg("Portal message status buffer is still full after 10 seconds, dropping")
	}
}

func (user *User) HandleTypingNotification(notif *imessage.TypingNotification) {
	portal := user.GetPortalByURI(notif.Chat)
	if len(portal.MXID) == 0 {
		return
	}
	var timeout time.Duration
	if notif.Typing {
		timeout = 60 * time.Second
	}
	_, err := portal.MainIntent().UserTyping(portal.MXID, notif.Typing, timeout)
	if err != nil {
		action := "typing"
		if !notif.Typing {
			action = "not typing"
		}
		portal.log.Warnln("Failed to mark %s as %s in %s: %v", portal.MainIntent().UserID, action, portal.MXID, err)
	}
}

func (user *User) HandleChatDeleted(deleted *imessage.ChatDeleted) {
	portal := user.GetPortalByURI(deleted.Chat)
	if len(portal.MXID) == 0 {
		portal.log.Warnfln("Couldn't get portal to delete uri %s", deleted.Chat.String())
		return
	}

	portal.Delete()
	portal.Cleanup(false)
}
