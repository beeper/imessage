// beeper-imessage - A Matrix-iMessage puppeting bridge.
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
	"crypto/sha256"
	_ "embed"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"golang.org/x/exp/maps"
	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"

	"github.com/beeper/imessage/analytics"
	"github.com/beeper/imessage/database"
	"github.com/beeper/imessage/imessage"
	"github.com/beeper/imessage/imessage/appleid"
	"github.com/beeper/imessage/imessage/direct"
	"github.com/beeper/imessage/imessage/direct/ids"
	"github.com/beeper/imessage/imessage/direct/ids/types"
	"github.com/beeper/imessage/imessage/direct/util/uri"
	"github.com/beeper/imessage/ipc"
	"github.com/beeper/imessage/msgconv"
)

const (
	CmdStarted              ipc.Command = "started"
	CmdStop                 ipc.Command = "stop"
	CmdPing                 ipc.Command = "ping"
	CmdLogin                ipc.Command = "login"
	CmdMessage              ipc.Command = "message"
	CmdMultipartMessage     ipc.Command = "multipart-message"
	CmdStartChat            ipc.Command = "start-chat"
	CmdResolveIdentifier    ipc.Command = "resolve-identifier"
	CmdRegisterPhoneNumber  ipc.Command = "register-phone-number"
	CmdReregister           ipc.Command = "reregister"
	CmdClearIDSCache        ipc.Command = "clear-ids-cache"
	CmdDeregister           ipc.Command = "deregister"
	CmdBridgeInfo           ipc.Command = "bridge-info"
	CmdGetBridgeInfo        ipc.Command = "get-bridge-info"
	CmdSetDefaultHandle     ipc.Command = "set-default-handle"
	CmdBroadcastIMessage    ipc.Command = "broadcast-imessage"
	CmdSwapRegistrations    ipc.Command = "swap-registrations"
	CmdDeregisterSecondary  ipc.Command = "deregister-secondary"
	CmdLogout               ipc.Command = "logout"
	CmdRefreshRooms         ipc.Command = "refresh-rooms"
	CmdSetFCMPushToken      ipc.Command = "set-fcm-push-token"
	CmdFileTransferProgress ipc.Command = "file-transfer-progress"
	CmdAppStateChange       ipc.Command = "app-state-change"
	CmdPanic                ipc.Command = "panic"
	CmdCreateASP            ipc.Command = "create-app-specific-password"
	CmdAnalyticEvent        ipc.Command = "analytic-event"
	CmdCheckConnection      ipc.Command = "check-connection"
	CmdSetRelay             ipc.Command = "set-relay"
)

type ReqFileTransferProgress struct {
	EventID  string              `json:"event_id"`
	Path     id.ContentURIString `json:"path"`
	Progress float64             `json:"progress"`
	Error    string              `json:"error"`
	Done     bool                `json:"done"`
}

type ReqLogin struct {
	Username  string `json:"username"`
	Password  string `json:"password"`
	Code      string `json:"code,omitempty"`
	Secondary bool   `json:"secondary,omitempty"`
}

var Err2FARequired = ipc.Error{
	Code:    "two-factor",
	Message: "2-factor authentication required",
}

func fnLogin(ctx context.Context, req ReqLogin) any {
	im := global.IM
	if req.Secondary {
		im = global.SecondaryIM
	}
	err := im.Login(ctx, req.Username, req.Password, req.Code)
	if errors.Is(err, types.Err2FARequired) && req.Code == "" {
		return Err2FARequired
	} else if errors.Is(err, types.ErrInvalidNameOrPassword) {
		errorMsg := "Invalid username or password."
		if req.Code != "" {
			errorMsg = "Login with 2FA code failed. Please check your 2FA code and try again or check your account on https://appleid.apple.com."
		}
		return ipc.Error{
			Code:    "incorrect-auth",
			Message: errorMsg,
		}
	} else if err != nil {
		zerolog.Ctx(ctx).Warn().Err(err).Msg("Login failed")
		return err
	}
	return nil
}

func fnSwapRegistrations(ctx context.Context) any {
	log := zerolog.Ctx(ctx)
	startLogEvt := log.Info()
	if global.IM.User != nil {
		startLogEvt = startLogEvt.Strs("old_primary_cert_ids", maps.Keys(global.IM.User.AuthIDCertPairs))
	}
	if global.SecondaryIM.User != nil {
		startLogEvt = startLogEvt.Strs("old_secondary_cert_ids", maps.Keys(global.SecondaryIM.User.AuthIDCertPairs))
	}
	startLogEvt.Msg("Swapping apple registrations")
	global.IM.Stop(ctx)
	global.SecondaryIM.Stop(ctx)
	global.DBUser.AppleRegistration, global.DBUser.SecondaryReg = global.DBUser.SecondaryReg, global.DBUser.AppleRegistration
	if global.DBUser.AppleRegistration == nil || len(global.DBUser.AppleRegistration.AuthIDCertPairs) == 0 {
		global.DBUser.AppleRegistration = &ids.Config{}
	}
	if global.DBUser.SecondaryReg != nil && len(global.DBUser.SecondaryReg.AuthIDCertPairs) == 0 {
		global.DBUser.SecondaryReg = nil
	}
	// TODO do cache clear in same db transaction as config save?
	err := global.DB.IDSCache.Clear(ctx, global.DBUser.RowID)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to clear IDS cache")
	}
	global.IM = direct.NewConnector(
		global.NAC, handleEvent,
		&database.IDSCache{Query: global.DB.IDSCache, UserID: global.DBUser.RowID},
		&database.RerouteHistory{Query: global.DB.RerouteHistory, UserID: global.DBUser.RowID},
		global.Cfg.EnablePairECSending,
		database.NewOutgoingCounterStore(global.DB.OutgoingCounter, global.DBUser.RowID),
		manualLookupRatelimiter,
	)
	global.IM.LoginTestConfig = global.Cfg.LoginTest

	global.SecondaryIM = direct.NewConnector(global.NAC, handleSecondaryEvent, nil, nil, false, nil, manualLookupRatelimiter)
	err = global.IM.Configure(ctx, global.DBUser.AppleRegistration, false)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to configure primary connector after swap")
	}
	if global.DBUser.SecondaryReg != nil {
		err = global.SecondaryIM.Configure(secondaryIMLog(ctx), global.DBUser.SecondaryReg, true)
		if err != nil {
			log.Fatal().Err(err).Msg("Failed to configure secondary connector after swap")
		}
		err = global.SecondaryIM.RunWithoutConn(secondaryIMLog(global.Ctx))
		if err != nil {
			log.Err(err).Msg("Failed to run secondary iMessage connector registration after swap")
		}
	}
	if len(global.DBUser.AppleRegistration.AuthIDCertPairs) > 0 {
		// Register IDS before connecting if the new primary is already logged in.
		// This ensures that the IPC command response has the proper handles and other things.
		err = global.IM.RegisterIDS(secondaryIMLog(ctx), false)
		if err != nil {
			log.Err(err).Msg("Failed to register primary iMessage connector registration after swap")
		}
	}
	go global.IM.Run(*global.Log, nil, nil)

	log.Info().Msg("Swapped apple registrations")
	global.IM.EventHandler(&direct.ConfigUpdated{})
	global.IM.EventHandler(&direct.BridgeInfoUpdated{})

	if err != nil {
		log.Err(err).Msg("Failed to update database user after swap")
	}
	return nil
}

func fnDeregisterSecondary(ctx context.Context) any {
	if global.DBUser.SecondaryReg == nil {
		global.SecondaryIM.Stop(secondaryIMLog(ctx))
		global.SecondaryIM = direct.NewConnector(global.NAC, handleSecondaryEvent, nil, nil, false, nil, manualLookupRatelimiter)
		return nil
	}
	log := zerolog.Ctx(ctx)
	log.Info().Msg("Deregistering secondary registration")
	err := global.SecondaryIM.DeRegisterIDS(secondaryIMLog(ctx))
	if err != nil {
		log.Err(err).Msg("Error deregistering secondary iMessage connector")
	}
	global.SecondaryIM.Stop(secondaryIMLog(ctx))
	global.SecondaryIM = direct.NewConnector(global.NAC, handleSecondaryEvent, nil, nil, false, nil, manualLookupRatelimiter)
	global.DBUser.SecondaryReg = nil
	return global.DBUser.Update(ctx)
}

type ReqMessage struct {
	UUID  *uuid.UUID   `json:"uuid,omitempty"`
	Event *event.Event `json:"event"`
}

func fnMessage(ctx context.Context, req ReqMessage) any {
	log := zerolog.Ctx(ctx)
	err := req.Event.Content.ParseRaw(req.Event.Type)
	if err != nil {
		log.Err(err).Msg("Failed to parse event content")
		return fmt.Errorf("failed to parse event content")
	}
	portal, err := global.DB.Portal.GetByMXID(ctx, req.Event.RoomID)
	if err != nil {
		log.Err(err).Msg("Failed to get portal from database")
		return fmt.Errorf("internal database error")
	} else if portal == nil {
		return fmt.Errorf("portal not found")
	}
	log.Debug().
		Str("portal_outgoing_handle", portal.OutgoingHandle.String()).
		Any("request_message_uuid", req.UUID).
		Str("event_type", req.Event.Type.String()).
		Msg("Sending event from IPC client")
	ctx = context.WithValue(ctx, contextKeyPortal, portal)
	switch req.Event.Type {
	case event.EventMessage:
		content, ok := req.Event.Content.Parsed.(*event.MessageEventContent)
		if !ok {
			return fmt.Errorf("unexpected event content type")
		}
		editEventID := content.RelatesTo.GetReplaceID()
		var editMessageID uuid.UUID
		var editMessagePartInfo imessage.MessagePartInfo
		if editEventID != "" {
			editMessageID, editMessagePartInfo, err = mxidToMessageID(editEventID)
			if err != nil {
				log.Err(err).Msg("Failed to parse edit message target")
				return fmt.Errorf("malformed edit message target")
			}
			if content.NewContent != nil {
				content = content.NewContent
			}
		}
		converted, err := global.MC.ToiMessage(ctx, req.Event, content)
		if err != nil {
			log.Err(err).Msg("Failed to convert message")
			return err
		}
		dbMessages := prepareDBMessagesOutgoing(portal, converted, req.UUID)
		var resp *direct.SendResponse
		if editEventID != "" {
			resp, err = global.IM.SendEdit(
				ctx, portal.OutgoingHandle, converted.Participants, converted.GroupID,
				editMessageID, editMessagePartInfo.PartID, event.TextToHTML(converted.Text),
			)
		} else {
			// TODO don't ignore errors
			// note that when resending messages, this will fail because the message was inserted on the first attempt
			for _, dbMessage := range dbMessages {
				dbMessage.Insert(ctx)
			}
			resp, err = global.IM.SendMessage(ctx, portal.OutgoingHandle, converted, dbMessages[0].ID)
		}
		if err != nil {
			analytics.Track("IMGo Message Sent", map[string]any{
				"success":    false,
				"error":      err.Error(),
				"message id": dbMessages[0].ID.String(),
			})
			log.Err(err).Msg("Failed to send message")
			return err
		} else {
			analytics.Track("IMGo Message Sent", map[string]any{
				"success":    true,
				"message id": dbMessages[0].ID.String(),
			})
		}
		if editEventID != "" {
			return &mautrix.RespSendEvent{EventID: editToMXID(editMessageID, editMessagePartInfo.PartID, resp.ID)}
		}
		return &mautrix.RespSendEvent{EventID: dbMessages[0].MXID}
	case event.EventRedaction:
		content, ok := req.Event.Content.Parsed.(*event.RedactionEventContent)
		if !ok {
			return fmt.Errorf("unexpected event content type")
		}
		if content.Redacts == "" {
			content.Redacts = req.Event.Redacts
		}
		if msgID, partInfo, err := mxidToMessageID(content.Redacts); err == nil {
			resp, err := global.IM.SendUnsend(ctx, portal.OutgoingHandle, portal.Participants, portal.GroupID, msgID, partInfo.PartID)
			if err != nil {
				log.Err(err).Msg("Failed to send unsend")
				return fmt.Errorf("failed to send unsend")
			}
			return &mautrix.RespSendEvent{EventID: unsendToMXID(msgID, partInfo.PartID, resp.ID)}
		} else if msgID, partInfo, _, err = mxidToTapbackID(content.Redacts); err == nil {
			emoji, ok := req.Event.Content.Raw["reaction"].(string)
			if !ok {
				return fmt.Errorf("missing emoji to un-react")
			}
			tapbackType := imessage.TapbackFromEmoji(emoji)
			if tapbackType == 0 {
				return fmt.Errorf("unsupported emoji")
			}
			origContent := msgconv.GetReactionTargetContent(ctx, req.Event.Content.VeryRaw)
			converted := global.MC.BuildTapback(ctx, msgID, partInfo, tapbackType, true, origContent)
			_, err = global.IM.SendMessage(ctx, portal.OutgoingHandle, converted, uuid.New())
			if err != nil {
				log.Err(err).Msg("Failed to send tapback")
				var sme *direct.SendMessageError
				if errors.As(err, &sme) {
					return err
				}
				return fmt.Errorf("failed to send tapback")
			}
			eventID := tapbackToMXID(msgID, partInfo, portal.OutgoingHandle)
			return &mautrix.RespSendEvent{EventID: eventID}
		} else {
			return fmt.Errorf("unrecognized event ID format")
		}
	case event.EventReaction:
		content, ok := req.Event.Content.Parsed.(*event.ReactionEventContent)
		if !ok {
			return fmt.Errorf("unexpected event content type")
		}
		msgID, partInfo, err := mxidToMessageID(content.RelatesTo.EventID)
		if err != nil {
			return err
		}
		tapbackType := imessage.TapbackFromEmoji(content.RelatesTo.Key)
		if tapbackType == 0 {
			return fmt.Errorf("unsupported emoji")
		}
		origContent := msgconv.GetReactionTargetContent(ctx, req.Event.Content.VeryRaw)
		converted := global.MC.BuildTapback(ctx, msgID, partInfo, tapbackType, false, origContent)
		_, err = global.IM.SendMessage(ctx, portal.OutgoingHandle, converted, uuid.New())
		if err != nil {
			log.Err(err).Msg("Failed to send tapback")
			var sme *direct.SendMessageError
			if errors.As(err, &sme) {
				return err
			}
			return fmt.Errorf("failed to send tapback")
		}
		eventID := tapbackToMXID(msgID, partInfo, portal.OutgoingHandle)
		return &mautrix.RespSendEvent{EventID: eventID}
	case event.EphemeralEventReceipt:
		contentPtr, ok := req.Event.Content.Parsed.(*event.ReceiptEventContent)
		if !ok {
			return fmt.Errorf("unexpected event content type")
		} else if len(*contentPtr) != 1 {
			return fmt.Errorf("read receipts must have exactly one receipt event")
		}
		content := *contentPtr
		evtID := maps.Keys(content)[0]
		targetMessage, err := global.DB.Message.GetByMXID(ctx, evtID)
		if err != nil {
			log.Fatal().Err(err).Msg("Failed to get message by MXID from database")
		} else if targetMessage == nil {
			return fmt.Errorf("unknown event ID")
		} else if slices.Contains(global.IM.User.Handles, targetMessage.SenderURI) {
			log.Info().Msg("Not sending read receipt for own message")
			return nil
		}
		receipt := content[evtID]
		if len(receipt) != 1 {
			return fmt.Errorf("read receipts must have exactly one receipt type")
		}
		receiptType := maps.Keys(receipt)[0]
		if receiptType != event.ReceiptTypeRead && receiptType != event.ReceiptTypeReadPrivate {
			return fmt.Errorf("unsupported receipt type %q", receiptType)
		}
		sendReceiptsTo := portal.Participants
		if !portal.IsPrivateChat() || receiptType == event.ReceiptTypeReadPrivate {
			sendReceiptsTo = []uri.ParsedURI{portal.OutgoingHandle}
		}
		err = global.IM.SendReadReceipt(ctx, portal.OutgoingHandle, sendReceiptsTo, targetMessage.ID, portal.Service)
		return err
	case EventTypeMarkedUnreadIPC:
		if targetMessage, err := global.DB.Message.GetLastInChat(ctx, portal.Key); err != nil {
			log.Fatal().Err(err).Msg("Failed to get message by MXID from database")
			return err
		} else if targetMessage == nil {
			return fmt.Errorf("unknown event ID")
		} else {
			return global.IM.SendMarkUnread(ctx, portal.OutgoingHandle, targetMessage.ID)
		}
	case event.EphemeralEventTyping:
		if !portal.IsPrivateChat() {
			log.Info().Msg("Not sending typing update for group chat")
			return nil
		}
		isTyping := false
		for _, userID := range req.Event.Content.Parsed.(*event.TypingEventContent).UserIDs {
			parsed, err := uri.ParseIdentifier(userID.String(), uri.ParseiMessageDM)
			if err != nil {
				return err
			}
			if slices.Contains(global.IM.User.Handles, parsed) {
				isTyping = true
				break
			}
		}
		_, err := global.IM.SendTypingNotification(ctx, portal.OutgoingHandle, portal.Participants, portal.GroupID, isTyping)
		return err

	case event.StateRoomName:
		roomName := req.Event.Content.Parsed.(*event.RoomNameEventContent).Name
		_, err = global.IM.UpdateChatName(ctx, portal.OutgoingHandle, portal.Participants, portal.GroupID, roomName)
		if err != nil {
			return err
		}
		portal.Name = roomName
		portal.NameSet = true
		return portal.Update(ctx)
	case event.StateRoomAvatar:
		// We have to handle StateRoomAvatar separately because the parsing of
		// the ContentURI errors.
		url := req.Event.Content.Parsed.(*RoomAvatarEventContent).URL
		data, err := global.MC.DownloadMatrixMedia(ctx, url)
		if err != nil {
			return err
		}

		portal.PropertiesVersion++
		avatarGUID, err := global.IM.UpdateChatAvatar(ctx, portal.OutgoingHandle, portal.Participants, portal.GroupID, portal.Name, portal.PropertiesVersion, data)
		if err != nil {
			return err
		}
		portal.AvatarGUID = &avatarGUID
		portal.AvatarURL = url
		hash := sha256.Sum256(data)
		portal.AvatarHash = &hash
		portal.AvatarSet = true
		return portal.Update(ctx)
	case event.StateMember:
		memberContent := req.Event.Content.Parsed.(*event.MemberEventContent)
		parsed, err := uri.ParseIdentifier(*req.Event.StateKey, uri.ParseiMessageDM)

		newParticipants := slices.Clone(portal.Participants)
		if memberContent.Membership == event.MembershipLeave {
			newParticipants = slices.DeleteFunc(newParticipants, func(u uri.ParsedURI) bool {
				return u == parsed
			})
		} else if memberContent.Membership == event.MembershipJoin || memberContent.Membership == event.MembershipInvite {
			newParticipants = uri.Sort(append(newParticipants, parsed))
		} else {
			return fmt.Errorf("unsupported membership state %s", memberContent.Membership)
		}

		log.Info().
			Any("old_participants", portal.Participants).
			Any("new_participants", newParticipants).
			Msg("Updating iMessage chat participants")

		_, err = global.IM.UpdateParticipants(context.TODO(), portal.OutgoingHandle, portal.Participants, portal.GroupID, newParticipants)
		if err != nil {
			log.Warn().Err(err).Msg("Failed to leave iMessage chat")
		}
		portal.Participants = newParticipants
		err = portal.Update(context.TODO())
		if err != nil {
			return err
		}
		sendUpdatedBridgeInfo(ctx, "", time.Now(), portal)
		return nil

	default:
		return fmt.Errorf("unsupported event type %s", req.Event.Type.String())
	}
}

type ReqMultipartMessage struct {
	UUID   *uuid.UUID     `json:"uuid,omitempty"`
	Events []*event.Event `json:"events"`
}

type RespMultipartMessage struct {
	EventIDs []id.EventID `json:"event_ids"`
}

func fnMultipartMessage(ctx context.Context, req ReqMultipartMessage) any {
	log := zerolog.Ctx(ctx)
	if len(req.Events) == 0 {
		return fmt.Errorf("multipart message must have at least one event")
	}

	roomID := req.Events[0].RoomID
	for i, evt := range req.Events {
		if evt.Type != event.EventMessage {
			return fmt.Errorf("unsupported event type %s at index %d in multipart message", evt.Type.String(), i)
		} else if evt.RoomID != roomID {
			return fmt.Errorf("all events in multipart message must be in the same room")
		}

		if err := evt.Content.ParseRaw(evt.Type); err != nil {
			log.Err(err).Int("index", i).Msg("Failed to parse event content")
			return fmt.Errorf("failed to parse event content")
		}

		content, ok := evt.Content.Parsed.(*event.MessageEventContent)
		if !ok {
			log.Error().Type("content_type", content).Int("index", i).Msg("Unexpected event content type")
			return fmt.Errorf("unexpected event content type")
		}
		if content.RelatesTo.GetReplaceID() != "" {
			return fmt.Errorf("multipart messages cannot contain edit events")
		}
	}

	portal, err := global.DB.Portal.GetByMXID(ctx, roomID)
	if err != nil {
		log.Err(err).Msg("Failed to get portal from database")
		return fmt.Errorf("internal database error")
	} else if portal == nil {
		return fmt.Errorf("portal not found")
	}
	log.Debug().
		Str("portal_outgoing_handle", portal.OutgoingHandle.String()).
		Any("request_message_uuid", req.UUID).
		Msg("Sending multipart message from IPC client")
	ctx = context.WithValue(ctx, contextKeyPortal, portal)

	converted, err := global.MC.MultipartToIMessage(ctx, req.Events)
	if err != nil {
		log.Err(err).Msg("Failed to convert multipart message")
		return err
	}

	dbMessages := prepareDBMessagesOutgoing(portal, converted, req.UUID)
	var eventIDs []id.EventID
	for _, dbMessage := range dbMessages {
		eventIDs = append(eventIDs, dbMessage.MXID)
		// TODO don't ignore error
		dbMessage.Insert(ctx)
	}

	_, err = global.IM.SendMessage(ctx, portal.OutgoingHandle, converted, dbMessages[0].ID)
	if err != nil {
		analytics.Track("IMGo Message Sent", map[string]any{
			"success":    false,
			"error":      err.Error(),
			"message id": dbMessages[0].ID.String(),
		})
		log.Err(err).Msg("Failed to send message")
		return err
	} else {
		analytics.Track("IMGo Message Sent", map[string]any{
			"success":    true,
			"message id": dbMessages[0].ID.String(),
		})
	}
	return &RespMultipartMessage{EventIDs: eventIDs}
}

type ReqResolveIdentifier struct {
	Identifiers       []string `json:"identifiers"`
	Force             bool     `json:"force"`
	IgnoreParseErrors bool     `json:"ignore_parse_errors"`
	Handle            string   `json:"handle"`
}

type RespResolveIdentifier struct {
	Found         []uri.ParsedURI `json:"found"`
	NotFound      []uri.ParsedURI `json:"not_found"`
	FailedToParse []string        `json:"failed_to_parse"`
}

func fnResolveIdentifier(ctx context.Context, req ReqResolveIdentifier) any {
	var handle *uri.ParsedURI
	if req.Handle != "" {
		parsedHandle, err := uri.ParseURI(req.Handle)
		if err != nil {
			return err
		}
		handle = &parsedHandle
	}
	var failedToParse []string
	if req.IgnoreParseErrors {
		lookupInput := req.Identifiers[:0]
		for _, identifier := range req.Identifiers {
			_, err := uri.ParseIdentifier(identifier, uri.ParseiMessageDM|uri.POShortcodes)
			if err != nil {
				failedToParse = append(failedToParse, identifier)
			} else {
				lookupInput = append(lookupInput, identifier)
			}
		}
		req.Identifiers = lookupInput
	}

	found, notFound, err := global.IM.ResolveIdentifiers(ctx, req.Force, handle, req.Identifiers...)
	if err != nil {
		return err
	}
	return RespResolveIdentifier{
		Found:         found,
		NotFound:      notFound,
		FailedToParse: failedToParse,
	}
}

type RespStartChat struct {
	RoomID id.RoomID `json:"room_id"`
}

func fnStartChat(ctx context.Context, req ReqResolveIdentifier) any {
	found, notFound, err := global.IM.ResolveIdentifiers(ctx, req.Force, nil, req.Identifiers...)
	if err != nil {
		return err
	}
	if len(notFound) > 0 {
		return fmt.Errorf("one or more handles were not found: %+v", notFound)
	}
	var portalKey database.Key
	var groupID string
	var portal *database.Portal
	var participants []uri.ParsedURI
	if len(found) == 1 {
		portalKey = database.Key{
			URI:      found[0],
			Receiver: global.DBUser.RowID,
		}
		portal, err = global.DB.Portal.GetByURI(ctx, portalKey)
		participants = found
	} else {
		groupID = strings.ToUpper(uuid.New().String())
		portalKey = database.Key{
			URI:      uri.ParsedURI{Scheme: uri.SchemeGroup, Identifier: groupID},
			Receiver: global.DBUser.RowID,
		}
		portal, err = global.DB.Portal.GetByParticipants(ctx, found, global.DBUser.RowID)
		participants = uri.Sort(append(found, global.IM.User.DefaultHandle))
	}
	if err != nil {
		// TODO log
		panic(err)
	} else if portal == nil {
		portal = global.DB.Portal.New()
		portal.Key = portalKey
		portal.GroupID = groupID
		portal.Service = imessage.ServiceIMessage
		portal.Participants = participants
		portal.OutgoingHandle = global.IM.User.DefaultHandle
		portal.MXID = id.RoomID(portal.URI.String())
		err = portal.Insert(ctx)
		if err != nil {
			// TODO log
			panic(err)
		}
		sendUpdatedBridgeInfo(ctx, "", time.Now(), portal)
	}

	return RespStartChat{
		RoomID: portal.MXID,
	}
}

type ReqRegisterPhoneNumber struct {
	// MCCMNC is the MCC+MNC of the device's SIM card. This is always required.
	MCCMNC string `json:"mccmnc"`

	// PhoneNumber is the phone number to register. This is always required.
	// This number should have a leading plus on it, ex: +15194969994
	PhoneNumber string `json:"phone_number"`

	// ResponseText is the response text sent back by Apple servers from the gateway.
	ResponseText string `json:"response_text"`

	Secondary bool `json:"secondary"`
}

type RegisterPhoneNumberStatus string

const (
	RegisterPhoneNumberStatusDone    RegisterPhoneNumberStatus = "done"
	RegisterPhoneNumberStatusSendSMS RegisterPhoneNumberStatus = "send-sms"
)

type RespRegisterPhoneNumber struct {
	// Status indicates whether the registration is done or if an SMS needs to
	// be sent to the gateway.
	Status RegisterPhoneNumberStatus `json:"status"`

	// Gateway will be returned if the status is "send-sms". This is the phone
	// number that the value in "sms" needs to be sent to.
	Gateway string `json:"gateway,omitempty"`

	// SMSText will be returned if the status is "send-sms". This is the text
	// that needs to be sent to the gateway.
	SMSText string `json:"sms,omitempty"`

	// ForceSendSMS may be returned if the status is "send-sms". This flag
	// indicates whether or not the bridge wants the SMS to be resent even if
	// there's already a recent response on the same gateway.
	ForceSendSMS bool `json:"force_send_sms,omitempty"`

	// ForceSendSMSReason may be returned if the status is "send-sms". This
	// indicates the reason for needing to force send the SMS.
	ForceSendSMSReason string `json:"force_send_sms_reason,omitempty"`

	TestSuccess *bool `json:"test_success,omitempty"`
}

func trackPhoneNumberRegister(ctx context.Context, phone, stage string, err error) {
	args := map[string]any{
		"success": true,
		"phone":   phone,
		"bi":      true,
	}
	if err != nil {
		args["success"] = false
		args["error"] = err.Error()
	}
	analytics.Track("IMGo Register Phone Number "+stage, args)

	global.DBUser.RegisteredPhoneNumbers = append(global.DBUser.RegisteredPhoneNumbers, phone)
	slices.Sort(global.DBUser.RegisteredPhoneNumbers)
	global.DBUser.RegisteredPhoneNumbers = slices.Compact(global.DBUser.RegisteredPhoneNumbers)
	if err := global.DBUser.Update(ctx); err != nil {
		zerolog.Ctx(ctx).Err(err).Msg("failed to save registered phone numbers")
	}
}

func fnRegisterPhoneNumber(ctx context.Context, req ReqRegisterPhoneNumber) any {
	log := zerolog.Ctx(ctx).With().
		Str("action", "register phone number").
		Str("mccmnc", req.MCCMNC).
		Str("phone_number", req.PhoneNumber).
		Bool("has_response", len(req.ResponseText) > 0).
		Bool("secondary", req.Secondary).
		Logger()
	im := global.IM
	if req.Secondary {
		im = global.SecondaryIM
	}

	log.Info().Msg("Register phone number called")
	im.User.Versions = ids.GetDefaultiPhoneVersions()

	// First check if this phone number is already in the process of being registered.
	if certs, ok := im.User.AuthIDCertPairs["P:"+req.PhoneNumber]; ok && !certs.RefreshNeeded {
		if certs.IDCert == nil {
			// We haven't successfully done IDS registration yet. (App might
			// have gotten killed before we got validation data or something.)
			log.Debug().Msg("Registering phone number with IDS")
			if err := im.RegisterIDS(ctx, false); err != nil {
				log.Err(err).Msg("Failed to register IDS with phone number auth cert")
				return err
			}
			if err := global.DBUser.Update(ctx); err != nil {
				log.Err(err).Msg("Failed to update user in db after registering")
				err = fmt.Errorf("failed to update user in db after registering: %w", err)
				return err
			}
			log.Debug().Msg("Successfully registered phone number with IDS")
			trackPhoneNumberRegister(ctx, req.PhoneNumber, "Done", nil)
		} else {
			log.Debug().Msg("Phone number is already registered")
		}
		return RespRegisterPhoneNumber{Status: RegisterPhoneNumberStatusDone}
	}

	// If there's no response text, we need to ask for the app to send an SMS
	// (or give us the most recently received SMS from the gateway if there is one).
	if req.ResponseText == "" {
		var err error
		resp := RespRegisterPhoneNumber{
			Status:  RegisterPhoneNumberStatusSendSMS,
			SMSText: ids.CreateSMSRegisterRequest(im.User.PushToken),
		}

		resp.Gateway, err = ids.GetGatewayByMCCMNC(ctx, req.MCCMNC)
		if err != nil {
			log.Err(err).Msg("Failed to get gateway number to start phone number registration")
			err = fmt.Errorf("failed to get gateway: %w", err)
			trackPhoneNumberRegister(ctx, req.PhoneNumber, "Start", err)
			return err
		}
		log.Debug().Msg("Phone number registration started")
		trackPhoneNumberRegister(ctx, req.PhoneNumber, "Start", nil)
		return resp
	}

	phoneNumber, signature, err := ids.ParseSMSRegisterResponse(req.ResponseText)
	if err != nil {
		log.Err(err).Msg("Failed to parse SMS register response")
		trackPhoneNumberRegister(ctx, req.PhoneNumber, "Response", err)
		return err
	}
	if phoneNumber != req.PhoneNumber {
		trackPhoneNumberRegister(ctx, req.PhoneNumber, "Response", fmt.Errorf("mismatching phone number in request and response"))
		// This might happen in dual SIM situations where the gateway is the same for both SIM.
		log.Error().Str("sms_phone_number", phoneNumber).Msg("phone number in response text does not match phone number in request")

		resp := RespRegisterPhoneNumber{
			Status:             RegisterPhoneNumberStatusSendSMS,
			SMSText:            ids.CreateSMSRegisterRequest(im.User.PushToken),
			ForceSendSMS:       true,
			ForceSendSMSReason: "phone number in response text does not match phone number in request",
		}
		resp.Gateway, err = ids.GetGatewayByMCCMNC(ctx, req.MCCMNC)
		if err != nil {
			log.Err(err).Msg("Failed to get gateway number after register error")
			return fmt.Errorf("failed to get gateway: %w", err)
		}
		return resp
	}

	log.Debug().Msg("Getting auth cert with SMS register response")
	authCert, err := im.User.GetAuthCertSMS(ctx, im.User.PushToken, signature, phoneNumber)
	if err != nil {
		log.Err(err).Msg("Failed to get auth cert with SMS register response")
		trackPhoneNumberRegister(ctx, req.PhoneNumber, "Response", fmt.Errorf("failed to get auth cert with SMS register response: %w", err))
		resp := RespRegisterPhoneNumber{
			Status:             RegisterPhoneNumberStatusSendSMS,
			SMSText:            ids.CreateSMSRegisterRequest(im.User.PushToken),
			ForceSendSMS:       true,
			ForceSendSMSReason: fmt.Sprintf("getting auth cert failed %v", err),
		}
		resp.Gateway, err = ids.GetGatewayByMCCMNC(ctx, req.MCCMNC)
		if err != nil {
			log.Err(err).Msg("Failed to get gateway number after register error")
			return fmt.Errorf("failed to get gateway: %w", err)
		}
		return resp
	}
	log.Info().Msg("Got auth cert for phone number")
	trackPhoneNumberRegister(ctx, req.PhoneNumber, "Response", nil)

	if im.User.AuthIDCertPairs == nil {
		im.User.AuthIDCertPairs = map[string]*ids.AuthIDCertPair{}
	}
	im.User.AuthIDCertPairs["P:"+phoneNumber] = &ids.AuthIDCertPair{
		Added:    time.Now(),
		AuthCert: authCert,
	}
	if err = global.DBUser.Update(ctx); err != nil {
		log.Err(err).Msg("Failed to update user in db after getting auth cert")
		return fmt.Errorf("failed to update user in db after getting auth cert: %w", err)
	}

	log.Info().Msg("Registering phone number with IDS")
	if err = im.RegisterIDS(ctx, true); err != nil {
		log.Err(err).Msg("Failed to register IDS after getting auth cert")
		return err
	}

	if err = global.DBUser.Update(ctx); err != nil {
		log.Err(err).Msg("Failed to update user in db after registering")
		return fmt.Errorf("failed to update user in db after registering: %w", err)
	}

	log.Info().Msg("Phone number registration complete and successfully registered on IDS")
	trackPhoneNumberRegister(ctx, req.PhoneNumber, "Done", nil)

	lookupOK, lookupErr := im.DoPhoneRegistrationLookupTest(ctx, uri.ParsedURI{Scheme: uri.SchemeTel, Identifier: req.PhoneNumber})
	if lookupErr != nil {
		log.Err(lookupErr).Msg("Failed to do lookup test after phone registration")
	}

	return RespRegisterPhoneNumber{Status: RegisterPhoneNumberStatusDone, TestSuccess: &lookupOK}
}

type ReqReregister struct {
	Force         bool `json:"force"`
	ClearIDSCache bool `json:"clear_ids_cache"`
}

func fnReregister(ctx context.Context, req ReqReregister) any {
	if global.DBUser.SecondaryReg != nil {
		err := global.SecondaryIM.RegisterIDS(secondaryIMLog(ctx), req.Force)
		if err != nil {
			return fmt.Errorf("error reregistering secondary connection: %w", err)
		}
	}
	err := global.IM.RegisterIDS(ctx, req.Force)
	if err != nil {
		return err
	}
	if req.ClearIDSCache {
		err = global.IM.IDSCache.Clear(ctx)
		if err != nil {
			return err
		}
	}
	return global.DBUser.Update(ctx)
}

func fnClearIDSCache(ctx context.Context) any {
	if err := global.IM.IDSCache.Clear(ctx); err != nil {
		return err
	}
	if err := global.IM.RerouteHistory.Clear(ctx); err != nil {
		return err
	}
	return nil
}

func fnDeregister(ctx context.Context) any {
	err := global.IM.DeRegisterIDS(ctx)
	if err != nil {
		return err
	}
	return global.DBUser.Update(ctx)
}

func fnGetBridgeInfo(ctx context.Context) any {
	bridgeInfo := GetBridgeInfo()
	if bridgeInfo == nil {
		return fmt.Errorf("bridge not started yet")
	}
	return bridgeInfo
}

type SetDefaultHandleRequest struct {
	Handle string `json:"handle"`
}

func fnSetDefaultHandle(ctx context.Context, req SetDefaultHandleRequest) any {
	log := zerolog.Ctx(ctx).With().
		Str("new_default_handle", req.Handle).
		Str("old_default_handle", global.IM.User.DefaultHandle.String()).
		Str("old_preferred_handle", global.IM.User.PreferredHandle.String()).
		Logger()

	handle, err := uri.ParseURI(req.Handle)
	if err != nil {
		log.Err(err).Msg("Failed to parse new default handle")
		return err
	}

	if !slices.Contains(global.IM.User.Handles, handle) {
		log.Error().Msg("Tried to switch default to unknown handle")
		return fmt.Errorf("unknown handle")
	}

	analytics.Track("IMGo Default Handle Changed", map[string]any{
		"old_handle": global.IM.User.DefaultHandle,
		"new_handle": handle,
		"bi":         true,
	})
	global.IM.User.DefaultHandle = handle
	global.IM.User.PreferredHandle = handle
	log.Info().Msg("Changed default handle")

	global.IM.EventHandler(&direct.BridgeInfoUpdated{})
	return global.DBUser.Update(context.TODO())
}

type ReqBroadcastIMessage struct {
	Handle uri.ParsedURI `json:"handle"`
	URIs   []string      `json:"uris"`
}

func fnBroadcastIMessage(ctx context.Context, req ReqBroadcastIMessage) any {
	if !slices.Contains(global.IM.User.Handles, req.Handle) {
		return fmt.Errorf("handle %s is not owned by this user", req.Handle)
	}
	for _, u := range req.URIs {
		ident, err := uri.ParseIdentifier(u, uri.ParseiMessageDM)
		if err != nil {
			return err
		}
		if err = global.IM.BroadcastHandleTo(ctx, []uri.ParsedURI{ident}, req.Handle, false); err != nil {
			return err
		}
	}
	return nil
}

func fnLogout(ctx context.Context) any {
	if err := global.IM.Logout(ctx); err != nil {
		return err
	}
	if global.SecondaryIM.User != nil {
		if err := global.SecondaryIM.Logout(ctx); err != nil {
			return err
		}
	}

	appleProfileID := global.DBUser.AppleRegistration.ProfileID
	secondaryProfileID := global.DBUser.SecondaryReg.ProfileID

	global.IM.Stop(ctx)
	global.SecondaryIM.Stop(secondaryIMLog(ctx))
	global.DBUser.AppleRegistration = nil
	global.DBUser.SecondaryReg = nil
	global.DeleteImux(ctx)
	analytics.Track("IMGo Logged Out", map[string]any{
		"bi":                   true,
		"apple_profile_id":     appleProfileID,
		"secondary_profile_id": secondaryProfileID,
		"handles":              global.IM.User.Handles,
	})
	return global.DBUser.Update(ctx)
}

func fnRefreshRooms(ctx context.Context) any {
	log := zerolog.Ctx(ctx)
	portals, err := global.DB.Portal.GetAllForUser(ctx, global.DBUser.RowID)
	if err != nil {
		log.Err(err).Msg("Failed to get portal from database")
		return fmt.Errorf("internal database error")
	}
	now := time.Now()
	for _, portal := range portals {
		sendUpdatedBridgeInfo(ctx, "", now, portal)
		if portal.Name != "" {
			sendRoomName(ctx, "", now, portal)
		}
	}
	return nil
}

type ReqSetFCMPushToken struct {
	FCMPushToken string `json:"fcm_push_token"`
}

func fnSetFCMPushToken(ctx context.Context, req ReqSetFCMPushToken) any {
	log := zerolog.Ctx(ctx)
	if req.FCMPushToken == global.DBUser.FCMPushToken {
		log.Info().Msg("Call to set fcm token to its current value, ignoring.")
		return nil
	}
	global.DBUser.FCMPushToken = req.FCMPushToken
	err := global.DBUser.Update(ctx)
	if err != nil {
		log.Err(err).Msg("Failed to save user to database")
		return fmt.Errorf("internal database error")
	}
	log.Info().Msg("FCM Token updated, resetting imux")
	global.ResetImux()
	return nil
}

type ReqAppStateChange struct {
	Foreground bool `json:"foreground"`
}

func fnAppStateChange(ctx context.Context, req ReqAppStateChange) any {
	if req.Foreground {
		go qftOnce.Do(DoAllQueuedFileTransfers)
	}
	return nil
}

func fnPanic(ctx context.Context) any {
	go func() {
		panic(fmt.Errorf("panicing because we were asked to over IPC"))
	}()
	return nil
}

type ReqCreateAppSpecificPassword struct {
	Username    string `json:"username"`
	Password    string `json:"password"`
	Code        string `json:"code"`
	Description string `json:"description"`
}

type RespCreateAppSpecificPassword struct {
	Done        bool   `json:"done"`
	PhoneNumber string `json:"phone_number,omitempty"`
	Password    string `json:"password,omitempty"`
}

var aspLock sync.Mutex

func aspLogin(ctx context.Context, username, password string) any {
	aid := appleid.NewClient()
	var resp *appleid.TwoFactorInfo
	var err error
	if err = aid.Prepare(ctx); err != nil {
		err = fmt.Errorf("failed to prepare login: %w", err)
	} else if err = aid.EnterUsername(ctx, username, false); err != nil {
		err = fmt.Errorf("failed to submit username: %w", err)
	} else if resp, err = aid.EnterPassword(ctx, password); err != nil {
		err = fmt.Errorf("failed to submit password: %w", err)
	} else if resp.HasTrustedDevices {
		err = aid.RequestSMS2FA(ctx, resp.PhoneNumberInfo.TrustedPhoneNumber.PushMode, resp.PhoneNumberInfo.TrustedPhoneNumber.ID)
		if err != nil {
			err = fmt.Errorf("failed to request SMS 2FA code: %w", err)
		}
	}
	if err != nil {
		return err
	}
	global.AID = aid
	return &RespCreateAppSpecificPassword{
		Done:        false,
		PhoneNumber: resp.PhoneNumberInfo.TrustedPhoneNumber.NumberWithDialCode,
	}
}

func aspCreate(ctx context.Context, aid *appleid.Client, password, twoFactorCode, description string) any {
	if description == "" {
		description = global.Cfg.DeviceName
	}
	if err := aid.Submit2FA(ctx, twoFactorCode); err != nil {
		return fmt.Errorf("failed to submit 2fa code: %w", err)
	}
	defer func() {
		global.AID = nil
	}()
	resp, err := aid.CreateAppSpecificPassword(ctx, description)
	if errors.Is(err, appleid.ErrStandardAdditionalAuthNeeded) {
		err = aid.SubmitStandardAdditionalAuth(ctx, password)
		if err != nil {
			return fmt.Errorf("failed to submit standard additional auth: %w", err)
		}
		resp, err = aid.CreateAppSpecificPassword(ctx, description)
	}
	if err != nil {
		return fmt.Errorf("failed to create app-specific password: %w", err)
	}
	if len(resp.Password) == 16 {
		resp.Password = fmt.Sprintf("%s-%s-%s-%s", resp.Password[:4], resp.Password[4:8], resp.Password[8:12], resp.Password[12:16])
	}
	return &RespCreateAppSpecificPassword{
		Done:     true,
		Password: resp.Password,
	}
}

func fnCreateAppSpecificPassword(ctx context.Context, req ReqCreateAppSpecificPassword) any {
	if !aspLock.TryLock() {
		return fmt.Errorf("another app-specific password creation is already in progress")
	}
	defer aspLock.Unlock()

	if req.Code == "" {
		return aspLogin(ctx, req.Username, req.Password)
	} else if aid := global.AID; aid == nil {
		return fmt.Errorf("2FA code provided before login was started")
	} else {
		return aspCreate(ctx, aid, req.Password, req.Code, req.Description)
	}
}

type RespCheckConnection struct {
	Fixed bool `json:"fixed"`
}

func fnCheckConnection(ctx context.Context) any {
	fixed, err := global.IM.TryResolveOwnHandle(ctx, true)
	if err != nil {
		return err
	}
	return &RespCheckConnection{Fixed: fixed}
}

type ReqSetRelay struct {
	URL   string `json:"url"`
	Token string `json:"token"`

	NotRelay bool `json:"not_relay"`
}

type RespSetRelay struct {
	CanPhoneRegister bool `json:"can_phone_register"`
}

func fnSetRelay(ctx context.Context, req ReqSetRelay) any {
	global.NAC.URL = req.URL
	global.NAC.Token = req.Token
	global.NAC.IsRelay = !req.NotRelay
	versions, err := global.IM.FetchValidationVersions(ctx)
	if err != nil {
		zerolog.Ctx(ctx).Err(err).Msg("Failed to fetch versions from validation relay")
		return fmt.Errorf("failed to get versions: %w", err)
	}
	if !global.InitialConfigureDone {
		global.InitialConfigureDone = true
		zerolog.Ctx(ctx).Info().Msg("Running initial configuration and connection after relay was updated")
		initialConfigure(global.Ctx)
		go global.IM.Run(*global.Log, nil, nil)
	} else if global.IM.HasValidIDCerts() {
		zerolog.Ctx(ctx).Info().Msg("Re-registering after relay was updated")
		err := global.IM.RegisterIDS(ctx, true)
		if err != nil {
			return err
		}
	} else {
		zerolog.Ctx(ctx).Info().Msg("Not doing anything after relay was updated")
	}
	return RespSetRelay{
		CanPhoneRegister: versions.SoftwareName == "iPhone OS",
	}
}
