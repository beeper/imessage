// beeper-imessage - A Matrix-iMessage puppeting bridge.
// Copyright (C) 2022 Tulir Asokan
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
	"errors"
	"fmt"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	"github.com/gabriel-vasile/mimetype"
	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"go.mau.fi/util/exzerolog"
	"go.mau.fi/util/jsontime"
	"golang.org/x/exp/slices"
	"maunium.net/go/maulogger/v2"
	"maunium.net/go/maulogger/v2/maulogadapt"
	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/appservice"
	"maunium.net/go/mautrix/bridge"
	"maunium.net/go/mautrix/bridge/bridgeconfig"
	"maunium.net/go/mautrix/bridge/status"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"

	"github.com/beeper/imessage/database"
	"github.com/beeper/imessage/imessage"
	"github.com/beeper/imessage/imessage/direct"
	"github.com/beeper/imessage/imessage/direct/util/uri"
	"github.com/beeper/imessage/ipc"
	"github.com/beeper/imessage/msgconv"
)

func (br *IMBridge) GetPortalByMXID(mxid id.RoomID) *Portal {
	br.portalsLock.Lock()
	defer br.portalsLock.Unlock()
	portal, ok := br.portalsByMXID[mxid]
	if !ok {
		ctx := context.TODO()
		dbPortal, err := br.DB.Portal.GetByMXID(ctx, mxid)
		if err != nil {
			br.ZLog.Err(err).Str("mxid", mxid.String()).Msg("Failed to get portal from database")
			return nil
		}
		return br.loadDBPortal(ctx, dbPortal, nil)
	}
	return portal
}

func (br *IMBridge) GetPortalByID(key database.Key) *Portal {
	br.portalsLock.Lock()
	defer br.portalsLock.Unlock()
	return br.maybeGetPortalByID(context.TODO(), key, true)
}

func (br *IMBridge) FindPortalByParticipants(participants []uri.ParsedURI, receiver int) *Portal {
	ctx := context.TODO()
	portal, err := br.DB.Portal.GetByParticipants(ctx, participants, receiver)
	if err != nil {
		br.ZLog.Err(err).Any("participants", participants).Msg("Failed to find portal by participants from database")
		return nil
	} else if portal == nil {
		return nil
	}
	br.portalsLock.Lock()
	defer br.portalsLock.Unlock()
	existing, ok := br.portalsByKey[portal.Key]
	if ok {
		return existing
	}
	return br.loadDBPortal(ctx, portal, nil)
}

func (br *IMBridge) GetPortalByIDIfExists(key database.Key) *Portal {
	br.portalsLock.Lock()
	defer br.portalsLock.Unlock()
	return br.maybeGetPortalByID(context.TODO(), key, false)
}

func (br *IMBridge) maybeGetPortalByID(ctx context.Context, key database.Key, createIfNotExist bool) *Portal {
	var fallbackKey *database.Key
	if createIfNotExist {
		fallbackKey = &key
	}
	portal, ok := br.portalsByKey[key]
	if !ok {
		dbPortal, err := br.DB.Portal.GetByURI(ctx, key)
		if err != nil {
			br.ZLog.Err(err).Object("portal_key", key).Msg("Failed to get portal from database")
			return nil
		}
		return br.loadDBPortal(ctx, dbPortal, fallbackKey)
	}
	return portal
}

func (br *IMBridge) GetAllPortals() []*Portal {
	return br.loadManyPortals(br.DB.Portal.GetAllWithMXID)
}

func (br *IMBridge) GetAllPortalsForUser(receiver int) []*Portal {
	return br.loadManyPortals(func(ctx context.Context) ([]*database.Portal, error) {
		return br.DB.Portal.GetAllForUser(ctx, receiver)
	})
}

func (br *IMBridge) FindPortalsWithRecentMessages(receiver int, interval time.Duration) []*Portal {
	return br.loadManyPortals(func(ctx context.Context) ([]*database.Portal, error) {
		return br.DB.Portal.FindWithRecentMessages(ctx, receiver, interval)
	})
}

func (br *IMBridge) loadManyPortals(query func(ctx context.Context) ([]*database.Portal, error)) []*Portal {
	br.portalsLock.Lock()
	defer br.portalsLock.Unlock()
	dbPortals, err := query(context.TODO())
	if err != nil {
		br.ZLog.Err(err).Msg("Failed to load all portals from database")
		return []*Portal{}
	}
	output := make([]*Portal, len(dbPortals))
	for index, dbPortal := range dbPortals {
		if dbPortal == nil {
			continue
		}
		portal, ok := br.portalsByKey[dbPortal.Key]
		if !ok {
			portal = br.loadDBPortal(context.TODO(), dbPortal, nil)
		}
		output[index] = portal
	}
	return output
}

func (br *IMBridge) loadDBPortal(ctx context.Context, dbPortal *database.Portal, key *database.Key) *Portal {
	if dbPortal == nil {
		if key == nil {
			return nil
		}
		dbPortal = br.DB.Portal.New()
		dbPortal.Key = *key
		err := dbPortal.Insert(ctx)
		if err != nil {
			br.ZLog.Err(err).Object("portal_key", key).Msg("Failed to insert portal")
			return nil
		}
	}
	portal := br.NewPortal(dbPortal)
	br.portalsByKey[portal.Key] = portal
	if len(portal.MXID) > 0 {
		br.portalsByMXID[portal.MXID] = portal
	}
	return portal
}

func (br *IMBridge) GetAllIPortals() (iportals []bridge.Portal) {
	portals := br.GetAllPortals()
	iportals = make([]bridge.Portal, len(portals))
	for i, portal := range portals {
		iportals[i] = portal
	}
	return iportals
}

func (br *IMBridge) GetIPortal(mxid id.RoomID) bridge.Portal {
	p := br.GetPortalByMXID(mxid)
	if p == nil {
		return nil
	}
	return p
}

func (br *IMBridge) NewPortal(dbPortal *database.Portal) *Portal {
	portal := &Portal{
		Portal: dbPortal,
		bridge: br,

		Messages:       make(chan any, 100),
		MatrixMessages: make(chan *event.Event, 100),
	}
	portal.user = br.GetUserByRowID(dbPortal.Receiver)
	portal.MsgConv = &msgconv.MessageConverter{
		PortalMethods: portal,
		ConvertHEIF:   portal.bridge.Config.Bridge.ConvertHEIF,
		ConvertTIFF:   portal.bridge.Config.Bridge.ConvertTIFF,
		ConvertMOV:    portal.bridge.Config.Bridge.ConvertMOV,
		ConvertCAF:    true,
		MaxFileSize:   br.MediaConfig.UploadSize,
		Threads:       portal.bridge.Config.Bridge.MatrixThreads,
	}
	portal.updateLogger()
	portal.log = maulogadapt.ZeroAsMau(&portal.zlog)
	go portal.handleMessageLoop()
	return portal
}

type Portal struct {
	*database.Portal

	bridge *IMBridge
	user   *User

	// Deprecated
	log  maulogger.Logger
	zlog zerolog.Logger

	Messages       chan any
	MatrixMessages chan *event.Event

	MsgConv *msgconv.MessageConverter

	roomCreateLock sync.Mutex

	userIsTyping bool
	typingLock   sync.Mutex
}

func (portal *Portal) updateLogger() {
	portal.zlog = portal.bridge.ZLog.With().
		Str("portal_id", portal.URI.String()).
		Int("portal_receiver", portal.Receiver).
		Str("room_id", portal.MXID.String()).
		Logger()
}

var (
	_ bridge.Portal                    = (*Portal)(nil)
	_ bridge.ReadReceiptHandlingPortal = (*Portal)(nil)
	_ bridge.TypingPortal              = (*Portal)(nil)
	//	_ bridge.MembershipHandlingPortal = (*Portal)(nil)
	//	_ bridge.MetaHandlingPortal = (*Portal)(nil)
	//	_ bridge.DisappearingPortal = (*Portal)(nil)
)

const intentKey = "com.beeper.portal.intent"

func (portal *Portal) UploadMatrixMedia(ctx context.Context, data []byte, fileName, contentType string) (id.ContentURIString, error) {
	intent, ok := ctx.Value(intentKey).(*appservice.IntentAPI)
	if !ok {
		intent = portal.MainIntent()
	}
	req := mautrix.ReqUploadMedia{
		ContentBytes: data,
		ContentType:  contentType,
		FileName:     fileName,
	}
	if portal.bridge.Config.Homeserver.AsyncMedia {
		uploaded, err := intent.UploadAsync(req)
		if err != nil {
			return "", err
		}
		return uploaded.ContentURI.CUString(), nil
	} else {
		uploaded, err := intent.UploadMedia(req)
		if err != nil {
			return "", err
		}
		return uploaded.ContentURI.CUString(), nil
	}
}

func (portal *Portal) DownloadMatrixMedia(ctx context.Context, uriString id.ContentURIString) ([]byte, error) {
	parsedURI, err := uriString.Parse()
	if err != nil {
		return nil, fmt.Errorf("malformed content URI: %w", err)
	}
	return portal.MainIntent().DownloadBytesContext(ctx, parsedURI)
}

func (portal *Portal) GetiMessageThreadRoot(ctx context.Context, content *event.MessageEventContent) string {
	threadRootMXID := content.RelatesTo.GetThreadParent()
	replyToID := content.RelatesTo.GetReplyTo()
	log := zerolog.Ctx(ctx).With().
		Str("reply_to_mxid", replyToID.String()).
		Str("thread_root_mxid", threadRootMXID.String()).
		Logger()
	var replyToMsg *database.Message
	var err error
	if len(threadRootMXID) > 0 {
		replyToMsg, err = portal.bridge.DB.Message.GetByMXID(ctx, threadRootMXID)
		if err != nil {
			log.Warn().Err(err).Msg("Failed to get thread root message from database")
			return ""
		}
	} else if len(replyToID) > 0 {
		replyToMsg, err = portal.bridge.DB.Message.GetByMXID(ctx, replyToID)
		if err != nil {
			log.Warn().Err(err).Msg("Failed to get reply target message from database")
			return ""
		}
		if replyToMsg != nil && replyToMsg.ReplyToID != uuid.Nil {
			replyToMsg, err = portal.bridge.DB.Message.GetByID(ctx, portal.Key, replyToMsg.ReplyToID, replyToMsg.ReplyToPart)
			if err != nil {
				log.Warn().Err(err).
					Str("reply_to_guid", replyToMsg.ReplyToID.String()).
					Int("reply_to_part", replyToMsg.ReplyToPart).
					Msg("Failed to get thread root based on reply target message from database")
				return ""
			}
		}
	}
	if replyToMsg == nil {
		return ""
	}
	return imessage.ParsedThreadRoot{
		MessagePartInfo: imessage.MessagePartInfo{
			PartID:     replyToMsg.Part,
			StartIndex: replyToMsg.StartIndex,
			Length:     replyToMsg.Length,
		},
		ID: replyToMsg.ID,
	}.String()
}

func (portal *Portal) IsEncrypted() bool {
	return portal.Encrypted
}

func (portal *Portal) MarkEncrypted() {
	portal.Encrypted = true
	portal.Update(context.TODO())
}

func (portal *Portal) ReceiveMatrixEvent(u bridge.User, evt *event.Event) {
	brUser := u.(*User)
	if brUser != portal.user {
		portal.sendErrorMessage(evt, fmt.Errorf("internal error: user id mismatch"), "", true, status.MsgStatusPermFailure)
	} else if !portal.user.IsLoggedIn() {
		portal.sendErrorMessage(evt, fmt.Errorf("not logged into iMessage"), "", true, status.MsgStatusPermFailure)
	} else {
		portal.MatrixMessages <- evt
	}
}

func (portal *Portal) HandleMatrixMeta(u bridge.User, evt *event.Event) {
	brUser := u.(*User)
	if brUser != portal.user {
		portal.sendErrorMessage(evt, fmt.Errorf("internal error: user id mismatch"), "", true, status.MsgStatusPermFailure)
	} else if !portal.user.IsLoggedIn() {
		portal.sendErrorMessage(evt, fmt.Errorf("not logged into iMessage"), "", true, status.MsgStatusPermFailure)
	} else {
		switch evt.Type {
		case event.StateRoomName:
			portal.HandleMatrixRoomName(evt)
		case event.StateRoomAvatar:
			portal.HandleMatrixRoomAvatar(evt)
		}
	}
}

func (portal *Portal) handleMatrixParticipantChange(u bridge.User, evt *event.Event, newParticipants []uri.ParsedURI) {
	brUser := u.(*User)
	if brUser != portal.user {
		portal.sendErrorMessage(evt, fmt.Errorf("internal error: user id mismatch"), "", true, status.MsgStatusPermFailure)
		return
	} else if !portal.user.IsLoggedIn() {
		portal.sendErrorMessage(evt, fmt.Errorf("not logged into iMessage"), "", true, status.MsgStatusPermFailure)
		return
	}
	portal.zlog.Info().
		Any("old_participants", portal.Participants).
		Any("new_participants", newParticipants).
		Msg("Updating iMessage chat participants")

	_, err := portal.user.IM.UpdateParticipants(context.TODO(), portal.OutgoingHandle, portal.Participants, portal.GroupID, newParticipants)
	if err != nil {
		portal.zlog.Warn().Err(err).Msg("Failed to leave iMessage chat")
		return
	}
	portal.Participants = newParticipants
	portal.SyncParticipants(portal.Participants)
	err = portal.Update(context.TODO())
	if err != nil {
		portal.zlog.Warn().Err(err).Msg("Failed to save new participants list")
	}
}

func (portal *Portal) HandleMatrixLeave(u bridge.User, evt *event.Event) {
	newParticipants := slices.DeleteFunc(slices.Clone(portal.Participants), func(uri uri.ParsedURI) bool {
		return slices.Contains(portal.user.IM.User.Handles, uri)
	})
	portal.handleMatrixParticipantChange(u, evt, newParticipants)
}

func (portal *Portal) HandleMatrixKick(u bridge.User, ghost bridge.Ghost, evt *event.Event) {
	newParticipants := slices.DeleteFunc(slices.Clone(portal.Participants), func(uri uri.ParsedURI) bool {
		return uri == ghost.(*Puppet).URI
	})
	portal.handleMatrixParticipantChange(u, evt, newParticipants)
}

func (portal *Portal) HandleMatrixInvite(u bridge.User, ghost bridge.Ghost, evt *event.Event) {
	newParticipants := uri.Sort(append(slices.Clone(portal.Participants), ghost.(*Puppet).URI))
	portal.handleMatrixParticipantChange(u, evt, newParticipants)
}

func (portal *Portal) SyncParticipants(memberURIs []uri.ParsedURI) (memberIDs []id.UserID) {
	// Don't sync own ghosts into portal
	memberURIs = slices.DeleteFunc(slices.Clone(memberURIs), func(uri uri.ParsedURI) bool {
		return slices.Contains(portal.user.IM.User.Handles, uri)
	})
	var members map[id.UserID]mautrix.JoinedMember
	if portal.MXID != "" {
		membersResp, err := portal.MainIntent().JoinedMembers(portal.MXID)
		if err != nil {
			portal.log.Warnfln("Failed to get members in room to remove extra members: %v", err)
		} else {
			members = membersResp.Joined
			delete(members, portal.bridge.Bot.UserID)
			delete(members, portal.user.MXID)
		}
	}
	portal.zlog.Debug().
		Int("chat_info_member_count", len(memberURIs)).
		Int("room_member_count", len(members)).
		Msg("Syncing participants")
	for _, memberURI := range memberURIs {
		puppet := portal.user.GetPuppetByURI(memberURI)
		puppet.Sync()
		memberIDs = append(memberIDs, puppet.MXID)
		if portal.MXID != "" {
			err := puppet.Intent.EnsureJoined(portal.MXID)
			if err != nil {
				portal.log.Warnfln("Failed to make puppet of %s join %s: %v", memberURI, portal.MXID, err)
			}
		}
		if members != nil {
			delete(members, puppet.MXID)
		}
	}
	if portal.MXID != "" && members != nil {
		for userID := range members {
			portal.log.Debugfln("Removing %s as they don't seem to be in the group anymore", userID)
			_, err := portal.MainIntent().KickUser(portal.MXID, &mautrix.ReqKickUser{
				Reason: "user is no longer in group",
				UserID: userID,
			})
			if err != nil {
				portal.log.Errorfln("Failed to remove %s: %v", userID, err)
			}
		}
	}
	return memberIDs
}

func (portal *Portal) UpdateName(name string, intent *appservice.IntentAPI) bool {
	if portal.Name == name && portal.NameSet {
		return false
	}

	portal.Name = name

	if len(portal.MXID) == 0 {
		// We still want to count this as an update, but we won't actually set
		// anything in a matrix room because there isn't one.
		return true
	}

	if intent == nil {
		intent = portal.MainIntent()
	}
	_, err := intent.SetRoomName(portal.MXID, name)
	if mainIntent := portal.MainIntent(); errors.Is(err, mautrix.MForbidden) && intent != mainIntent {
		_, err = mainIntent.SetRoomName(portal.MXID, name)
	}
	if err != nil {
		portal.log.Warnln("Failed to set room name:", err)
	} else {
		portal.Name = name
		portal.NameSet = true
		portal.UpdateBridgeInfo()
		return true
	}
	return false
}

func (portal *Portal) SyncWithInfo(sourceMsg *imessage.Message) {
	portal.zlog.Debug().Msg("Syncing with chat info")
	update := false
	if sourceMsg.GroupID != "" && sourceMsg.GroupID != portal.GroupID {
		portal.log.Infofln("Found portal thread ID in sync: %s (prev: %s)", sourceMsg.GroupID, portal.GroupID)
		portal.GroupID = sourceMsg.GroupID
		update = true
	}
	if !portal.IsPrivateChat() {
		update = portal.UpdateName(sourceMsg.GroupName, nil) || update
		portal.SyncParticipants(sourceMsg.Participants)
	}
	if update {
		// TODO don't ignore errors
		portal.Update(context.TODO())
		portal.UpdateBridgeInfo()
	}
}

func (portal *Portal) ensureUserInvited(user *User) {
	user.ensureInvited(portal.MainIntent(), portal.MXID, portal.IsPrivateChat())
}

func (portal *Portal) Sync(backfill bool) {
	if len(portal.MXID) == 0 {
		portal.log.Infoln("Creating Matrix room due to sync")
		err := portal.CreateMatrixRoom(nil)
		if err != nil {
			portal.log.Errorln("Failed to create portal room:", err)
		}
		return
	}

	portal.ensureUserInvited(portal.user)
	portal.addToSpace(portal.user)

	pls, err := portal.MainIntent().PowerLevels(portal.MXID)
	if err != nil {
		portal.zlog.Warn().Err(err).Msg("Failed to get power levels")
	} else if portal.updatePowerLevels(pls) {
		resp, err := portal.MainIntent().SetPowerLevels(portal.MXID, pls)
		if err != nil {
			portal.zlog.Warn().Err(err).Msg("Failed to update power levels")
		} else {
			portal.zlog.Debug().Str("event_id", resp.EventID.String()).Msg("Updated power levels")
		}
	}

	if !portal.IsPrivateChat() {
		// TODO can anything be synced in group chats?
	} else {
		portal.GetDMPuppet().Sync()
	}
}

type CustomReadReceipt struct {
	Timestamp          int64  `json:"ts,omitempty"`
	DoublePuppetSource string `json:"fi.mau.double_puppet_source,omitempty"`
}

type CustomReadMarkers struct {
	mautrix.ReqSetReadMarkers
	ReadExtra      CustomReadReceipt `json:"com.beeper.read.extra"`
	FullyReadExtra CustomReadReceipt `json:"com.beeper.fully_read.extra"`
}

func (portal *Portal) markRead(intent *appservice.IntentAPI, eventID id.EventID, readAt time.Time) error {
	if intent == nil {
		return nil
	}
	var extra CustomReadReceipt
	if intent == portal.user.DoublePuppetIntent {
		extra.DoublePuppetSource = portal.bridge.Name
	}
	if !readAt.IsZero() {
		extra.Timestamp = readAt.UnixMilli()
	}
	content := CustomReadMarkers{
		ReqSetReadMarkers: mautrix.ReqSetReadMarkers{
			Read:      eventID,
			FullyRead: eventID,
		},
		ReadExtra:      extra,
		FullyReadExtra: extra,
	}
	return intent.SetReadMarkers(portal.MXID, &content)
}

func (portal *Portal) HandleiMessageReadReceipt(rr *imessage.ReadReceipt) {
	if len(portal.MXID) == 0 {
		return
	}
	var intent *appservice.IntentAPI
	if rr.IsFromMe {
		intent = portal.user.DoublePuppetIntent
	} else if portal.IsPrivateChat() {
		intent = portal.MainIntent()
	} else {
		portal.log.Debugfln("Dropping unexpected read receipt %+v", *rr)
		return
	}
	if intent == nil {
		portal.log.Errorfln("Dropping read receipt %+v because intent is nil", *rr)
		return
	}

	// TODO don't ignore errors
	if message, _ := portal.bridge.DB.Message.GetLastPartByID(context.TODO(), portal.Key, rr.ReadUpTo); message != nil {
		err := portal.markRead(intent, message.MXID, rr.ReadAt)
		if err != nil {
			portal.log.Warnln("Failed to send read receipt for %s from %s: %v", message.MXID, intent.UserID)
		}
	} else if tapback, _ := portal.bridge.DB.Tapback.GetByTapbackID(context.TODO(), portal.Key, rr.ReadUpTo); tapback != nil {
		err := portal.markRead(intent, tapback.MXID, rr.ReadAt)
		if err != nil {
			portal.log.Warnln("Failed to send read receipt for %s from %s: %v", tapback.MXID, intent.UserID)
		}
	} else {
		portal.log.Debugfln("Dropping read receipt for %s: not found in db messages or tapbacks", rr.ReadUpTo)
	}
}

type UnreadAccountData struct {
	Unread    bool   `json:"unread"`
	Timestamp uint64 `json:"ts,omitempty"`
}

func (portal *Portal) HandleiMessageMarkUnread(msg *imessage.MarkUnread) {
	markedUnreadKey := "m.marked_unread"
	markedUnread := UnreadAccountData{
		Unread:    true,
		Timestamp: uint64(time.Now().UnixMilli()),
	}
	err := portal.user.DoublePuppetIntent.SetRoomAccountData(portal.MXID, markedUnreadKey, &markedUnread)
	if err != nil {
		portal.zlog.Err(err).Msg("Couldn't set account data to mark unread")
	}
}

func (portal *Portal) handleMessageLoop() {
	for {
		var start time.Time
		var thing string
		select {
		case untypedMsg := <-portal.Messages:
			start = time.Now()
			switch msg := untypedMsg.(type) {
			case *imessage.Message:
				thing = "iMessage"
				portal.HandleiMessage(msg)
			case *imessage.GroupInfoChange:
				portal.HandleiMessageGroupInfoChange(msg)
			case *imessage.MessageEdit:
				thing = "iMessage edit"
				portal.HandleiMessageEdit(msg)
			case *imessage.MessageUnsend:
				thing = "iMessage unsend"
				portal.HandleiMessageUnsend(msg)
			case *imessage.ReadReceipt:
				thing = "read receipt"
				portal.HandleiMessageReadReceipt(msg)
			case *imessage.MarkUnread:
				thing = "mark unread"
				portal.HandleiMessageMarkUnread(msg)
			case *imessage.SendMessageStatus:
				thing = "message status"
				portal.HandleiMessageSendMessageStatus(msg)
			case *direct.MessageDelivered:
				thing = "delivered"
				portal.HandleiMessageDelivered(msg)
			default:
				thing = "unsupported iMessage struct"
				portal.log.Warnfln("Unsupported data type %T in portal message channel", untypedMsg)
			}
		case evt := <-portal.MatrixMessages:
			start = time.Now()
			switch evt.Type {
			case event.EventMessage, event.EventSticker:
				thing = "Matrix message"
				portal.HandleMatrixMessage(evt)
			case event.EventRedaction:
				thing = "Matrix redaction"
				portal.HandleMatrixRedaction(evt)
			case event.EventReaction:
				thing = "Matrix reaction"
				portal.HandleMatrixReaction(evt)
			default:
				thing = "unsupported Matrix event"
				portal.log.Warnfln("Unsupported event type %+v in portal message channel", evt.Type)
			}
		}
		portal.log.Debugfln(
			"Handled %s in %s",
			thing, time.Since(start),
		)
	}
}

func (portal *Portal) HandleiMessageDelivered(deliv *direct.MessageDelivered) {
	var eventID id.EventID
	// TODO don't ignore errors
	if msg, err := portal.bridge.DB.Message.GetLastPartByID(context.TODO(), portal.Key, deliv.ID); msg != nil {
		eventID = msg.MXID
	} else if tapback, _ := portal.bridge.DB.Tapback.GetByTapbackID(context.TODO(), portal.Key, deliv.ID); tapback != nil {
		eventID = tapback.MXID
	} else {
		if err != nil {
			fmt.Println("MEOW 3:<", err)
		}
		portal.log.Debugfln("Dropping delivered status for %s: not found in db messages or tapbacks", deliv.ID)
		return
	}
	go portal.bridge.SendRawMessageCheckpoint(&status.MessageCheckpoint{
		EventID:    eventID,
		RoomID:     portal.MXID,
		Step:       status.MsgStepRemote,
		Timestamp:  jsontime.UnixMilliNow(),
		Status:     status.MsgStatusDelivered,
		ReportedBy: status.MsgReportedByBridge,
	})
	deliveredTo := make([]id.UserID, 0, len(deliv.To))
	for to := range deliv.To {
		deliveredTo = append(deliveredTo, portal.bridge.FormatPuppetMXID(portal.user.RowID, to))
	}
	portal.zlog.Debug().
		Array("delivered_to", exzerolog.ArrayOfStringers(deliveredTo)).
		Stringer("message_uuid", deliv.ID).
		Msg("Got delivery receipts for message")
	// Only enable delivery status in groups for now
	if portal.IsPrivateChat() && len(deliveredTo) == 1 && deliveredTo[0] == portal.MainIntent().UserID {
		go portal.sendSuccessMessageStatus(eventID, deliv.ID, deliveredTo)
	}
}

func (portal *Portal) HandleiMessageSendMessageStatus(msgStatus *imessage.SendMessageStatus) {
	var eventID id.EventID
	// TODO don't ignore errors
	if msg, err := portal.bridge.DB.Message.GetLastPartByID(context.TODO(), portal.Key, msgStatus.GUID); msg != nil {
		eventID = msg.MXID
	} else if tapback, _ := portal.bridge.DB.Tapback.GetByTapbackID(context.TODO(), portal.Key, msgStatus.GUID); tapback != nil {
		eventID = tapback.MXID
	} else {
		if err != nil {
			fmt.Println("MEOW 3:<", err)
		}
		portal.log.Debugfln("Dropping send message status for %s: not found in db messages or tapbacks", msgStatus.GUID)
		return
	}
	portal.log.Debugfln("Processing message status with type %s/%s for event %s/%s in %s/%s", msgStatus.Status, msgStatus.StatusCode, eventID, msgStatus.GUID, portal.MXID, portal.URI)
	switch msgStatus.Status {
	case "delivered":
		go portal.bridge.SendRawMessageCheckpoint(&status.MessageCheckpoint{
			EventID:    eventID,
			RoomID:     portal.MXID,
			Step:       status.MsgStepRemote,
			Timestamp:  jsontime.UnixMilliNow(),
			Status:     status.MsgStatusDelivered,
			ReportedBy: status.MsgReportedByBridge,
		})
		if p := portal.GetDMPuppet(); p != nil {
			go portal.sendSuccessMessageStatus(eventID, msgStatus.GUID, []id.UserID{p.MXID})
		}
	case "fail":
		portal.zlog.Debug().Any("status", msgStatus).Msg("Got failed message status")
		evt, err := portal.MainIntent().GetEvent(portal.MXID, eventID)
		if err != nil {
			portal.log.Warnfln("Failed to lookup event %s/%s %s/%s: %v", string(eventID), portal.MXID, msgStatus.GUID, portal.URI, err)
			return
		}
		errString := "internal error"
		humanReadableError := "internal error"
		if len(msgStatus.Message) != 0 {
			humanReadableError = msgStatus.Message
			if len(msgStatus.StatusCode) != 0 {
				errString = fmt.Sprintf("%s: %s", msgStatus.StatusCode, msgStatus.Message)
			} else {
				errString = msgStatus.Message
			}
		} else if len(msgStatus.StatusCode) != 0 {
			errString = msgStatus.StatusCode
		}
		portal.sendErrorMessage(evt, errors.New(errString), humanReadableError, true, status.MsgStatusPermFailure)
	default:
		portal.log.Warnfln("Unrecognized message status type %s", msgStatus.Status)
	}
}

func (portal *Portal) GetBasePowerLevels() *event.PowerLevelsEventContent {
	anyone := 0
	nope := 99
	return &event.PowerLevelsEventContent{
		UsersDefault:    anyone,
		EventsDefault:   anyone,
		RedactPtr:       &anyone,
		StateDefaultPtr: &nope,
		BanPtr:          &nope,
		InvitePtr:       &anyone,
		KickPtr:         &anyone,
		Users: map[id.UserID]int{
			portal.user.MXID:           1,
			portal.MainIntent().UserID: 100,
			portal.bridge.Bot.UserID:   100,
		},
		Events: map[string]int{
			event.StateRoomName.Type:   anyone,
			event.StateRoomAvatar.Type: anyone,
			event.StateTopic.Type:      anyone,
		},
	}
}

func (portal *Portal) updatePowerLevels(pl *event.PowerLevelsEventContent) bool {
	update := false
	anyone := 0
	if pl.Invite() != anyone {
		pl.InvitePtr = &anyone
		update = true
	}
	if pl.Kick() != anyone {
		pl.KickPtr = &anyone
		update = true
	}
	update = pl.EnsureUserLevel(portal.user.MXID, 1) || update
	return pl.EnsureUserLevel(portal.bridge.Bot.UserID, 100) || update
}

const bridgeInfoProto = "fi.mau.imessage"

func (portal *Portal) getBridgeInfoStateKey() string {
	return fmt.Sprintf("%s://%s/%s",
		bridgeInfoProto, strings.ToLower(portal.Service.String()), portal.URI.Identifier)
}

func (portal *Portal) GetBridgeInfo() (string, *database.CustomBridgeInfoContent) {
	content := portal.Portal.GetBridgeInfo()
	content.BridgeEventContent.BridgeBot = portal.bridge.Bot.UserID
	content.BridgeEventContent.Creator = portal.MainIntent().UserID
	content.BridgeEventContent.Protocol.AvatarURL = id.ContentURIString(portal.bridge.Config.AppService.Bot.Avatar)
	return portal.getBridgeInfoStateKey(), content
}

func (portal *Portal) UpdateBridgeInfo() {
	if len(portal.MXID) == 0 {
		portal.log.Debugln("Not updating bridge info: no Matrix room created")
		return
	}
	portal.log.Debugln("Updating bridge info...")
	intent := portal.MainIntent()
	if portal.Encrypted && intent != portal.bridge.Bot && portal.IsPrivateChat() {
		intent = portal.bridge.Bot
	}
	stateKey, content := portal.GetBridgeInfo()
	_, err := intent.SendStateEvent(portal.MXID, event.StateBridge, stateKey, content)
	if err != nil {
		portal.log.Warnln("Failed to update m.bridge:", err)
	}
	_, err = intent.SendStateEvent(portal.MXID, event.StateHalfShotBridge, stateKey, content)
	if err != nil {
		portal.log.Warnln("Failed to update uk.half-shot.bridge:", err)
	}
}

func (portal *Portal) GetEncryptionEventContent() (evt *event.EncryptionEventContent) {
	evt = &event.EncryptionEventContent{Algorithm: id.AlgorithmMegolmV1}
	if rot := portal.bridge.Config.Bridge.Encryption.Rotation; rot.EnableCustom {
		evt.RotationPeriodMillis = rot.Milliseconds
		evt.RotationPeriodMessages = rot.Messages
	}
	return
}

func (portal *Portal) shouldSetDMRoomMetadata() bool {
	return !portal.IsPrivateChat() ||
		portal.bridge.Config.Bridge.PrivateChatPortalMeta == "always" ||
		(portal.IsEncrypted() && portal.bridge.Config.Bridge.PrivateChatPortalMeta != "never")
}

func (portal *Portal) getRoomCreateContent() *mautrix.ReqCreateRoom {
	bridgeInfoStateKey, bridgeInfo := portal.GetBridgeInfo()

	initialState := []*event.Event{{
		Type: event.StatePowerLevels,
		Content: event.Content{
			Parsed: portal.GetBasePowerLevels(),
		},
	}, {
		Type:     event.StateBridge,
		Content:  event.Content{Parsed: bridgeInfo},
		StateKey: &bridgeInfoStateKey,
	}, {
		// TODO remove this once https://github.com/matrix-org/matrix-doc/pull/2346 is in spec
		Type:     event.StateHalfShotBridge,
		Content:  event.Content{Parsed: bridgeInfo},
		StateKey: &bridgeInfoStateKey,
	}}
	if portal.bridge.Config.Bridge.Encryption.Default {
		initialState = append(initialState, &event.Event{
			Type: event.StateEncryption,
			Content: event.Content{
				Parsed: portal.GetEncryptionEventContent(),
			},
		})
		portal.Encrypted = true
	}
	if parsedAvatarURL, err := portal.AvatarURL.Parse(); err != nil {
		portal.log.Warnln("Failed to parse avatar URL:", err)
	} else if !parsedAvatarURL.IsEmpty() && portal.shouldSetDMRoomMetadata() {
		initialState = append(initialState, &event.Event{
			Type: event.StateRoomAvatar,
			Content: event.Content{
				Parsed: event.RoomAvatarEventContent{URL: parsedAvatarURL},
			},
		})
	}

	var invite []id.UserID

	if portal.IsPrivateChat() {
		invite = append(invite, portal.bridge.Bot.UserID)
	}

	autoJoinInvites := portal.bridge.Config.Homeserver.Software == bridgeconfig.SoftwareHungry
	if autoJoinInvites {
		invite = append(invite, portal.user.MXID)
	}

	creationContent := make(map[string]interface{})
	if !portal.bridge.Config.Bridge.FederateRooms {
		creationContent["m.federate"] = false
	}
	req := &mautrix.ReqCreateRoom{
		Visibility:      "private",
		Name:            portal.Name,
		Invite:          invite,
		Preset:          "private_chat",
		IsDirect:        portal.IsPrivateChat(),
		InitialState:    initialState,
		CreationContent: creationContent,

		BeeperAutoJoinInvites: autoJoinInvites,
	}
	if !portal.shouldSetDMRoomMetadata() {
		req.Name = ""
	}
	return req
}

// CreateMatrixRoom creates a matrix room
// sourceMsg is only required for group chats, otherwise can be nil
func (portal *Portal) CreateMatrixRoom(sourceMsg *imessage.Message) error {
	portal.roomCreateLock.Lock()
	defer portal.roomCreateLock.Unlock()
	if len(portal.MXID) > 0 {
		return nil
	}

	intent := portal.MainIntent()
	err := intent.EnsureRegistered()
	if err != nil {
		return err
	}

	if portal.IsPrivateChat() {
		puppet := portal.GetDMPuppet()
		puppet.Sync()
		portal.Name = puppet.Displayname
		portal.AvatarURL = puppet.AvatarURL.CUString()
		portal.AvatarHash = puppet.AvatarHash
		if sourceMsg != nil {
			portal.Service = sourceMsg.Service
		} else {
			portal.Service = imessage.ServiceIMessage
		}
	} else {
		// If there's no chat info for a group, it probably doesn't exist, and we shouldn't auto-create a Matrix room for it.
		if sourceMsg == nil {
			return fmt.Errorf("failed to get chat info: not implemented")
		}
		portal.Name = sourceMsg.GroupName
		portal.GroupID = sourceMsg.GroupID
		portal.Participants = sourceMsg.Participants
		portal.Service = sourceMsg.Service
	}

	req := portal.getRoomCreateContent()
	if req.BeeperAutoJoinInvites && !portal.IsPrivateChat() {
		req.Invite = append(req.Invite, portal.SyncParticipants(sourceMsg.Participants)...)
	}
	resp, err := intent.CreateRoom(req)
	if err != nil {
		return err
	}
	portal.NameSet = true
	portal.AvatarSet = true
	portal.MXID = resp.RoomID
	portal.updateLogger()
	portal.zlog.Debug().Msg("Storing created room ID in database")
	// TODO don't ignore errors
	portal.Update(context.TODO())
	portal.bridge.portalsLock.Lock()
	portal.bridge.portalsByMXID[portal.MXID] = portal
	portal.bridge.portalsLock.Unlock()

	portal.zlog.Debug().Interface("members", req.Invite).Msg("Updating state store with initial memberships")
	inviteeMembership := event.MembershipInvite
	if req.BeeperAutoJoinInvites {
		inviteeMembership = event.MembershipJoin
	}
	for _, user := range req.Invite {
		portal.bridge.StateStore.SetMembership(portal.MXID, user, inviteeMembership)
	}

	if portal.Encrypted && !req.BeeperAutoJoinInvites {
		portal.zlog.Debug().Msg("Ensuring bridge bot is joined to portal")
		err = portal.bridge.Bot.EnsureJoined(portal.MXID)
		if err != nil {
			portal.log.Errorln("Failed to join created portal with bridge bot for e2be:", err)
		}
	}

	if !req.BeeperAutoJoinInvites {
		portal.ensureUserInvited(portal.user)
	}
	portal.addToSpace(portal.user)

	if !portal.IsPrivateChat() && !req.BeeperAutoJoinInvites {
		portal.zlog.Debug().Msg("New portal is group chat, syncing participants")
		portal.SyncParticipants(sourceMsg.Participants)
	}
	portal.zlog.Debug().Msg("Finished creating Matrix room")

	return nil
}

func (portal *Portal) addToSpace(user *User) {
	spaceID := user.GetSpaceRoom()
	if len(spaceID) == 0 || portal.InSpace {
		return
	}
	_, err := portal.bridge.Bot.SendStateEvent(spaceID, event.StateSpaceChild, portal.MXID.String(), &event.SpaceChildEventContent{
		Via: []string{portal.bridge.Config.Homeserver.Domain},
	})
	if err != nil {
		portal.log.Errorfln("Failed to add room to %s's personal filtering space (%s): %v", user.MXID, spaceID, err)
	} else {
		portal.log.Debugfln("Added room to %s's personal filtering space (%s)", user.MXID, spaceID)
		portal.InSpace = true
		portal.Update(context.TODO())
	}
}

func (portal *Portal) GetDMPuppet() *Puppet {
	if portal.IsPrivateChat() {
		return portal.user.GetPuppetByURI(portal.URI)
	}
	return nil
}

func (portal *Portal) MainIntent() *appservice.IntentAPI {
	if portal.IsPrivateChat() {
		return portal.GetDMPuppet().Intent
	}
	return portal.bridge.Bot
}

func (portal *Portal) sendMainIntentMessage(content interface{}) (*mautrix.RespSendEvent, error) {
	return portal.sendMessage(portal.MainIntent(), event.EventMessage, content, map[string]interface{}{}, 0)
}

func (portal *Portal) encrypt(intent *appservice.IntentAPI, content *event.Content, eventType event.Type) (event.Type, error) {
	if portal.Encrypted && portal.bridge.Crypto != nil {
		intent.AddDoublePuppetValue(content)
		err := portal.bridge.Crypto.Encrypt(portal.MXID, eventType, content)
		if err != nil {
			return eventType, fmt.Errorf("failed to encrypt event: %w", err)
		}
		eventType = event.EventEncrypted
	}
	return eventType, nil
}

func (portal *Portal) sendMessage(intent *appservice.IntentAPI, eventType event.Type, content interface{}, extraContent map[string]interface{}, timestamp int64) (*mautrix.RespSendEvent, error) {
	wrappedContent := &event.Content{Parsed: content}
	wrappedContent.Raw = extraContent
	var err error
	eventType, err = portal.encrypt(intent, wrappedContent, eventType)
	if err != nil {
		return nil, err
	}

	_, _ = intent.UserTyping(portal.MXID, false, 0)
	if timestamp == 0 {
		return intent.SendMessageEvent(portal.MXID, eventType, &wrappedContent)
	} else {
		return intent.SendMassagedMessageEvent(portal.MXID, eventType, &wrappedContent, timestamp)
	}
}

func (portal *Portal) sendErrorMessage(evt *event.Event, rootErr error, humanReadableError string, isCertain bool, checkpointStatus status.MessageCheckpointStatus) {
	portal.bridge.SendMessageCheckpoint(evt, status.MsgStepRemote, rootErr, checkpointStatus, 0)

	possibility := "may not have been"
	if isCertain {
		possibility = "was not"
	}

	errorIntent := portal.bridge.Bot
	if !portal.Encrypted {
		// Bridge bot isn't present in unencrypted DMs
		errorIntent = portal.MainIntent()
	}

	if portal.bridge.Config.Bridge.MessageStatusEvents {
		reason := event.MessageStatusGenericError
		msgStatusCode := event.MessageStatusRetriable
		switch checkpointStatus {
		case status.MsgStatusUnsupported:
			reason = event.MessageStatusUnsupported
			msgStatusCode = event.MessageStatusFail
		case status.MsgStatusTimeout:
			reason = event.MessageStatusTooOld
		}
		if humanReadableError == "" {
			humanReadableError = rootErr.Error()
		} else if humanReadableError == "-" {
			humanReadableError = ""
		}

		content := event.BeeperMessageStatusEventContent{
			Network: portal.getBridgeInfoStateKey(),
			RelatesTo: event.RelatesTo{
				Type:    event.RelReference,
				EventID: evt.ID,
			},
			Reason:  reason,
			Status:  msgStatusCode,
			Error:   rootErr.Error(),
			Message: humanReadableError,
		}
		_, err := errorIntent.SendMessageEvent(portal.MXID, event.BeeperMessageStatus, &event.Content{
			Parsed: &content,
		})
		if err != nil {
			portal.log.Warnln("Failed to send message send status event:", err)
			return
		}
	}
	if portal.bridge.Config.Bridge.SendErrorNotices {
		_, err := portal.sendMessage(errorIntent, event.EventMessage, event.MessageEventContent{
			MsgType: event.MsgNotice,
			Body:    fmt.Sprintf("\u26a0 Your message %s bridged: %v", possibility, rootErr),
		}, map[string]interface{}{}, 0)
		if err != nil {
			portal.log.Warnfln("Failed to send bridging error message:", err)
			return
		}
	}
}

func (portal *Portal) sendDeliveryReceipt(eventID id.EventID) {
	if portal.bridge.Config.Bridge.DeliveryReceipts {
		err := portal.bridge.Bot.MarkRead(portal.MXID, eventID)
		if err != nil {
			portal.log.Debugfln("Failed to send delivery receipt for %s: %v", eventID, err)
		}
	}
}

func (portal *Portal) sendSuccessCheckpoint(evt *event.Event, msgID uuid.UUID) {
	go portal.bridge.SendMessageSuccessCheckpoint(evt, status.MsgStepRemote, 0)
	portal.sendSuccessMessageStatus(evt.ID, msgID, []id.UserID{})
}

func (portal *Portal) sendSuccessMessageStatus(eventID id.EventID, msgID uuid.UUID, deliveredTo []id.UserID) {
	if !portal.bridge.Config.Bridge.MessageStatusEvents {
		return
	}

	mainContent := &event.BeeperMessageStatusEventContent{
		Network: portal.getBridgeInfoStateKey(),
		RelatesTo: event.RelatesTo{
			Type:    event.RelReference,
			EventID: eventID,
		},
		Status: event.MessageStatusSuccess,
	}

	if (portal.IsPrivateChat() && portal.Service == imessage.ServiceIMessage) || len(deliveredTo) > 0 {
		// This is an iMessage DM, then we want to include the list of users
		// that the message has been delivered to.
		mainContent.DeliveredToUsers = &deliveredTo
	}

	content := &event.Content{
		Parsed: mainContent,
		Raw: map[string]any{
			"com.beeper.imessage.message_uuid": msgID.String(),
		},
	}

	statusIntent := portal.bridge.Bot
	if !portal.Encrypted {
		statusIntent = portal.MainIntent()
	}

	// Hack: don't send MSS success before the message is delivered, instead send a failure if the delivery doesn't happen in 5 minutes.
	// Brad 2023-08-29 For imessagego let's just go with straight up SUCCESS/DELIVERED and hopefully we don't have the same delivery
	// problems we had before
	// if mainContent.DeliveredToUsers != nil && len(*mainContent.DeliveredToUsers) == 0 {
	// 	ctx, cancel := context.WithCancel(context.Background())
	// 	portal.pendingMSSFailsLock.Lock()
	// 	portal.pendingMSSFails[eventID] = cancel
	// 	portal.pendingMSSFailsLock.Unlock()
	// 	go func() {
	// 		defer func() {
	// 			portal.pendingMSSFailsLock.Lock()
	// 			delete(portal.pendingMSSFails, eventID)
	// 			cancel()
	// 			portal.pendingMSSFailsLock.Unlock()
	// 		}()
	// 		select {
	// 		case <-time.After(5 * time.Minute):
	// 		case <-ctx.Done():
	// 			return
	// 		}
	// 		mainContent.Status = event.MessageStatusRetriable
	// 		mainContent.Reason = "com.beeper.imessage.delivery_timeout"
	// 		mainContent.Error = "delivery timeout"
	// 		mainContent.Message = "delivering message timed out"
	// 		_, err := statusIntent.SendMessageEvent(portal.MXID, event.BeeperMessageStatus, content)
	// 		if err != nil {
	// 			portal.log.Warnln("Failed to send message send status event:", err)
	// 		}
	// 	}()
	// 	return
	// }

	_, err := statusIntent.SendMessageEvent(portal.MXID, event.BeeperMessageStatus, content)
	if err != nil {
		portal.log.Warnln("Failed to send message send status event:", err)
	}
}

func (portal *Portal) shouldHandleMessage(evt *event.Event) error {
	if portal.bridge.Config.Bridge.MaxHandleSeconds == 0 {
		return nil
	}
	if time.Since(time.UnixMilli(evt.Timestamp)) < time.Duration(portal.bridge.Config.Bridge.MaxHandleSeconds)*time.Second {
		return nil
	}

	return fmt.Errorf("message is too old (over %d seconds)", portal.bridge.Config.Bridge.MaxHandleSeconds)
}

const MaxEditTime = 15 * time.Minute
const MaxUnsendTime = 2 * time.Minute

func (portal *Portal) HandleMatrixEdit(evt *event.Event, editEventID id.EventID, msg *direct.IMessage) {
	log := portal.zlog.With().
		Str("event_id", evt.ID.String()).
		Str("editing_event_id", editEventID.String()).
		Logger()
	if portal.Service == imessage.ServiceSMS {
		log.Debug().Msg("Ignoring edit of SMS message")
		portal.sendErrorMessage(evt, fmt.Errorf("can't edit SMS message"), "", true, status.MsgStatusPermFailure)
		return
	}

	if msg.Text == "" {
		log.Error().Msg("No text in edited message")
		portal.sendErrorMessage(evt, fmt.Errorf("no text in edited message"), "", true, status.MsgStatusPermFailure)
		return
	}

	editedMessage, err := portal.bridge.DB.Message.GetByMXID(context.TODO(), editEventID)
	if err != nil {
		log.Err(err).Msg("Failed to get message by MXID")
		return
	} else if editedMessage == nil {
		portal.sendErrorMessage(evt, fmt.Errorf("edit target message not found"), "", true, status.MsgStatusPermFailure)
		return
	}
	if time.Since(editedMessage.Time()) > MaxEditTime {
		portal.sendErrorMessage(evt, fmt.Errorf("can't edit messages older than 15 minutes"), "", true, status.MsgStatusPermFailure)
		return
	}
	log = log.With().
		Str("edited_message_id", editedMessage.ID.String()).
		Int("edited_message_part", editedMessage.Part).
		Logger()

	_, err = portal.user.IM.SendEdit(
		context.TODO(), portal.OutgoingHandle, msg.Participants, portal.GroupID,
		editedMessage.ID, editedMessage.Part, event.TextToHTML(msg.Text),
	)
	if err != nil {
		log.Err(err).Msg("Failed to send message edit")
		portal.bridge.SendMessageErrorCheckpoint(evt, status.MsgStepRemote, err, true, 0)
	} else {
		log.Debug().Msg("Handled Matrix edit of iMessage")
		portal.sendDeliveryReceipt(evt.ID)
		portal.sendSuccessCheckpoint(evt, editedMessage.ID)
	}

	// For some reason, when you edit, it doesn't seem to clear the
	// typing notification.
	portal.user.IM.SendTypingNotification(context.TODO(), portal.OutgoingHandle, msg.Participants, portal.GroupID, false)
}

func (portal *Portal) HandleMatrixMessage(evt *event.Event) {
	log := portal.zlog.With().
		Str("action", "handle matrix message").
		Str("event_id", evt.ID.String()).
		Str("sender", evt.Sender.String()).
		Logger()
	ctx := log.WithContext(context.TODO())
	content, ok := evt.Content.Parsed.(*event.MessageEventContent)
	if !ok {
		log.Warn().
			Str("event_type", evt.Type.String()).
			Type("content_type", evt.Content.Parsed).
			Msg("Unexpected event content type")
		return
	}
	log.Debug().Msg("Starting handling Matrix message")

	if err := portal.shouldHandleMessage(evt); err != nil {
		log.Debug().Err(err).Msg("Not handling message")
		portal.sendErrorMessage(evt, err, "", true, status.MsgStatusTimeout)
		return
	}

	editEventID := content.RelatesTo.GetReplaceID()
	if editEventID != "" && content.NewContent != nil {
		content = content.NewContent
	}

	msg, err := portal.MsgConv.ToiMessage(ctx, evt, content)
	if err != nil {
		log.Err(err).Msg("Failed to convert Matrix message")
		portal.sendErrorMessage(evt, err, "", true, status.MsgStatusPermFailure)
		return
	}

	if editEventID != "" {
		portal.HandleMatrixEdit(evt, editEventID, msg)
		return
	}

	dbMessage := portal.bridge.DB.Message.New()
	dbMessage.Portal = portal.Key
	dbMessage.ID = uuid.New()
	dbMessage.MXID = evt.ID
	dbMessage.RoomID = portal.MXID
	dbMessage.ReceivingHandle = portal.OutgoingHandle
	dbMessage.Timestamp = time.Now().UnixMilli()
	log = log.With().Str("message_id", dbMessage.ID.String()).Logger()
	ctx = log.WithContext(ctx)

	dbMessage.Part = 0
	dbMessage.StartIndex = 0
	dbMessage.Length = direct.TextLen(msg.Text)
	if msg.AttachmentCount > 0 {
		dbMessage.Length = 1
	}
	if msg.ThreadRoot != "" {
		tr, err := imessage.ParseThreadRoot(msg.ThreadRoot)
		if err != nil {
			log.Err(err).Str("thread_root", msg.ThreadRoot).Msg("Failed to parse converted message thread root")
		} else {
			dbMessage.ReplyToID = tr.ID
			dbMessage.ReplyToPart = tr.PartID
		}
	}
	err = dbMessage.Insert(ctx)
	if err != nil {
		log.Err(err).Msg("Failed to save outgoing message to database")
		portal.sendErrorMessage(evt, err, "-", true, status.MsgStatusPermFailure)
		return
	}

	if portal.Service == imessage.ServiceSMS {
		var sms *direct.ReflectedSMS
		sms, err = portal.MsgConv.ToSMS(ctx, msg, dbMessage.ID)
		if err != nil {
			log.Err(err).Msg("Failed to convert Matrix message to SMS")
			portal.sendErrorMessage(evt, err, "", true, status.MsgStatusPermFailure)
			return
		}
		_, err = portal.user.IM.SendSMS(ctx, sms)
	} else {
		_, err = portal.user.IM.SendMessage(ctx, portal.OutgoingHandle, msg, dbMessage.ID)
		if errors.Is(err, direct.ErrNotOnIMessage) {
			if !portal.IsPrivateChat() {
				portal.sendErrorMessage(evt, err, "Failed to send message to all group participants", true, status.MsgStatusPermFailure)
				return
			}
			smsHandle := portal.user.IM.User.SMSForwarding.GetHandle()
			if smsHandle.IsEmpty() {
				portal.sendErrorMessage(evt, err, "User not found on iMessage and SMS forwarding not available", true, status.MsgStatusPermFailure)
				return
			}
			var sms *direct.ReflectedSMS
			sms, err = portal.MsgConv.ToSMS(ctx, msg, dbMessage.ID)
			if err != nil {
				log.Err(err).Msg("Failed to convert Matrix message to SMS")
				portal.sendErrorMessage(evt, err, "", true, status.MsgStatusPermFailure)
				return
			}
			_, err = portal.user.IM.SendSMS(ctx, sms)
		}
	}
	if err != nil {
		log.Err(err).Msg("Error sending to iMessage")
		statusCode := status.MsgStatusPermFailure
		certain := false
		if errors.Is(err, ipc.ErrSizeLimitExceeded) {
			certain = true
			statusCode = status.MsgStatusUnsupported
		}
		var ipcErr ipc.Error
		if errors.As(err, &ipcErr) {
			certain = true
			err = errors.New(ipcErr.Message)
			switch ipcErr.Code {
			case ipc.ErrUnsupportedError.Code:
				statusCode = status.MsgStatusUnsupported
			case ipc.ErrTimeoutError.Code:
				statusCode = status.MsgStatusTimeout
			}
		}
		portal.sendErrorMessage(evt, err, ipcErr.Message, certain, statusCode)
	} else {
		portal.sendDeliveryReceipt(evt.ID)
		portal.sendSuccessCheckpoint(evt, dbMessage.ID)
		log.Debug().Msg("Successfully handled Matrix message")
	}
}

func (portal *Portal) sendUnsupportedCheckpoint(evt *event.Event, step status.MessageCheckpointStep, err error) {
	portal.log.Errorf("Sending unsupported checkpoint for %s: %+v", evt.ID, err)
	portal.bridge.SendMessageCheckpoint(evt, step, err, status.MsgStatusUnsupported, 0)

	if portal.bridge.Config.Bridge.MessageStatusEvents {
		content := event.BeeperMessageStatusEventContent{
			Network: portal.getBridgeInfoStateKey(),
			RelatesTo: event.RelatesTo{
				Type:    event.RelReference,
				EventID: evt.ID,
			},
			Status: event.MessageStatusFail,
			Reason: event.MessageStatusUnsupported,
			Error:  err.Error(),
		}

		errorIntent := portal.bridge.Bot
		if !portal.Encrypted {
			errorIntent = portal.MainIntent()
		}
		_, sendErr := errorIntent.SendMessageEvent(portal.MXID, event.BeeperMessageStatus, &content)
		if sendErr != nil {
			portal.log.Warnln("Failed to send message send status event:", sendErr)
		}
	}
}

func (portal *Portal) HandleMatrixReadReceipt(user bridge.User, eventID id.EventID, receipt event.ReadReceipt) {
	if user.GetMXID() != portal.user.MXID {
		return
	}
	outgoingHandle := portal.OutgoingHandle
	if outgoingHandle.IsEmpty() {
		outgoingHandle = portal.user.IM.User.DefaultHandle
	}

	sendReceiptsTo := portal.Participants
	if !portal.IsPrivateChat() || portal.user.HideReadReceipts {
		// For group chats, only send read receipts to our devices so that they
		// know that we have read the message.
		sendReceiptsTo = []uri.ParsedURI{outgoingHandle}
	}

	if message, err := portal.bridge.DB.Message.GetByMXID(context.TODO(), eventID); err != nil {
		portal.zlog.Warn().Err(err).Msg("Error getting message by MXID")
	} else if message != nil {
		if slices.Contains(portal.user.IM.User.Handles, message.SenderURI) {
			portal.zlog.Info().Msg("Not sending read receipt for own message")
			return
		}

		portal.zlog.Debug().
			Str("message_id", message.ID.String()).
			Str("message_mxid", message.MXID.String()).
			Msg("Marking message as read")
		err := portal.user.IM.SendReadReceipt(context.TODO(), outgoingHandle, sendReceiptsTo, message.ID, portal.Service)
		if err != nil {
			portal.zlog.Warn().Err(err).Msg("Error marking message as read")
		}
	} else if tapback, err := portal.bridge.DB.Tapback.GetByMXID(context.TODO(), eventID); err != nil {
		portal.zlog.Warn().Err(err).Msg("Error getting tapback by MXID")
	} else if tapback != nil {
		if slices.Contains(portal.user.IM.User.Handles, tapback.Sender) {
			portal.zlog.Info().Msg("Not sending read receipt for own message")
			return
		}

		portal.zlog.Debug().
			Str("tapback_id", tapback.ID.String()).
			Str("tapback_mxid", tapback.MXID.String()).
			Msg("Marking tapback as read")
		err := portal.user.IM.SendReadReceipt(context.TODO(), outgoingHandle, sendReceiptsTo, tapback.ID, portal.Service)
		if err != nil {
			portal.zlog.Warn().Err(err).Msg("Error marking message as read")
		}
	}
}

func (portal *Portal) HandleMatrixTyping(userIDs []id.UserID) {
	if portal.Service == imessage.ServiceSMS {
		return
	}

	if !portal.IsPrivateChat() {
		portal.zlog.Info().Msg("Not sending typing update for group chat")
		return
	}

	portal.typingLock.Lock()
	defer portal.typingLock.Unlock()

	isTyping := false
	for _, userID := range userIDs {
		if userID == portal.user.MXID {
			isTyping = true
			break
		}
	}
	if isTyping != portal.userIsTyping {
		outgoingHandle := portal.OutgoingHandle
		if outgoingHandle.IsEmpty() {
			outgoingHandle = portal.user.IM.User.DefaultHandle
		}

		log := portal.zlog.With().Bool("typing", isTyping).Logger()
		ctx := log.WithContext(context.TODO())
		log.Debug().Msg("Sending typing update")

		portal.userIsTyping = isTyping
		_, err := portal.user.IM.SendTypingNotification(ctx, outgoingHandle, portal.Participants, portal.GroupID, isTyping)
		if err != nil {
			log.Warn().Err(err).Msg("Failed to bridge typing status change")
		} else {
			log.Debug().Msg("Typing update sent")
		}
	}
}

func (portal *Portal) HandleMatrixReaction(evt *event.Event) {
	log := portal.zlog.With().
		Str("action", "handle matrix reaction").
		Str("event_id", evt.ID.String()).
		Str("sender", evt.Sender.String()).
		Logger()
	log.Debug().Msg("Starting handling of Matrix reaction")

	if err := portal.shouldHandleMessage(evt); err != nil {
		log.Debug().Err(err).Msg("Not handling reaction")
		portal.sendErrorMessage(evt, err, "", true, status.MsgStatusTimeout)
		return
	}

	doError := func(msg string, err error) {
		log.Error().Err(err).Msg(msg)
		var checkpointErr error
		if err != nil {
			checkpointErr = fmt.Errorf("%s: %w", msg, err)
		} else {
			checkpointErr = errors.New(msg)
		}
		portal.sendErrorMessage(evt, checkpointErr, msg, true, status.MsgStatusPermFailure)
	}

	outgoingHandle := portal.OutgoingHandle
	if outgoingHandle.IsEmpty() {
		outgoingHandle = portal.user.IM.User.DefaultHandle
	}

	reaction, ok := evt.Content.Parsed.(*event.ReactionEventContent)
	if !ok || reaction.RelatesTo.Type != event.RelAnnotation {
		doError("Ignoring reaction due to unknown m.relates_to data", nil)
		return
	}
	log = log.With().Str("target_mxid", reaction.RelatesTo.EventID.String()).Logger()
	ctx := log.WithContext(context.TODO())
	if portal.Service != imessage.ServiceIMessage {
		doError("Reactions to SMS messages are not yet supported", nil)
	} else if tapbackType := imessage.TapbackFromEmoji(reaction.RelatesTo.Key); tapbackType == 0 {
		doError("Unknown reaction type", nil)
	} else if target, err := portal.bridge.DB.Message.GetByMXID(ctx, reaction.RelatesTo.EventID); err != nil {
		doError("Failed to get target message from database", err)
	} else if target == nil {
		doError("Unknown reaction target", nil)
	} else if existing, err := portal.bridge.DB.Tapback.GetByID(ctx, portal.Key, target.ID, target.Part, outgoingHandle); err != nil {
		doError("Failed to get existing reaction from database", err)
	} else if existing != nil && existing.Type == tapbackType {
		doError("Ignoring outgoing tapback: type is same", nil)
	} else {
		origContent := msgconv.GetReactionTargetContent(ctx, evt.Content.VeryRaw)
		converted := portal.MsgConv.BuildTapback(ctx, target.ID, target.PartInfo(), tapbackType, false, origContent)
		newTapbackUUID := uuid.New()
		var oldMXID id.EventID
		if existing == nil {
			// TODO should timestamp be stored?
			tapback := portal.bridge.DB.Tapback.New()
			tapback.Portal = portal.Key
			tapback.ID = newTapbackUUID
			tapback.Sender = outgoingHandle
			tapback.MessageID = target.ID
			tapback.MessagePart = target.Part
			tapback.Type = tapbackType
			tapback.MXID = evt.ID
			// TODO don't ignore error
			tapback.Insert(ctx)
		} else {
			oldMXID = existing.MXID
			existing.ID = newTapbackUUID
			existing.Type = tapbackType
			existing.MXID = evt.ID
			// TODO don't ignore error
			existing.Update(ctx)
		}
		if resp, err := portal.user.IM.SendMessage(ctx, outgoingHandle, converted, newTapbackUUID); err != nil {
			log.Err(err).Msg("Failed to send tapback")
			portal.sendErrorMessage(evt, err, "", true, status.MsgStatusPermFailure)
		} else {
			log.Debug().Str("message_uuid", resp.ID.String()).Msg("Handled Matrix reaction")
			portal.sendSuccessCheckpoint(evt, newTapbackUUID)
			if oldMXID != "" {
				_, err = portal.MainIntent().RedactEvent(portal.MXID, oldMXID)
				if err != nil {
					log.Warn().Err(err).
						Str("existing_reaction_mxid", oldMXID.String()).
						Msg("Failed to redact old tapback")
				}
			}
		}
	}
}

func (portal *Portal) HandleMatrixRedaction(evt *event.Event) {
	log := portal.zlog.With().
		Str("redaction_event_id", evt.ID.String()).
		Str("redacts", evt.Redacts.String()).
		Logger()
	ctx := log.WithContext(context.TODO())
	log.Debug().Msg("Starting handling of Matrix redaction")

	if err := portal.shouldHandleMessage(evt); err != nil {
		log.Debug().Err(err).Msg("Ignoring redaction")
		portal.sendErrorMessage(evt, err, "", true, status.MsgStatusTimeout)
		return
	}

	outgoingHandle := portal.OutgoingHandle
	if outgoingHandle.IsEmpty() {
		outgoingHandle = portal.user.IM.User.DefaultHandle
	}

	redactedTapback, err := portal.bridge.DB.Tapback.GetByMXID(ctx, evt.Redacts)
	if err != nil {
		log.Warn().Err(err).Msg("Failed to get tapback by MXID")
	} else if redactedTapback != nil {
		targetMsg, err := portal.bridge.DB.Message.GetByID(ctx, portal.Key, redactedTapback.MessageID, redactedTapback.MessagePart)
		// TODO don't ignore fetch error
		log := log.With().
			Str("redacted_tapback_id", redactedTapback.ID.String()).
			Int("redacted_tapback_type", int(redactedTapback.Type)).
			Str("redacted_message_id", redactedTapback.MessageID.String()).
			Int("redacted_message_part", redactedTapback.MessagePart).
			Logger()
		ctx = log.WithContext(ctx)
		log.Debug().Msg("Redacting tapback")

		// TODO don't ignore errors
		redactedTapback.Delete(ctx)
		converted := portal.MsgConv.BuildTapback(ctx, targetMsg.ID, targetMsg.PartInfo(), redactedTapback.Type, true, nil)

		redactionUUID := uuid.New()
		_, err = portal.user.IM.SendMessage(ctx, outgoingHandle, converted, redactionUUID)
		if err != nil {
			log.Err(err).Msg("Failed to send tapback removal")
			portal.bridge.SendMessageErrorCheckpoint(evt, status.MsgStepRemote, err, true, 0)
		} else {
			log.Debug().Msg("Handled Matrix redaction of iMessage tapback")
			portal.sendSuccessCheckpoint(evt, redactionUUID)
		}
		return
	}

	redactedMessage, err := portal.bridge.DB.Message.GetByMXID(ctx, evt.Redacts)
	if err != nil {
		log.Warn().Err(err).Msg("Failed to get message by MXID")
	} else if redactedMessage != nil {
		if time.Since(redactedMessage.Time()) > MaxUnsendTime {
			portal.sendErrorMessage(evt, fmt.Errorf("can't unsend messages older than 2 minutes"), "", true, status.MsgStatusPermFailure)
			return
		}
		log := log.With().
			Str("redacted_message_id", redactedMessage.ID.String()).
			Int("redacted_message_part", redactedMessage.Part).
			Logger()

		_, err := portal.user.IM.SendUnsend(ctx, outgoingHandle, portal.Participants, portal.GroupID, redactedMessage.ID, redactedMessage.Part)
		if err != nil {
			log.Err(err).Msg("Failed to send message removal")
			portal.bridge.SendMessageErrorCheckpoint(evt, status.MsgStepRemote, err, true, 0)
		} else {
			log.Debug().Msg("Handled Matrix redaction of iMessage")
			// TODO add uuid parameter to SendUnsend
			portal.sendSuccessCheckpoint(evt, uuid.Nil)
		}
		return
	}

	portal.sendUnsupportedCheckpoint(evt, status.MsgStepRemote, fmt.Errorf("couldn't find message or tapback to redact"))
}

func (portal *Portal) HandleMatrixRoomName(evt *event.Event) {
	roomName := evt.Content.AsRoomName().Name
	log := portal.zlog.With().Str("new_room_name", roomName).Logger()
	ctx := log.WithContext(context.TODO())

	_, err := portal.user.IM.UpdateChatName(ctx, portal.OutgoingHandle, portal.Participants, portal.GroupID, roomName)
	if err != nil {
		portal.sendErrorMessage(evt, err, "", true, status.MsgStatusPermFailure)
		return
	}
	portal.Name = roomName
	portal.NameSet = true
	if err := portal.Update(ctx); err != nil {
		log.Err(err).Msg("Failed to update portal")
	} else {
		log.Debug().Msg("Successfully updated room name")
	}
}

func (portal *Portal) HandleMatrixRoomAvatar(evt *event.Event) {
	url := evt.Content.AsRoomAvatar().URL
	log := portal.zlog.With().Str("new_room_avatar", url.String()).Logger()
	ctx := log.WithContext(context.TODO())

	var data []byte
	var err error
	if !url.IsEmpty() {
		data, err = portal.MainIntent().DownloadBytesContext(ctx, url)
		if err != nil {
			log.Err(err).Msg("Failed to download avatar")
			return
		}
	}

	portal.PropertiesVersion++
	avatarGUID, err := portal.user.IM.UpdateChatAvatar(ctx, portal.OutgoingHandle, portal.Participants, portal.GroupID, portal.Name, portal.PropertiesVersion, data)
	if err != nil {
		portal.sendErrorMessage(evt, err, "", true, status.MsgStatusPermFailure)
		return
	}
	portal.AvatarGUID = &avatarGUID
	portal.AvatarURL = url.CUString()
	hash := sha256.Sum256(data)
	portal.AvatarHash = &hash
	portal.AvatarSet = true
	if err := portal.Update(ctx); err != nil {
		log.Err(err).Msg("Failed to update portal")
	} else {
		log.Debug().Msg("Successfully updated room avatar")
	}
}

func (portal *Portal) UpdateAvatar(data []byte, intent *appservice.IntentAPI) bool {
	log := portal.zlog.With().Str("action", "update avatar").Logger()
	hash := sha256.Sum256(data)
	if portal.AvatarSet && portal.AvatarHash != nil && hash == *portal.AvatarHash {
		log.Debug().Msg("not updating avatar: hash matches current avatar")
		return false
	}
	portal.AvatarHash = &hash
	uploadResp, err := intent.UploadBytes(data, mimetype.Detect(data).String())
	if err != nil {
		portal.AvatarHash = nil
		portal.AvatarSet = false
		log.Err(err).Msg("failed to upload avatar attachment")
		return false
	}
	portal.AvatarURL = uploadResp.ContentURI.CUString()
	log = log.With().Str("avatar_url", string(portal.AvatarURL)).Logger()
	if len(portal.MXID) > 0 {
		parsedAvatarURL, err := portal.AvatarURL.Parse()
		if err != nil {
			portal.AvatarHash = nil
			portal.AvatarSet = false
			log.Err(err).Msg("failed to parse room avatar URL")
			return false
		}
		resp, err := intent.SetRoomAvatar(portal.MXID, parsedAvatarURL)
		if errors.Is(err, mautrix.MForbidden) && intent != portal.MainIntent() {
			resp, err = portal.MainIntent().SetRoomAvatar(portal.MXID, parsedAvatarURL)
		}
		if err != nil {
			portal.AvatarHash = nil
			portal.AvatarSet = false
			log.Err(err).Msg("failed to set room avatar")
			return false
		}
		log = log.With().Str("event_id", resp.EventID.String()).Logger()
	}
	portal.UpdateBridgeInfo()
	if err = portal.Update(context.TODO()); err != nil {
		log.Err(err).Msg("failed to update portal")
		return false
	} else {
		log.Debug().Msg("Successfully updated room avatar")
		return true
	}
}

func (portal *Portal) RemoveAvatar(intent *appservice.IntentAPI) *id.EventID {
	portal.AvatarHash = nil

	if len(portal.MXID) == 0 {
		return nil
	}

	resp, err := intent.SendStateEvent(portal.MXID, event.StateRoomAvatar, "", nil)
	if err != nil {
		portal.zlog.Err(err).Msg("Failed to remove avatar")
		return nil
	}

	portal.Update(context.TODO())
	portal.UpdateBridgeInfo()
	return &resp.EventID
}

func (portal *Portal) setMembership(inviter *appservice.IntentAPI, puppet *Puppet, membership event.Membership, ts int64) *id.EventID {
	err := inviter.EnsureInvited(portal.MXID, puppet.MXID)
	if err != nil {
		if errors.Is(err, mautrix.MForbidden) {
			err = portal.MainIntent().EnsureInvited(portal.MXID, puppet.MXID)
		}
		if err != nil {
			portal.log.Warnfln("Failed to ensure %s is invited to %s: %v", puppet.MXID, portal.MXID, err)
		}
	}
	resp, err := puppet.Intent.SendMassagedStateEvent(portal.MXID, event.StateMember, puppet.MXID.String(), &event.MemberEventContent{
		Membership:  membership,
		AvatarURL:   puppet.AvatarURL.CUString(),
		Displayname: puppet.Displayname,
	}, ts)
	if err != nil {
		puppet.log.Warnfln("Failed to set membership to %s in %s: %v", membership, portal.MXID, err)
		if membership == event.MembershipJoin {
			_ = puppet.Intent.EnsureJoined(portal.MXID, appservice.EnsureJoinedParams{IgnoreCache: true})
		} else if membership == event.MembershipLeave {
			_, _ = portal.MainIntent().KickUser(portal.MXID, &mautrix.ReqKickUser{UserID: puppet.MXID})
		}
		return nil
	} else {
		portal.bridge.AS.StateStore.SetMembership(portal.MXID, puppet.MXID, "join")
		return &resp.EventID
	}
}

func (portal *Portal) handleIMMemberChange(msg *imessage.Message, dbMessage *database.Message, intent *appservice.IntentAPI) *id.EventID {
	// FIXME
	//if len(msg.Target.LocalID) == 0 {
	//	portal.log.Debugfln("Ignoring member change item with empty target")
	//	return nil
	//}
	//puppet := portal.bridge.GetPuppetByLocalID(msg.Target.LocalID)
	//puppet.Sync()
	//if msg.GroupActionType == imessage.GroupActionAddUser {
	//	return portal.setMembership(intent, puppet, event.MembershipJoin, dbMessage.Timestamp)
	//} else if msg.GroupActionType == imessage.GroupActionRemoveUser {
	//	return portal.setMembership(intent, puppet, event.MembershipLeave, dbMessage.Timestamp)
	//} else {
	//	portal.log.Warnfln("Unexpected group action type %d in member change item", msg.GroupActionType)
	//}
	return nil
}

func (portal *Portal) GetIM() *direct.Connector {
	return portal.user.IM
}

func (portal *Portal) GetData(ctx context.Context) *database.Portal {
	return portal.Portal
}

func (portal *Portal) GetMatrixReply(ctx context.Context, msg *imessage.Message) (threadRoot, replyFallback id.EventID) {
	if msg.ThreadRoot == nil {
		return "", ""
	}
	log := zerolog.Ctx(ctx).With().
		Str("reply_to_guid", msg.ThreadRoot.ID.String()).
		Int("reply_to_part", msg.ThreadRoot.PartID).
		Logger()
	message, err := portal.bridge.DB.Message.GetByID(ctx, portal.Key, msg.ThreadRoot.ID, msg.ThreadRoot.PartID)
	if err != nil {
		log.Err(err).Msg("Failed to get thread root from database")
	} else if message == nil {
		log.Debug().Msg("Thread root message not found")
	} else {
		threadRoot = message.MXID
		replyFallbackMsg, err := portal.bridge.DB.Message.GetLastMessageInThread(ctx, portal.Key, msg.ThreadRoot.ID, msg.ThreadRoot.PartID)
		if err != nil {
			log.Warn().Err(err).Msg("Failed to get last message in thread from database")
		} else if replyFallbackMsg != nil {
			replyFallback = replyFallbackMsg.MXID
		} else {
			replyFallback = threadRoot
		}
	}
	return
}

func (portal *Portal) handleNormaliMessage(ctx context.Context, msg *imessage.Message, dbMessage *database.Message, intent *appservice.IntentAPI) {
	log := zerolog.Ctx(ctx)
	parts := portal.MsgConv.ToMatrix(context.WithValue(ctx, intentKey, intent), msg)
	if len(parts) == 0 {
		log.Warn().Msg("Message doesn't contain any attachments nor text")
	}
	for _, converted := range parts {
		log := log.With().Int("part_id", converted.PartInfo.PartID).Logger()
		log.Debug().Msg("Sending message part")
		resp, err := portal.sendMessage(intent, converted.Type, converted.Content, converted.Extra, dbMessage.Timestamp)
		if err != nil {
			log.Err(err).Msg("Failed to send message part")
		} else {
			log.Debug().Str("event_id", resp.EventID.String()).Msg("Handled message part")
			dbMessage.MXID = resp.EventID
			dbMessage.Part = converted.PartInfo.PartID
			dbMessage.StartIndex = converted.PartInfo.StartIndex
			dbMessage.Length = converted.PartInfo.Length
			if msg.ThreadRoot != nil {
				dbMessage.ReplyToID = msg.ThreadRoot.ID
				dbMessage.ReplyToPart = msg.ThreadRoot.PartID
			}
			err = dbMessage.Insert(context.TODO())
			if err != nil {
				log.Err(err).Msg("Failed to save message part to database")
			}
			dbMessage.Part++
		}
	}
}

func (portal *Portal) getIntentForMessage(ctx context.Context, msg imessage.IMessageWithSender) *appservice.IntentAPI {
	if msg.GetIsFromMe() {
		intent := portal.user.DoublePuppetIntent
		if intent == nil {
			zerolog.Ctx(ctx).Debug().Msg("Dropping own message as double puppeting is not initialized")
			return nil
		}
		return intent
	} else if len(msg.GetSender().Identifier) > 0 {
		puppet := portal.user.GetPuppetByURI(msg.GetSender())
		if len(puppet.Displayname) == 0 {
			zerolog.Ctx(ctx).Debug().
				Str("puppet_uri", puppet.URI.String()).
				Msg("Displayname is empty, syncing before handling message")
			puppet.Sync()
		}
		return puppet.Intent
	}
	return portal.MainIntent()
}

func (portal *Portal) HandleiMessage(msg *imessage.Message) id.EventID {
	log := portal.zlog.With().
		Str("action", "handle iMessage").
		Str("message_id", msg.ID.String()).
		Str("sender_uri", msg.Sender.String()).
		Logger()
	ctx := log.WithContext(context.TODO())
	var dbMessage *database.Message
	defer func() {
		if err := recover(); err != nil {
			log.Error().
				Bytes(zerolog.ErrorStackFieldName, debug.Stack()).
				Interface(zerolog.ErrorFieldName, err).
				Msg("Panic while handling message")
		}
	}()

	if msg.Tapback != nil {
		portal.HandleiMessageTapback(ctx, msg)
		return ""
	} else if existingMsg, err := portal.bridge.DB.Message.GetLastPartByID(ctx, portal.Key, msg.ID); err != nil {
		log.Err(err).Msg("Failed to check if message is duplicate")
	} else if existingMsg != nil {
		log.Debug().Msg("Ignoring duplicate message")
		return ""
	}

	log.Debug().
		Int("attachment_count", len(msg.Attachments)).
		Int("text_length", len(msg.Text)).
		Msg("Starting handling of normal iMessage")
	dbMessage = portal.bridge.DB.Message.New()
	dbMessage.Portal = portal.Key
	dbMessage.RoomID = portal.MXID
	//dbMessage.ReceivingHandle = msg.ChatGUID
	dbMessage.SenderURI = msg.Sender
	dbMessage.ID = msg.ID
	dbMessage.Timestamp = msg.Time.UnixMilli()

	intent := portal.getIntentForMessage(ctx, msg)
	if intent == nil {
		log.Debug().Msg("Handling of message was cancelled (didn't get an intent)")
		return dbMessage.MXID
	}
	portal.handleNormaliMessage(ctx, msg, dbMessage, intent)

	if len(dbMessage.MXID) > 0 {
		portal.sendDeliveryReceipt(dbMessage.MXID)
	} else {
		log.Debug().Msg("Unhandled message")
	}
	return dbMessage.MXID
}

func (portal *Portal) HandleiMessageGroupInfoChange(msg *imessage.GroupInfoChange) {
	log := portal.zlog.With().
		Str("action", "handle iMessage group info").
		Str("message_id", msg.ID.String()).
		Str("sender_uri", msg.Sender.String()).
		Logger()
	ctx := log.WithContext(context.TODO())

	if msg.PropertiesVersion > 0 && msg.PropertiesVersion > portal.PropertiesVersion {
		log.Debug().Int("version", msg.PropertiesVersion).Msg("Properties version changed")
		portal.PropertiesVersion = msg.PropertiesVersion
		if err := portal.Update(ctx); err != nil {
			log.Err(err).Msg("failed to update portal with new properties version")
			return
		}
	}

	intent := portal.getIntentForMessage(ctx, msg)
	if intent == nil {
		log.Debug().Msg("Handling of iMessage was cancelled (didn't get an intent)")
		return
	}

	if msg.NewParticipants != nil && !slices.Equal(portal.Participants, msg.NewParticipants) {
		log.Debug().
			Any("old_participants_portal", portal.Participants).
			Any("old_participants_msg", msg.OldParticipants).
			Any("new_participants", msg.NewParticipants).
			Msg("Participant list for portal changed in group meta message")
		portal.Participants = msg.NewParticipants
		portal.SyncParticipants(portal.Participants)
	}
	if msg.NewName != "" || msg.OldName != "" {
		if portal.UpdateName(msg.NewName, intent) {
			if err := portal.Update(ctx); err != nil {
				log.Warn().Err(err).Msg("failed to update portal with new group name")
			}
		}
	}
	if msg.AvatarFileTransferGUID != nil && msg.AvatarFileTransferGUID != portal.AvatarGUID {
		portal.AvatarGUID = msg.AvatarFileTransferGUID
		log.Debug().Msg("Updating avatar")
		avatarBytes, err := msg.NewAvatar.DownloadMemory(ctx, portal.user.IM.User)
		if err != nil {
			log.Warn().Err(err).Msg("failed to download avatar")
		} else {
			portal.UpdateAvatar(avatarBytes, intent)
		}
	} else if msg.RemoveAvatar {
		log.Debug().Msg("Removing avatar")
		portal.RemoveAvatar(intent)
	}
}

func (portal *Portal) HandleiMessageEdit(msgEdit *imessage.MessageEdit) {
	log := portal.zlog.With().
		Str("message_id", msgEdit.EditMessageID.String()).
		Str("sender_uri", msgEdit.Sender.String()).
		Str("action", "handle iMessage edit").
		Logger()
	ctx := log.WithContext(context.TODO())

	target, err := portal.bridge.DB.Message.GetByID(ctx, portal.Key, msgEdit.EditMessageID, msgEdit.EditPartIndex)
	if err != nil {
		log.Err(err).Msg("Failed to get edit target message")
		return
	} else if target == nil {
		log.Warn().Msg("Unknown edit target message")
		return
	}

	content := &event.MessageEventContent{
		MsgType: event.MsgText,
		Body:    msgEdit.Text,
	}
	content.SetEdit(target.MXID)

	intent := portal.getIntentForMessage(ctx, msgEdit)
	if intent == nil {
		return
	}

	_, err = portal.sendMessage(intent, event.EventMessage, content, nil, time.Now().UnixMilli())
	if err != nil {
		log.Err(err).Msg("Failed to send edit")
		return
	}
}

func (portal *Portal) HandleiMessageUnsend(msgUnsend *imessage.MessageUnsend) {
	log := portal.zlog.With().
		Str("unsend_message_id", msgUnsend.UnsendMessageID.String()).
		Str("sender_uri", msgUnsend.Sender.String()).
		Str("action", "handle iMessage unsend").
		Logger()
	ctx := log.WithContext(context.TODO())

	target, err := portal.bridge.DB.Message.GetByID(ctx, portal.Key, msgUnsend.UnsendMessageID, msgUnsend.UnsendPartIndex)
	if err != nil {
		log.Warn().Err(err).Msg("Failed to get unsend target message")
		return
	} else if target == nil {
		log.Warn().Msg("Unknown unsend target message")
		return
	}

	intent := portal.getIntentForMessage(ctx, msgUnsend)
	if intent == nil {
		return
	}

	_, err = intent.RedactEvent(portal.MXID, target.MXID)
	if err != nil {
		log.Err(err).Msg("Failed to send unsend")
	}
}

func (portal *Portal) HandleiMessageTapback(ctx context.Context, msg *imessage.Message) {
	log := zerolog.Ctx(ctx).With().
		Str("target_guid", msg.Tapback.TargetGUID.String()).
		Int("target_part", msg.Tapback.TargetPart).
		Logger()
	ctx = log.WithContext(ctx)
	log.Debug().Msg("Starting handling of iMessage tapback")
	target, err := portal.bridge.DB.Message.GetByID(ctx, portal.Key, msg.Tapback.TargetGUID, msg.Tapback.TargetPart)
	if err != nil {
		log.Err(err).Msg("Failed to get tapback target")
		return
	} else if target == nil {
		log.Debug().Msg("Unknown tapback target")
		return
	}
	intent := portal.getIntentForMessage(ctx, msg)
	if intent == nil {
		return
	}

	existing, err := portal.bridge.DB.Tapback.GetByID(ctx, portal.Key, target.ID, target.Part, msg.Sender)
	if err != nil {
		log.Err(err).Msg("Failed to get existing tapback")
	}
	if msg.Tapback.Remove {
		if existing == nil {
			return
		}
		_, err = intent.RedactEvent(portal.MXID, existing.MXID)
		if err != nil {
			log.Err(err).Msg("Failed to redact reaction")
		}
		err = existing.Delete(ctx)
		if err != nil {
			log.Err(err).Msg("Failed to delete tapback from database")
		}
		return
	} else if existing != nil && existing.Type == msg.Tapback.Type {
		log.Debug().Msg("Ignoring tapback of same type as existing reaction")
		return
	}

	content := &event.ReactionEventContent{
		RelatesTo: event.RelatesTo{
			EventID: target.MXID,
			Type:    event.RelAnnotation,
			Key:     msg.Tapback.Type.Emoji(),
		},
	}

	if existing != nil {
		if _, err = intent.RedactEvent(portal.MXID, existing.MXID); err != nil {
			log.Debug().Msg("Failed to redact old reaction")
		}
	}

	resp, err := intent.SendMassagedMessageEvent(portal.MXID, event.EventReaction, &content, msg.Time.UnixMilli())
	if err != nil {
		log.Err(err).Msg("Failed to send reaction")
		return
	}

	if existing == nil {
		tapback := portal.bridge.DB.Tapback.New()
		tapback.Portal = portal.Key
		tapback.MessageID = target.ID
		tapback.MessagePart = target.Part
		tapback.Sender = msg.Sender
		tapback.ID = msg.ID
		tapback.Type = msg.Tapback.Type
		tapback.MXID = resp.EventID
		if err = tapback.Insert(ctx); err != nil {
			log.Err(err).Msg("Failed to insert tapback to database")
		}
	} else {
		existing.ID = msg.ID
		existing.Type = msg.Tapback.Type
		existing.MXID = resp.EventID
		if err = existing.Update(ctx); err != nil {
			log.Err(err).Msg("Failed to update tapback in database")
		}
	}
}

func (portal *Portal) Delete() {
	portal.bridge.portalsLock.Lock()
	portal.unlockedDelete()
	portal.bridge.portalsLock.Unlock()
}

func (portal *Portal) unlockedDelete() {
	// TODO don't ignore errors
	portal.Portal.Delete(context.TODO())
	delete(portal.bridge.portalsByKey, portal.Key)
	if len(portal.MXID) > 0 {
		delete(portal.bridge.portalsByMXID, portal.MXID)
	}
}

func (portal *Portal) GetMatrixUsers() ([]id.UserID, error) {
	members, err := portal.MainIntent().JoinedMembers(portal.MXID)
	if err != nil {
		return nil, fmt.Errorf("failed to get member list: %w", err)
	}
	var users []id.UserID
	for userID := range members.Joined {
		if !portal.bridge.IsGhost(userID) && userID != portal.bridge.Bot.UserID {
			users = append(users, userID)
		}
	}
	return users, nil
}

func (portal *Portal) CleanupIfEmpty(deleteIfForbidden bool) bool {
	if len(portal.MXID) == 0 {
		return false
	}

	users, err := portal.GetMatrixUsers()
	if err != nil {
		if deleteIfForbidden && errors.Is(err, mautrix.MForbidden) {
			portal.log.Errorfln("Got %v while checking if portal is empty, assuming it's gone", err)
			portal.Delete()
			return true
		} else {
			portal.log.Errorfln("Failed to get Matrix user list to determine if portal needs to be cleaned up: %v", err)
		}
		return false
	}

	if len(users) == 0 {
		portal.log.Infoln("Room seems to be empty, cleaning up...")
		portal.Delete()
		portal.Cleanup(false)
		return true
	}
	return false
}

func (portal *Portal) Cleanup(puppetsOnly bool) {
	if len(portal.MXID) == 0 {
		return
	}
	intent := portal.MainIntent()
	if portal.bridge.SpecVersions.UnstableFeatures["com.beeper.room_yeeting"] {
		err := intent.BeeperDeleteRoom(portal.MXID)
		if err != nil && !errors.Is(err, mautrix.MNotFound) {
			portal.zlog.Err(err).Msg("Failed to delete room using hungryserv yeet endpoint")
		}
		return
	}
	if portal.IsPrivateChat() {
		_, err := intent.LeaveRoom(portal.MXID)
		if err != nil {
			portal.log.Warnln("Failed to leave private chat portal with main intent:", err)
		}
		return
	}
	members, err := intent.JoinedMembers(portal.MXID)
	if err != nil {
		portal.log.Errorln("Failed to get portal members for cleanup:", err)
		return
	}
	if _, isJoined := members.Joined[portal.user.MXID]; !puppetsOnly && !isJoined {
		// Kick the user even if they're not joined in case they're invited.
		_, _ = intent.KickUser(portal.MXID, &mautrix.ReqKickUser{UserID: portal.user.MXID, Reason: "Deleting portal"})
	}
	for member := range members.Joined {
		if member == intent.UserID {
			continue
		}
		puppet := portal.bridge.GetPuppetByMXID(member)
		if puppet != nil {
			_, err = puppet.Intent.LeaveRoom(portal.MXID)
			if err != nil {
				portal.log.Errorln("Error leaving as puppet while cleaning up portal:", err)
			}
		} else if !puppetsOnly {
			_, err = intent.KickUser(portal.MXID, &mautrix.ReqKickUser{UserID: member, Reason: "Deleting portal"})
			if err != nil {
				portal.log.Errorln("Error kicking user while cleaning up portal:", err)
			}
		}
	}
	_, err = intent.LeaveRoom(portal.MXID)
	if err != nil {
		portal.log.Errorln("Error leaving with main intent while cleaning up portal:", err)
	}
}
