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
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"time"

	"github.com/gabriel-vasile/mimetype"
	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"go.mau.fi/util/exslices"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"

	"github.com/beeper/imessage/analytics"
	"github.com/beeper/imessage/database"
	"github.com/beeper/imessage/imessage"
	"github.com/beeper/imessage/imessage/direct"
	"github.com/beeper/imessage/imessage/direct/util/uri"
	"github.com/beeper/imessage/msgconv"
)

func messageToMXID(msgID uuid.UUID, partInfo imessage.MessagePartInfo) id.EventID {
	return id.EventID(fmt.Sprintf("$%s.%d.%d.%d:imessage.apple.com", msgID.String(), partInfo.PartID, partInfo.StartIndex, partInfo.Length))
}

func tapbackToMXID(msgID uuid.UUID, partInfo imessage.MessagePartInfo, sender uri.ParsedURI) id.EventID {
	return id.EventID(fmt.Sprintf("$tapback_%s.%d.%d.%d_%s:imessage.apple.com", msgID.String(), partInfo.PartID, partInfo.StartIndex, partInfo.Length, sender.Identifier))
}

func unsendToMXID(msgID uuid.UUID, partID int, unsendID uuid.UUID) id.EventID {
	return id.EventID(fmt.Sprintf("$unsend_%s.%d_%s:imessage.apple.com", msgID, partID, unsendID))
}

func editToMXID(msgID uuid.UUID, partID int, editID uuid.UUID) id.EventID {
	return id.EventID(fmt.Sprintf("$edit_%s.%d_%s:imessage.apple.com", msgID, partID, editID))
}

var messageIDRegex = regexp.MustCompile(`^\$([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})\.(-?\d+)\.(\d+)\.(\d+):imessage\.apple\.com$`)
var tapbackIDRegex = regexp.MustCompile(`^\$tapback_([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})\.(-?\d+)\.(\d+)\.(\d+)_(.+?):imessage\.apple\.com$`)

func mxidToMessageID(mxid id.EventID) (id uuid.UUID, part imessage.MessagePartInfo, err error) {
	submatch := messageIDRegex.FindStringSubmatch(string(mxid))
	if len(submatch) != 5 {
		err = fmt.Errorf("invalid message ID")
		return
	}
	return uuid.MustParse(submatch[1]), imessage.MessagePartInfo{
		PartID:     must(strconv.Atoi(submatch[2])),
		StartIndex: must(strconv.Atoi(submatch[3])),
		Length:     must(strconv.Atoi(submatch[4])),
	}, nil
}

func mxidToTapbackID(mxid id.EventID) (id uuid.UUID, part imessage.MessagePartInfo, senderIdentifier string, err error) {
	submatch := tapbackIDRegex.FindStringSubmatch(string(mxid))
	if len(submatch) != 6 {
		err = fmt.Errorf("invalid tapback ID")
		return
	}
	return uuid.MustParse(submatch[1]), imessage.MessagePartInfo{
		PartID:     must(strconv.Atoi(submatch[2])),
		StartIndex: must(strconv.Atoi(submatch[3])),
		Length:     must(strconv.Atoi(submatch[4])),
	}, submatch[5], nil
}

var emptyString = ""

func createPortal(ctx context.Context, msg *imessage.Message) *database.Portal {
	portal := global.DB.Portal.New()
	portal.Key = database.Key{
		URI:      msg.Chat,
		Receiver: global.DBUser.RowID,
	}
	portal.Service = imessage.ServiceIMessage
	portal.Participants = msg.Participants
	portal.OutgoingHandle = msg.Receiver
	portal.MXID = id.RoomID(portal.URI.String())
	portal.Name = msg.GroupName
	portal.GroupID = msg.GroupID
	zerolog.Ctx(ctx).Info().
		Int("participant_count", len(portal.Participants)).
		Bool("has_name", len(portal.Name) > 0).
		Str("group_id", portal.GroupID).
		Msg("Creating new portal row")

	sendUpdatedBridgeInfo(ctx, "", msg.Time, portal)
	if portal.Name != "" {
		portal.NameSet = true
		sendRoomName(ctx, "", msg.Time, portal)
	}
	if portal.AvatarURL != "" {
		portal.AvatarSet = true
		sendRoomAvatar(ctx, "", msg.Time, string(portal.AvatarURL), portal)
	}

	err := portal.Insert(ctx)
	if err != nil {
		maybeFatalLog(zerolog.Ctx(ctx), err).Msg("Failed to insert portal to database")
	}
	return portal
}

func prepareDBMessagesOutgoing(portal *database.Portal, converted *direct.IMessage, id *uuid.UUID) []*database.Message {
	var msgID uuid.UUID
	if id != nil {
		msgID = *id
	} else {
		msgID = uuid.New()
	}
	var messages []*database.Message
	for i := 0; i < converted.AttachmentCount; i++ {
		partInfo := imessage.MessagePartInfo{
			PartID:     i,
			StartIndex: i,
			Length:     1,
		}
		var replyTo *imessage.ParsedThreadRoot
		if converted.ThreadRoot != "" {
			// TODO don't ignore error
			replyToVal, err := imessage.ParseThreadRoot(converted.ThreadRoot)
			if err == nil {
				replyTo = &replyToVal
			}
		}
		messages = append(messages, prepareDBMessage(portal, msgID, partInfo, replyTo, portal.OutgoingHandle, time.Now()))
	}
	textLength := direct.TextLen(converted.Text) - converted.AttachmentCount
	partInfo := imessage.MessagePartInfo{
		PartID:     converted.AttachmentCount,
		StartIndex: converted.AttachmentCount,
		Length:     textLength,
	}
	var replyTo *imessage.ParsedThreadRoot
	if converted.ThreadRoot != "" {
		// TODO don't ignore error
		replyToVal, err := imessage.ParseThreadRoot(converted.ThreadRoot)
		if err == nil {
			replyTo = &replyToVal
		}
	}
	messages = append(messages, prepareDBMessage(portal, msgID, partInfo, replyTo, portal.OutgoingHandle, time.Now()))
	return messages
}

func prepareDBMessage(portal *database.Portal, msgID uuid.UUID, partInfo imessage.MessagePartInfo, replyTo *imessage.ParsedThreadRoot, senderURI uri.ParsedURI, ts time.Time) *database.Message {
	msg := global.DB.Message.New()
	msg.Portal = portal.Key
	msg.ID = msgID
	msg.Part = partInfo.PartID
	msg.StartIndex = partInfo.StartIndex
	msg.Length = partInfo.Length
	msg.MXID = messageToMXID(msgID, partInfo)
	msg.RoomID = portal.MXID
	msg.SenderURI = senderURI
	msg.Timestamp = ts.UnixMilli()
	msg.ReceivingHandle = portal.OutgoingHandle
	if replyTo != nil {
		msg.ReplyToID = replyTo.ID
		msg.ReplyToPart = replyTo.PartID
	}
	return msg
}

func getPortalByURI(ctx context.Context, uri uri.ParsedURI) *database.Portal {
	portal, err := global.DB.Portal.GetByURI(ctx, database.Key{
		URI:      uri,
		Receiver: global.DBUser.RowID,
	})
	if err != nil {
		maybeFatalLog(zerolog.Ctx(ctx), err).Msg("Failed to get portal from database")
		return nil
	}
	return portal
}

func getOrCreatePortal(ctx context.Context, msg *imessage.Message) *database.Portal {
	portal, err := global.DB.Portal.GetByURI(ctx, database.Key{
		URI:      msg.Chat,
		Receiver: global.DBUser.RowID,
	})
	if err != nil {
		maybeFatalLog(zerolog.Ctx(ctx), err).Msg("Failed to get portal from database")
		return nil
	} else if portal == nil {
		portal = createPortal(ctx, msg)
	}
	return portal
}

func sendEvent(ctx context.Context, evt *event.Event) {
	var err error
	req := ReqMessage{Event: evt}
	if global.Cfg.WaitForMessage {
		err = global.IPC.Request(ctx, CmdMessage, &req, nil)
	} else {
		err = global.IPC.Send(CmdMessage, &req)
	}
	if err != nil {
		maybeFatalLog(zerolog.Ctx(ctx), err).Msg("Failed to send event over IPC")
	}
}

func sendMultipartEvent(ctx context.Context, events []*event.Event) {
	var err error
	req := ReqMultipartMessage{Events: events}
	if global.Cfg.WaitForMessage {
		err = global.IPC.Request(ctx, CmdMultipartMessage, &req, nil)
	} else {
		err = global.IPC.Send(CmdMultipartMessage, &req)
	}
	if err != nil {
		maybeFatalLog(zerolog.Ctx(ctx), err).Msg("Failed to send event over IPC")
	}
}

func updatePortalInfo(ctx context.Context, portal *database.Portal, msg *imessage.Message) {
	log := zerolog.Ctx(ctx)
	// TODO deduplicate with main bridge imessage.go?
	changed := false
	if !slices.Equal(portal.Participants, msg.Participants) {
		log.Debug().
			Any("old_participants", portal.Participants).
			Any("new_participants", msg.Participants).
			Msg("Participant list for portal changed")
		sendMemberDiff(ctx, portal.URI, uri.EmptyURI, msg.Time, portal.Participants, msg.Participants)
		portal.Participants = msg.Participants
		changed = true
	}
	if portal.GroupID != msg.GroupID && msg.GroupID != "" {
		log.Debug().
			Str("old_group_id", portal.GroupID).
			Str("new_group_id", msg.GroupID).
			Msg("Group ID for portal changed")
		portal.GroupID = msg.GroupID
		changed = true
	}
	if portal.Service != msg.Service {
		log.Debug().
			Str("old_service", portal.Service.String()).
			Str("new_service", msg.Service.String()).
			Msg("Service for portal changed")
		portal.Service = msg.Service
		changed = true
	}
	if portal.OutgoingHandle != msg.Receiver {
		// TODO this may cause flipping if the user has multiple handles in the group
		//      -> only change outgoing handle if the previous outgoing handle isn't in the group?
		// Also applies to matrix side
		portal.OutgoingHandle = msg.Receiver
		changed = true
		log.Debug().
			Str("old_handle", portal.OutgoingHandle.String()).
			Str("new_handle", msg.Receiver.String()).
			Msg("Outgoing handle for portal changed")
	}
	if !portal.IsPrivateChat() && portal.Name == "" && msg.GroupName != "" {
		portal.Name = msg.GroupName
		sendRoomName(ctx, "", time.Now(), portal)
		log.Debug().Msg("Found name for portal that was previously missing name")
		changed = true
	}
	if changed {
		sendUpdatedBridgeInfo(ctx, "", time.Now(), portal)
		err := portal.Update(ctx)
		if err != nil {
			maybeFatalLog(log, err).Msg("Failed to update portal in database")
		}
	}
}

func sendUpdatedBridgeInfo(ctx context.Context, sender string, ts time.Time, portal *database.Portal) {
	sendEvent(ctx, &event.Event{
		StateKey:  &emptyString,
		Sender:    id.UserID(sender),
		Type:      event.StateBridge,
		Timestamp: ts.UnixMilli(),
		RoomID:    portal.MXID,
		Content: event.Content{
			Parsed: portal.GetBridgeInfo(),
		},
	})
}

func sendMemberEvent(ctx context.Context, chat, sender, target uri.ParsedURI, ts time.Time, membership event.Membership) {
	if sender.IsEmpty() {
		sender = target
	}
	sendEvent(ctx, &event.Event{
		StateKey:  target.StringPtr(),
		Sender:    id.UserID(sender.String()),
		Type:      event.StateMember,
		Timestamp: ts.UnixMilli(),
		RoomID:    id.RoomID(chat.String()),
		Content: event.Content{
			Parsed: &event.MemberEventContent{
				Membership: membership,
			},
		},
	})
}

func sendMemberDiff(ctx context.Context, chat, sender uri.ParsedURI, ts time.Time, old, new []uri.ParsedURI) {
	left, joined := exslices.SortedDiff(old, new, uri.Compare)
	for _, participant := range left {
		sendMemberEvent(ctx, chat, sender, participant, ts, event.MembershipLeave)
	}
	for _, participant := range joined {
		sendMemberEvent(ctx, chat, sender, participant, ts, event.MembershipJoin)
	}
}

func sendRoomName(ctx context.Context, sender string, ts time.Time, portal *database.Portal) {
	sendEvent(ctx, &event.Event{
		StateKey:  &emptyString,
		Sender:    id.UserID(sender),
		Type:      event.StateRoomName,
		Timestamp: ts.UnixMilli(),
		RoomID:    portal.MXID,
		Content: event.Content{
			Parsed: &event.RoomNameEventContent{
				Name: portal.Name,
			},
		},
	})
}

func sendRoomAvatar(ctx context.Context, sender string, ts time.Time, url string, portal *database.Portal) {
	sendEvent(ctx, &event.Event{
		StateKey:  &emptyString,
		Sender:    id.UserID(sender),
		Type:      event.StateRoomAvatar,
		Timestamp: ts.UnixMilli(),
		RoomID:    portal.MXID,
		Content: event.Content{
			Raw: map[string]any{
				"url": url,
			},
		},
	})
}

func handleMessage(msg *imessage.Message) {
	log := global.Log.With().
		Str("action", "handle message").
		Str("id", msg.ID.String()).
		Str("sender", msg.Sender.String()).
		Str("chat", msg.Chat.String()).
		Logger()
	ctx := log.WithContext(global.Ctx)
	portal := getOrCreatePortal(ctx, msg)
	if portal == nil {
		if ctx.Err() == nil {
			log.Fatal().Msg("getOrCreatePortal returned nil even though context isn't done")
		}
		return
	}
	updatePortalInfo(ctx, portal, msg)
	ctx = context.WithValue(ctx, contextKeyPortal, portal)
	if msg.Tapback != nil {
		tapbackEventID := tapbackToMXID(msg.Tapback.TargetGUID, msg.Tapback.PartInfo, msg.Sender)
		if msg.Tapback.Remove {
			sendEvent(ctx, &event.Event{
				Sender:    id.UserID(msg.Sender.String()),
				Type:      event.EventRedaction,
				Timestamp: msg.Time.UnixMilli(),
				RoomID:    portal.MXID,
				Redacts:   tapbackEventID,
				Content: event.Content{
					Parsed: &event.RedactionEventContent{
						Redacts: tapbackEventID,
					},
				},
			})
		} else {
			sendEvent(ctx, &event.Event{
				Sender:    id.UserID(msg.Sender.String()),
				Type:      event.EventReaction,
				Timestamp: msg.Time.UnixMilli(),
				ID:        tapbackEventID,
				RoomID:    portal.MXID,
				Content: event.Content{
					Parsed: &event.ReactionEventContent{
						RelatesTo: event.RelatesTo{
							Type:    event.RelAnnotation,
							EventID: messageToMXID(msg.Tapback.TargetGUID, msg.Tapback.PartInfo),
							Key:     msg.Tapback.Type.Emoji(),
						},
					},
				},
			})
		}
		return
	}
	matrixEvt := global.MC.ToMatrix(ctx, msg)
	if len(matrixEvt) == 0 {
		// This is an empty message, send a end typing event.
		sendTypingNotification(ctx, msg.Chat, false)
		return
	}

	if global.Cfg.SendMultipart {
		var events []*event.Event
		var dbMessages []*database.Message
		for _, part := range matrixEvt {
			dbMessage := prepareDBMessage(portal, msg.ID, part.PartInfo, msg.ThreadRoot, msg.Sender, msg.Time)
			events = append(events, &event.Event{
				Sender:    id.UserID(msg.Sender.String()),
				Type:      part.Type,
				Timestamp: dbMessage.Timestamp,
				ID:        dbMessage.MXID,
				RoomID:    portal.MXID,
				Content: event.Content{
					Parsed: part.Content,
					Raw:    part.Extra,
				},
			})
			dbMessages = append(dbMessages, dbMessage)
		}
		sendMultipartEvent(ctx, events)
		// TODO maybe make some bulk insert thing at some point?
		for _, dbMessage := range dbMessages {
			err := dbMessage.Insert(ctx)
			if err != nil {
				log.Warn().Err(err).
					Int("part_id", dbMessage.Part).
					Msg("Failed to insert message part to database")
			}
		}
	} else {
		// TODO remove this method after Android supports receiving multipart
		// messages
		for _, part := range matrixEvt {
			dbMessage := prepareDBMessage(portal, msg.ID, part.PartInfo, msg.ThreadRoot, msg.Sender, msg.Time)
			sendEvent(ctx, &event.Event{
				Sender:    id.UserID(msg.Sender.String()),
				Type:      part.Type,
				Timestamp: dbMessage.Timestamp,
				ID:        dbMessage.MXID,
				RoomID:    portal.MXID,
				Content: event.Content{
					Parsed: part.Content,
					Raw:    part.Extra,
				},
			})
			err := dbMessage.Insert(ctx)
			if err != nil {
				log.Warn().Err(err).
					Int("part_id", part.PartInfo.PartID).
					Msg("Failed to insert message part to database")
			}
		}
	}
}

func handleEdit(edit *imessage.MessageEdit) {
	log := global.Log.With().
		Str("action", "handle edit").
		Str("id", edit.EditMessageID.String()).
		Int("part", edit.EditPartIndex).
		Str("sender", edit.Sender.String()).
		Logger()
	ctx := log.WithContext(global.Ctx)
	msg, err := global.DB.Message.GetByIDWithoutChat(ctx, global.DBUser.RowID, edit.EditMessageID, edit.EditPartIndex)
	if err != nil {
		maybeFatalLog(&log, err).Msg("Failed to get message from database")
		return
	} else if msg == nil {
		log.Warn().Msg("Edit target message not found")
		return
	}

	content := &event.MessageEventContent{
		MsgType: event.MsgText,
		Body:    edit.Text,
	}
	extraAttrs := map[string]any{}
	if edit.RichLink != nil {
		linkPreview := global.MC.ConvertRichLinkToBeeper(ctx, msg.ID, edit.RichLink)
		if linkPreview == nil {
			log.Warn().Msg("Failed to convert link preview metadata")
			return
		}

		if content.Body == "" {
			content.Body = edit.RichLink.OriginalURL
		}
		extraAttrs["com.beeper.linkpreviews"] = []*msgconv.BeeperLinkPreview{linkPreview}
		log.Debug().Msg("Link preview metadata converted")
	}
	content.SetEdit(msg.MXID)
	if edit.EditID == uuid.Nil {
		edit.EditID = uuid.New()
	}

	sendEvent(ctx, &event.Event{
		Sender:    id.UserID(edit.Sender.String()),
		Type:      event.EventMessage,
		Timestamp: edit.Timestamp.UnixMilli(),
		ID:        editToMXID(edit.EditMessageID, edit.EditPartIndex, edit.EditID),
		RoomID:    msg.RoomID,
		Content: event.Content{
			Parsed: &content,
			Raw:    extraAttrs,
		},
	})
}

func handleUnsend(unsend *imessage.MessageUnsend) {
	log := global.Log.With().
		Str("action", "handle unsend").
		Str("id", unsend.UnsendMessageID.String()).
		Int("part", unsend.UnsendPartIndex).
		Str("sender", unsend.Sender.String()).
		Logger()
	ctx := log.WithContext(global.Ctx)
	msg, err := global.DB.Message.GetByIDWithoutChat(ctx, global.DBUser.RowID, unsend.UnsendMessageID, unsend.UnsendPartIndex)
	if err != nil {
		maybeFatalLog(&log, err).Msg("Failed to get message from database")
		return
	} else if msg == nil {
		log.Warn().Msg("Unsend target message not found")
		return
	}

	sendEvent(ctx, &event.Event{
		Sender:    id.UserID(unsend.Sender.String()),
		Type:      event.EventRedaction,
		Timestamp: unsend.Timestamp.UnixMilli(),
		ID:        unsendToMXID(unsend.UnsendMessageID, unsend.UnsendPartIndex, unsend.UnsendID),
		RoomID:    msg.RoomID,
		Redacts:   msg.MXID,
		Content: event.Content{
			Parsed: &event.RedactionEventContent{
				Redacts: msg.MXID,
			},
		},
	})
}

func handleGroupInfoChange(change *imessage.GroupInfoChange) {
	log := global.Log.With().
		Str("action", "handle group info change").
		Str("id", change.ID.String()).
		Str("sender", change.Sender.String()).
		Str("chat", change.Chat.String()).
		Logger()
	ctx := log.WithContext(global.Ctx)
	portal := getPortalByURI(ctx, change.Chat)
	if portal == nil {
		// TODO handle new chats here too?
		return
	}

	if change.PropertiesVersion > 0 && change.PropertiesVersion > portal.PropertiesVersion {
		log.Debug().Int("version", change.PropertiesVersion).Msg("Properties version changed")
		portal.PropertiesVersion = change.PropertiesVersion
		if err := portal.Update(ctx); err != nil {
			maybeFatalLog(&log, err).Msg("Failed to update portal in database")
			return
		}
	}

	if change.NewParticipants != nil && !slices.Equal(portal.Participants, change.NewParticipants) {
		sendMemberDiff(ctx, change.Chat, change.Sender, change.Time, portal.Participants, change.NewParticipants)
		portal.Participants = change.NewParticipants
		sendUpdatedBridgeInfo(ctx, change.Sender.String(), change.Time, portal)
		err := portal.Update(ctx)
		if err != nil {
			maybeFatalLog(&log, err).Msg("Failed to update portal in database")
			return
		}
	}
	if (change.NewName != "" || change.OldName != "") && portal.Name != change.NewName {
		portal.Name = change.NewName
		portal.NameSet = true
		sendRoomName(ctx, change.Sender.String(), change.Time, portal)
		sendUpdatedBridgeInfo(ctx, change.Sender.String(), change.Time, portal)
		err := portal.Update(ctx)
		if err != nil {
			maybeFatalLog(&log, err).Msg("Failed to update portal in database")
			return
		}
	}
	if change.RemoveAvatar {
		log.Debug().Msg("Removing group chat avatar")
		portal.AvatarHash = nil
		portal.AvatarGUID = nil
		portal.AvatarSet = false
		sendRoomAvatar(ctx, change.Sender.String(), change.Time, "", portal)
		err := portal.Update(ctx)
		if err != nil {
			maybeFatalLog(&log, err).Msg("Failed to update portal in database")
			return
		}
	} else if change.AvatarFileTransferGUID != nil && portal.AvatarGUID != change.AvatarFileTransferGUID {
		log.Debug().Msg("Updating group chat avatar")
		portal.AvatarGUID = change.AvatarFileTransferGUID
		avatarBytes, err := change.NewAvatar.DownloadMemory(ctx, global.IM.User)
		if err != nil {
			log.Warn().Err(err).Msg("failed to download avatar")
		} else {
			hash := sha256.Sum256(avatarBytes)
			if !portal.AvatarSet || portal.AvatarHash == nil || *portal.AvatarHash != hash {
				mimeMeta := mimetype.Detect(avatarBytes)
				fileName := fmt.Sprintf("%s-avatar%s", change.GroupID, mimeMeta.Extension())
				fileURI, err := global.UploadMatrixMedia(ctx, avatarBytes, fileName, mimeMeta.String())
				if err != nil {
					log.Err(err).Msg("Failed to save avatar")
				} else {
					portal.AvatarHash = &hash
					portal.AvatarSet = true
					sendRoomAvatar(ctx, change.Sender.String(), change.Time, string(fileURI), portal)
					err := portal.Update(ctx)
					if err != nil {
						maybeFatalLog(&log, err).Msg("Failed to update portal in database")
						return
					}
				}
			}
		}
	}
}

func handleReadReceipt(receipt *imessage.ReadReceipt) {
	log := global.Log.With().
		Str("action", "handle read receipt").
		Str("read_up_to", receipt.ReadUpTo.String()).
		Str("sender", receipt.Sender.String()).
		Logger()
	ctx := log.WithContext(global.Ctx)

	if msg, err := global.DB.Message.GetLastPartByIDWithoutChat(ctx, global.DBUser.RowID, receipt.ReadUpTo); err != nil {
		maybeFatalLog(&log, err).Msg("Failed to get message from database")
		return
	} else if msg != nil {
		markRead(ctx, id.UserID(receipt.Sender.String()), msg.RoomID, msg.MXID, receipt.ReadAt)
	} else if tapback, err := global.DB.Tapback.GetByTapbackIDWithoutChat(ctx, global.DBUser.RowID, receipt.ReadUpTo); err != nil {
		maybeFatalLog(&log, err).Msg("Failed to get tapback from database")
		return
	} else if tapback != nil {
		markRead(ctx, id.UserID(receipt.Sender.String()), id.RoomID(tapback.Portal.URI.String()), tapback.MXID, receipt.ReadAt)
	} else {
		log.Warn().Msg("Read receipt target message not found")
	}
}

func handleMarkUnread(unread *imessage.MarkUnread) {
	log := global.Log.With().
		Str("action", "handle mark unread").
		Str("message_id", unread.MessageID.String()).
		Logger()
	ctx := log.WithContext(global.Ctx)

	portalURI, err := global.DB.Message.GetPortalURIByID(context.TODO(), unread.MessageID, global.DBUser.RowID)
	if err != nil {
		log.Err(err).Msg("Failed to get portal URI")
		return
	} else if portalURI.IsEmpty() {
		log.Warn().Msg("Unknown message")
		return
	}
	portal := getPortalByURI(ctx, portalURI)
	if portal == nil {
		if ctx.Err() == nil {
			log.Fatal().Msg("getPortalByURI returned nil even though context isn't done")
		}
		return
	}

	sendEvent(ctx, &event.Event{
		Type:   EventTypeMarkedUnreadIPC,
		RoomID: portal.MXID,
		Content: event.Content{
			Parsed: &MarkedUnreadEventContent{
				Unread:    true,
				Timestamp: uint64(time.Now().UnixMilli()),
			},
		},
	})
}

func markRead(ctx context.Context, sender id.UserID, roomID id.RoomID, eventID id.EventID, ts time.Time) {
	sendEvent(ctx, &event.Event{
		Type:   event.EphemeralEventReceipt,
		RoomID: roomID,
		Content: event.Content{
			Parsed: &event.ReceiptEventContent{
				eventID: {
					event.ReceiptTypeRead: {
						sender: {
							Timestamp: ts,
						},
					},
				},
			},
		},
	})
}

func handleTypingNotification(typing *imessage.TypingNotification) {
	log := global.Log.With().
		Str("action", "handle typing notification").
		Str("chat_guid", typing.Chat.String()).
		Bool("typing", typing.Typing).
		Logger()
	ctx := log.WithContext(global.Ctx)

	sendTypingNotification(ctx, typing.Chat, typing.Typing)
}

func sendTypingNotification(ctx context.Context, chat uri.ParsedURI, typing bool) {
	var userIDs []id.UserID
	if typing {
		// The user ID is the same as the chat ID in iMessage DMs, which are
		// the only chats that have typing notifications.
		userIDs = []id.UserID{id.UserID(chat.String())}
	}
	sendEvent(ctx, &event.Event{
		Type:   event.EphemeralEventTyping,
		RoomID: id.RoomID(chat.String()),
		Content: event.Content{
			Parsed: &event.TypingEventContent{UserIDs: userIDs},
		},
	})
}

func handleSendMessageStatus(status *imessage.SendMessageStatus) {
	log := global.Log.With().
		Str("action", "handle send message status").
		Str("id", status.GUID.String()).
		Logger()
	ctx := log.WithContext(global.Ctx)
	msgs, err := global.DB.Message.GetAllMessagesForIDWithoutChat(ctx, global.DBUser.RowID, status.GUID)
	if err != nil {
		maybeFatalLog(&log, err).Msg("Failed to get message from database")
		return
	} else if len(msgs) == 0 {
		log.Warn().Msg("Message status target message not found")
		return
	}
	statusCode := event.MessageStatusSuccess
	var deliveredTo *[]id.UserID
	if status.Status == "fail" {
		statusCode = event.MessageStatusFail
	} else if !status.Sender.IsEmpty() {
		deliveredTo = &[]id.UserID{id.UserID(status.Sender.String())}
	}
	for _, msg := range msgs {
		sendEvent(ctx, &event.Event{
			Type:      event.BeeperMessageStatus,
			Timestamp: status.Timestamp.UnixMilli(),
			RoomID:    msg.RoomID,
			Content: event.Content{
				Parsed: &event.BeeperMessageStatusEventContent{
					RelatesTo: event.RelatesTo{
						Type:    event.RelReference,
						EventID: msg.MXID,
					},
					Status:           statusCode,
					Message:          status.Message,
					DeliveredToUsers: deliveredTo,
				},
			},
		})
	}
}

func handleDelivered(status *direct.MessageDelivered) {
	log := global.Log.With().
		Str("action", "handle delivered").
		Str("id", status.ID.String()).
		Logger()
	ctx := log.WithContext(global.Ctx)
	msgs, err := global.DB.Message.GetAllMessagesForIDWithoutChat(ctx, global.DBUser.RowID, status.ID)
	if err != nil {
		maybeFatalLog(&log, err).Msg("Failed to get message from database")
		return
	} else if len(msgs) == 0 {
		log.Warn().Msg("Delivered event target message not found")
		return
	}
	deliveredTo := make([]id.UserID, 0, len(status.To))
	for to := range status.To {
		deliveredTo = append(deliveredTo, id.UserID(to.String()))
	}
	for _, msg := range msgs {
		sendEvent(ctx, &event.Event{
			Type:      event.BeeperMessageStatus,
			Timestamp: time.Now().UnixMilli(),
			RoomID:    msg.RoomID,
			Content: event.Content{
				Parsed: &event.BeeperMessageStatusEventContent{
					RelatesTo: event.RelatesTo{
						Type:    event.RelReference,
						EventID: msg.MXID,
					},
					Status:           event.MessageStatusSuccess,
					DeliveredToUsers: &deliveredTo,
				},
			},
		})
	}
}

func handleEvent(evt any) {
	switch typedEvt := evt.(type) {
	case *imessage.Message:
		handleMessage(typedEvt)
	case *imessage.MessageEdit:
		handleEdit(typedEvt)
	case *imessage.MessageUnsend:
		handleUnsend(typedEvt)
	case *imessage.GroupInfoChange:
		handleGroupInfoChange(typedEvt)
	case *imessage.ReadReceipt:
		handleReadReceipt(typedEvt)
	case *imessage.MarkUnread:
		handleMarkUnread(typedEvt)
	case *imessage.TypingNotification:
		handleTypingNotification(typedEvt)
	case *imessage.SendMessageStatus:
		handleSendMessageStatus(typedEvt)
	case *direct.MessageDelivered:
		handleDelivered(typedEvt)

	case *direct.IDSRegisterFail:
		analytics.Track("IMGo IDS Register Failure", map[string]any{
			"bi":    true,
			"error": typedEvt.Error.Error(),
		})

	case *direct.HandlesUpdated:
		log := zerolog.Ctx(context.TODO())
		removed, added := exslices.SortedDiff(typedEvt.OldHandles, typedEvt.NewHandles, uri.Compare)
		log.Debug().
			Any("old_handles", typedEvt.OldHandles).
			Any("new_handles", typedEvt.NewHandles).
			Any("removed", removed).
			Any("added", added).
			Msg("Handles updated")

		registered := global.DBUser.RegisteredPhoneNumbers
		phoneNumberURIs := make([]uri.ParsedURI, 0, len(registered))
		for _, phoneNumber := range registered {
			uri, err := uri.ParseIdentifier(phoneNumber, uri.POIntlNumber)
			if err != nil {
				log.Warn().
					Err(err).
					Str("phone_number", phoneNumber).
					Msg("Failed to parse phone number")
			}
			phoneNumberURIs = append(phoneNumberURIs, uri)
		}

		for _, handle := range added {
			if !slices.Contains(phoneNumberURIs, handle) {
				continue
			}
			analytics.Track("IMGo Handle Added", map[string]any{
				"bi":     true,
				"handle": handle.String(),
			})
		}
		for _, handle := range removed {
			if !slices.Contains(phoneNumberURIs, handle) {
				continue
			}
			analytics.Track("IMGo Handle Removed", map[string]any{
				"bi":     true,
				"handle": handle.String(),
			})
		}

	case *direct.InvalidSignature:

	case *direct.SMSForwardingEnableRequestCode:

	case *direct.SMSForwardingToggled:

	case *direct.RefreshCredentialsRequired:
		global.IPC.Send(CmdBridgeInfo, GetBridgeInfo())
		if !typedEvt.Old {
			analytics.Track("IMGo IDS Refresh Credentials Required", map[string]any{
				"bi":                 true,
				"error":              "im-ids-refresh-credentials",
				"refresh_profile_id": typedEvt.UserID,
			})
		}

	case *direct.ConfigUpdated:
		global.DBUser.Update(context.TODO())
		global.ResetImux()
	case *direct.APNSConnected:
		if !global.StartConfirmed {
			global.StartConfirmed = true
			global.IPC.Send(CmdStarted, ReqStarted{LoggedIn: global.IM.HasValidAuthCerts()})
		}
		global.IPC.Send(CmdBridgeInfo, GetBridgeInfo())
	case *direct.IDSActuallyReregistered:
		global.IPC.Send(CmdBridgeInfo, GetBridgeInfo())
	case *direct.IDSRegisterSuccess:
		//go updateGroupOutgoingHandles()
	case *direct.BridgeInfoUpdated:
		global.IPC.Send(CmdBridgeInfo, GetBridgeInfo())
	}
}

func handleSecondaryEvent(evt any) {
	switch evt.(type) {
	case *direct.ConfigUpdated:
		global.DBUser.Update(context.TODO())
	case *direct.IDSActuallyReregistered:
		global.IPC.Send(CmdBridgeInfo, GetBridgeInfo())
		global.Log.Debug().Msg("Re-registering IDS on primary connector after secondary re-registered")
		err := global.IM.RegisterIDS(global.Ctx, false)
		if err != nil {
			global.Log.Err(err).Msg("Failed to re-register primary IDS after secondary")
		}
	case *direct.RefreshCredentialsRequired:
		global.IPC.Send(CmdBridgeInfo, GetBridgeInfo())
	}
}
