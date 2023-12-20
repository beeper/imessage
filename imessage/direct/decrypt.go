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

package direct

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"strings"
	"time"

	"github.com/nyaruka/phonenumbers"
	"github.com/rs/zerolog"
	"golang.org/x/exp/slices"
	"google.golang.org/protobuf/proto"
	"howett.net/plist"
	"maunium.net/go/mautrix/event"

	"github.com/beeper/imessage/analytics"
	"github.com/beeper/imessage/imessage"
	"github.com/beeper/imessage/imessage/direct/apns"
	"github.com/beeper/imessage/imessage/direct/ids"
	"github.com/beeper/imessage/imessage/direct/ids/idsproto"
	"github.com/beeper/imessage/imessage/direct/util/gnuzip"
	"github.com/beeper/imessage/imessage/direct/util/uri"
)

var zeroIV = make([]byte, 16)

type InvalidSignature struct {
	Payload *apns.SendMessagePayload
	Error   error
}

func trackReceivedEvent(msg *imessage.Message) {
	analytics.Track("IMGo Message Received", map[string]any{
		"message id":        msg.ID.String(),
		"message timestamp": msg.Time.UTC().Format(time.RFC3339),
		"service":           msg.Service.String(),
	})
}

func (dc *Connector) decryptPairECEncryptedMessage(ctx context.Context, sendMessagePayload *apns.SendMessagePayload) ([]byte, error) {
	var outer idsproto.OuterMessage
	err := proto.Unmarshal(sendMessagePayload.Payload, &outer)
	if err != nil {
		return nil, err
	}

	sharedSecret, err := dc.User.DeriveExistingPairECSharedSecret(outer.EphemeralPubKey)
	if err != nil {
		return nil, err
	}

	err = dc.User.VerifySignedPairECPayload(
		ctx,
		*sendMessagePayload.DestinationID,
		*sendMessagePayload.SenderID,
		sendMessagePayload.Token,
		sharedSecret,
		&outer,
	)
	if err != nil {
		zerolog.Ctx(ctx).Err(err).
			Str("identifier", sendMessagePayload.SenderID.String()).
			Str("push_token", base64.StdEncoding.EncodeToString(sendMessagePayload.Token)).
			Msg("Message signature validation failed")
		dc.EventHandler(&InvalidSignature{Payload: sendMessagePayload, Error: err})
	}

	return dc.User.DecryptSignedPairECPayload(sharedSecret, outer.EncryptedPayload)
}

func (dc *Connector) decryptPairEncryptedMessage(ctx context.Context, sendMessagePayload *apns.SendMessagePayload) ([]byte, error) {
	log := zerolog.Ctx(ctx)
	body, err := ids.ParseBody(sendMessagePayload.Payload)
	if err != nil {
		log.Err(err).Msg("Dropping incoming payload: failed to parse")
		return nil, err
	}
	err = dc.User.VerifySignedPairPayload(
		ctx,
		*sendMessagePayload.DestinationID,
		*sendMessagePayload.SenderID,
		sendMessagePayload.Token,
		body,
	)
	if err != nil {
		log.Err(err).
			Str("identifier", sendMessagePayload.SenderID.String()).
			Str("push_token", base64.StdEncoding.EncodeToString(sendMessagePayload.Token)).
			Msg("Message signature validation failed")
		dc.EventHandler(&InvalidSignature{Payload: sendMessagePayload, Error: err})
	}

	return dc.User.DecryptSignedPairPayload(body)
}

func (dc *Connector) handleEncryptedAPNSMessage(ctx context.Context, sendMessagePayload *apns.SendMessagePayload) {
	log := zerolog.Ctx(ctx).With().
		Str("encryption_type", string(sendMessagePayload.EncryptionType)).
		Logger()
	ctx = log.WithContext(ctx)
	if dc.User == nil {
		log.Warn().Msg("Dropping incoming payload: user not set")
		return
	}
	if !dc.User.HasAuthCerts() {
		log.Warn().Msg("Dropping incoming payload: user not authenticated")
		return
	}

	var err error
	var decryptedBody []byte
	switch sendMessagePayload.EncryptionType {
	case apns.EncryptionTypePair:
		decryptedBody, err = dc.decryptPairEncryptedMessage(ctx, sendMessagePayload)
	case apns.EncryptionTypePairEC:
		decryptedBody, err = dc.decryptPairECEncryptedMessage(ctx, sendMessagePayload)
	default:
		log.Error().
			Str("encryption_type", string(sendMessagePayload.EncryptionType)).
			Msg("Dropping incoming payload: unknown encryption type")
		return
	}
	if err != nil {
		log.Err(err).Msg("Failed to decrypt body")
		return
	}

	decompressed, err := gnuzip.MaybeGUnzip(decryptedBody)
	if err != nil {
		log.Err(err).Msg("Failed to decompress decrypted body")
		return
	}

	// DEBUG
	var rawMessage map[string]any
	_, err = plist.Unmarshal(decompressed, &rawMessage)
	if err != nil {
		log.Err(err).Msg("Failed to decode body to map")
		return
	}
	log.Trace().Any("raw_message", rawMessage).Msg("DEBUG: Decrypted message raw payload")
	// END DEBUG
	log.Debug().
		Str("sender_id", sendMessagePayload.SenderID.String()).
		Str("receiver_id", sendMessagePayload.DestinationID.String()).
		Str("push_token", base64.StdEncoding.EncodeToString(sendMessagePayload.Token)).
		Str("encryption_type", string(sendMessagePayload.EncryptionType)).
		Str("message_uuid", sendMessagePayload.MessageUUID.String()).
		Str("command", sendMessagePayload.Command.String()).
		Msg("Decrypted message")

	switch sendMessagePayload.Command {
	case apns.MessageTypeIMessage:
		dc.handleIMessage(ctx, sendMessagePayload, decompressed, rawMessage)
	case apns.MessageTypeIMessageEdit:
		dc.handleIMessageEdit(ctx, sendMessagePayload, decompressed)
	case apns.MessageTypeIMessageGroupMeta:
		dc.handleIMessageGroupMeta(ctx, sendMessagePayload, decompressed)
	case apns.MessageTypeSMSEnableRequestCode:
		dc.handleIMessageSMSEnableRequestCode(ctx, sendMessagePayload, decompressed)
	case apns.MessageTypeSMSForwardingToggled:
		dc.handleIMessageSMSForwardingToggled(ctx, sendMessagePayload, decompressed)
	case apns.MessageTypeIncomingSMS:
		dc.handleIncomingSMS(ctx, sendMessagePayload, decompressed)
	case apns.MessageTypeIncomingMMS:
		dc.handleIncomingMMS(ctx, sendMessagePayload, decompressed)
	case apns.MessageTypeIMessageAsync:
		dc.handleIncomingAsyncMessage(ctx, sendMessagePayload, decompressed)
	case apns.MessageTypeReflectedSMS, apns.MessageTypeReflectedMMS:
		dc.handleReflectedSMS(ctx, sendMessagePayload, decompressed)
	case apns.MessageTypeDeleteSync:
		dc.handleDeleteSync(ctx, sendMessagePayload, decompressed)
	case apns.MessageTypeMarkUnread:
		dc.handleMarkUnread(ctx, sendMessagePayload, decompressed)
	case apns.MessageTypeLinkPreviewEdit:
		dc.handleLinkPreviewEdit(ctx, sendMessagePayload, decompressed)
	default:
		log.Warn().Str("command", sendMessagePayload.Command.String()).Msg("Unhandled command (of known type)")
	}
}

type inlineAttachmentGetter interface {
	GetInlineAttachment(name string) []byte
}

func (dc *Connector) convertAttachment(i int, att *ids.UploadedAttachment, iag inlineAttachmentGetter) (*imessage.Attachment, error) {
	attachment := &imessage.Attachment{
		MimeType: att.MimeType,
		FileName: att.Name,
		UTIType:  att.UTIType,
		FileSize: att.FileSize,
		PartInfo: imessage.MessagePartInfo{
			PartID:     att.MessagePart,
			StartIndex: i,
			Length:     1,
		},
	}

	if att.InlineAttachment != "" {
		attachment.InlineData = iag.GetInlineAttachment(att.InlineAttachment)
		if attachment.InlineData == nil {
			return nil, fmt.Errorf("inline attachment %q not found", att.InlineAttachment)
		}
		return attachment, nil
	}

	sig, err := hex.DecodeString(att.MMCSSignatureHex)
	if err != nil {
		return nil, fmt.Errorf("failed to decode MMCS signature: %w", err)
	}

	decryptionKey, err := hex.DecodeString(att.DecryptionKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode decryption key: %w", err)
	}

	attachment.Downloader = ids.NewAttachmentDownloader(att.MMCSURL, att.MMCSOwner, sig, decryptionKey)
	return attachment, nil
}

func (dc *Connector) getBalloonPayload(ctx context.Context, message IMessage) ([]byte, error) {
	data := message.BalloonPayload
	if len(data) == 0 && message.BalloonInfo != nil {
		return dc.User.DownloadAttachment(
			ctx,
			message.BalloonInfo.MMCSURL,
			message.BalloonInfo.MMCSOwner,
			message.BalloonInfo.MMCSSignature,
			message.BalloonInfo.DecryptionKey,
		)
	}
	return data, nil
}

func (dc *Connector) getRichLink(ctx context.Context, message IMessage) (*imessage.RichLinkMetadata, error) {
	if message.BalloonID != BalloonURL {
		return nil, nil
	}

	data, err := dc.getBalloonPayload(ctx, message)
	if err != nil {
		return nil, err
	}

	if len(data) == 0 {
		return nil, nil
	}

	return handleLinkBalloonData(ctx, data)
}

func (dc *Connector) convertYouTubeBalloon(ctx context.Context, message IMessage) (string, error) {
	data, err := dc.getBalloonPayload(ctx, message)
	if err != nil {
		return "", err
	}

	if len(data) == 0 {
		return "", nil
	}

	return handleYouTubeBalloonData(ctx, data)
}

type MessageObject struct {
	BreadcrumbText string `xml:"breadcrumbText,attr"`
}

// TODO move this to a more sensible place
type AttachmentMessageXML struct {
	XMLName     xml.Name                  `xml:"html"`
	Attachments []*ids.UploadedAttachment `xml:"body>FILE"`
	Text        []*imessage.MessagePart   `xml:"body>span"`
	Objects     []*MessageObject          `xml:"body>object"`
}

func (dc *Connector) ensureHandleBroadcasted(ctx context.Context, handle uri.ParsedURI, recipients []uri.ParsedURI) {
	err := dc.BroadcastHandleTo(ctx, slices.Clone(recipients), handle, true)
	if err != nil {
		zerolog.Ctx(ctx).Err(err).Msg("Failed to broadcast handle after receiving message")
	}
}

func (dc *Connector) handleIMessage(ctx context.Context, sendMessagePayload *apns.SendMessagePayload, decompressed []byte, rawMessage map[string]any) {
	log := zerolog.Ctx(ctx)
	var message IMessage
	_, err := plist.Unmarshal(decompressed, &message)
	if err != nil {
		log.Err(err).Msg("Failed to decode iMessage body to struct")
		return
	}
	log.Trace().Any("parsed_message", &message).Msg("DEBUG: Decrypted message struct payload")
	if len(message.Participants) == 0 {
		// Probably an edit or some other non-normal message
		return
	}

	var id [16]byte
	copy(id[:], sendMessagePayload.MessageUUID)
	var chatURI uri.ParsedURI
	parsedDestinationID := *sendMessagePayload.DestinationID
	if !slices.Contains(dc.User.Handles, parsedDestinationID) {
		log.Warn().
			Str("destination_id", parsedDestinationID.String()).
			Array("own_handles", uri.ToZerologArray(dc.User.Handles)).
			Msg("Received message for unknown destination ID (not in own handles)")
	}
	if len(message.Participants) == 2 {
		var otherUser uri.ParsedURI
		for _, participant := range message.Participants {
			if participant != parsedDestinationID {
				otherUser = participant
			}
		}
		if otherUser.IsEmpty() || !slices.Contains(message.Participants, parsedDestinationID) {
			log.Error().
				Array("participants", uri.ToZerologArray(message.Participants)).
				Array("own_handles", uri.ToZerologArray(dc.User.Handles)).
				Str("other_user", otherUser.String()).
				Str("destination_id", parsedDestinationID.String()).
				Msg("Failed to find other user in 2-person chat")
			return
		}
		message.Participants = []uri.ParsedURI{otherUser}
		chatURI = otherUser
	} else {
		if message.GroupID == "" {
			log.Warn().Msg("Ignoring suspicious group message without group ID")
			return
		}
		chatURI = uri.ParsedURI{
			Scheme:     uri.SchemeGroup,
			Identifier: message.GroupID,
		}
		message.Participants = uri.Sort(message.Participants)
	}
	go dc.ensureHandleBroadcasted(ctx, parsedDestinationID, message.Participants)

	var attachments []*imessage.Attachment
	var textPart *imessage.MessagePartInfo
	if message.XML != "" {
		var messageXML AttachmentMessageXML
		err := xml.Unmarshal([]byte(message.XML), &messageXML)
		if err != nil {
			log.Err(err).Msg("Failed to decode message XML")
			return
		}
		// This is a very hacky way to get a fallback for location shares
		if message.Text == "\ufffd" && len(messageXML.Objects) == 1 && len(messageXML.Objects[0].BreadcrumbText) > 0 {
			textPart = &imessage.MessagePartInfo{
				PartID:     0,
				StartIndex: 0,
				Length:     1,
			}
			message.Text = messageXML.Objects[0].BreadcrumbText
		}

		var attachmentDownloadError error
		for i, att := range messageXML.Attachments {
			if att.InlineAttachment == "" && (att.MMCSSignatureHex == "" || att.MMCSURL == "" || att.MMCSOwner == "") {
				// TODO remove this log after figuring out the problem
				log.Warn().
					Any("attachment", att).
					Str("raw_html", message.XML).
					Msg("DEBUG: Attachment missing download info")
			}
			attachment, err := dc.convertAttachment(i, att, &message)
			if err != nil {
				log.Err(err).Msg("Failed to convert attachment")
				attachmentDownloadError = err
			} else {
				attachments = append(attachments, attachment)
				if attachment.UTIType == "com.apple.coreaudio-format" && attachment.MimeType == "" {
					attachment.MimeType = "audio/x-caf"
				}
			}
		}
		if attachmentDownloadError != nil {
			attachments = nil
			message.Text = fmt.Sprintf("Failed to download image: %s\n\n%s", attachmentDownloadError.Error(), message.Text)
		} else {
			currentIdx := len(attachments)
			for _, text := range messageXML.Text {
				// TODO this won't work if there's ever actual HTML tags in edits,
				//      but at the moment it seems like edits can't have mentions.
				textWithNewlines := event.ReverseTextToHTML(text.Value)
				textPart = &imessage.MessagePartInfo{
					PartID:     text.PartIdx,
					StartIndex: currentIdx,
					Length:     TextLen(textWithNewlines),
				}
				currentIdx += textPart.Length
			}
		}
	}

	var messageHTML string
	if message.BalloonID == BalloonYouTube {
		messageHTML, err = dc.convertYouTubeBalloon(ctx, message)
		if err != nil {
			log.Err(err).Msg("Failed to parse YouTube Balloon info")
		}
		textPart = &imessage.MessagePartInfo{
			PartID:     0,
			StartIndex: 0,
			Length:     1,
		}
	}

	richLink, err := dc.getRichLink(ctx, message)
	if err != nil {
		log.Err(err).Msg("Failed to parse rich link")
	}

	if message.Text != "" && textPart == nil {
		textPart = &imessage.MessagePartInfo{
			PartID:     0,
			StartIndex: 0,
			Length:     TextLen(message.Text),
		}
	}

	msg := &imessage.Message{
		ID:       id,
		Time:     sendMessagePayload.Timestamp.Time,
		Subject:  message.Subject,
		Text:     message.Text,
		HTML:     messageHTML,
		TextPart: textPart,
		Chat:     chatURI,
		Sender:   *sendMessagePayload.SenderID,
		Receiver: parsedDestinationID,
		Service:  "iMessage",
		IsFromMe: slices.Contains(dc.User.Handles, *sendMessagePayload.SenderID),
		GroupID:  message.GroupID,

		Attachments:    attachments,
		IsAudioMessage: message.IsAudioMessage,

		GroupName:    message.GroupName,
		Participants: message.Participants,

		EffectID: string(message.EffectID),

		RichLink: richLink,
	}

	if message.ThreadRoot != "" {
		parsed, err := imessage.ParseThreadRoot(message.ThreadRoot)
		if err != nil {
			log.Warn().Err(err).Str("thread_root", message.ThreadRoot).Msg("Failed to parse message thread root")
		} else {
			msg.ThreadRoot = &parsed
		}
	}

	if message.TapbackType != 0 {
		tb := &imessage.Tapback{
			TargetGUIDString: message.TapbackTargetFullID,
			Type:             imessage.TapbackType(message.TapbackType),
		}
		msg.Tapback, err = tb.Parse()
		if err != nil {
			log.Err(err).Msg("Failed to parse tapback")
			return
		}
		var startIndex int
		if message.TapbackTargetStartIndex != nil {
			startIndex = *message.TapbackTargetStartIndex
		}
		msg.Tapback.PartInfo = imessage.MessagePartInfo{
			PartID:     msg.Tapback.TargetPart,
			StartIndex: startIndex,
			Length:     message.TapbackTargetLength,
		}
	}

	trackReceivedEvent(msg)

	dc.EventHandler(msg)
}

func (dc *Connector) handleLinkPreviewEdit(ctx context.Context, sendMessagePayload *apns.SendMessagePayload, decompressed []byte) {
	log := zerolog.Ctx(ctx)
	var message IMessage
	_, err := plist.Unmarshal(decompressed, &message)
	if err != nil {
		log.Err(err).Msg("Failed to decode iMessage body to struct")
		return
	}
	richLink, err := dc.getRichLink(ctx, message)
	if err != nil {
		log.Err(err).Msg("Failed to handle link preview edit")
		return
	}
	dc.EventHandler(&imessage.MessageEdit{
		Sender:        *sendMessagePayload.SenderID,
		IsFromMe:      slices.Contains(dc.User.Handles, *sendMessagePayload.SenderID),
		Timestamp:     sendMessagePayload.Timestamp.Time,
		EditMessageID: sendMessagePayload.MessageUUID.UUID(),
		EditPartIndex: 0,
		RichLink:      richLink,
	})
}

func (dc *Connector) handleIMessageEdit(ctx context.Context, sendMessagePayload *apns.SendMessagePayload, decompressed []byte) {
	log := zerolog.Ctx(ctx)
	var messageEdit IMessageEdit
	_, err := plist.Unmarshal(decompressed, &messageEdit)
	if err != nil {
		log.Err(err).Msg("Failed to decode iMessage edit body to struct")
		return
	}
	log.Trace().Any("message_edit", &messageEdit).Msg("DEBUG: Decrypted message edit struct payload")

	switch messageEdit.EditType {
	case EditTypeEdit:
		newText, err := ParseEditXML(messageEdit.EditXML)
		if err != nil {
			log.Err(err).Msg("Failed to parse edit details")
			return
		}

		dc.EventHandler(&imessage.MessageEdit{
			Sender:        *sendMessagePayload.SenderID,
			IsFromMe:      slices.Contains(dc.User.Handles, *sendMessagePayload.SenderID),
			Timestamp:     sendMessagePayload.Timestamp.Time,
			EditMessageID: messageEdit.EditMessageID.UUID,
			EditPartIndex: messageEdit.EditPartIndex,
			Text:          newText,
			EditID:        sendMessagePayload.MessageUUID.UUID(),
		})
	case EditTypeUnsend:
		dc.EventHandler(&imessage.MessageUnsend{
			Sender:          *sendMessagePayload.SenderID,
			IsFromMe:        slices.Contains(dc.User.Handles, *sendMessagePayload.SenderID),
			Timestamp:       sendMessagePayload.Timestamp.Time,
			UnsendMessageID: messageEdit.EditMessageID.UUID,
			UnsendPartIndex: messageEdit.EditPartIndex,
			UnsendID:        sendMessagePayload.MessageUUID.UUID(),
		})
	}
}

func (dc *Connector) handleIMessageGroupMeta(ctx context.Context, sendMessagePayload *apns.SendMessagePayload, decompressed []byte) {
	log := zerolog.Ctx(ctx)
	var groupMetaChange IMessageGroupMetaChange
	_, err := plist.Unmarshal(decompressed, &groupMetaChange)
	if err != nil {
		log.Err(err).Msg("Failed to decode iMessage group meta body to struct")
		return
	}
	log.Info().Any("group_meta_change", &groupMetaChange).Msg("DEBUG: Decrypted group meta change struct payload")

	var oldParticipants, newParticipants []uri.ParsedURI
	for _, participant := range groupMetaChange.Participants {
		parsed, err := uri.ParseIdentifier(participant, uri.ParseiMessageDM)
		if err != nil {
			log.Err(err).Msg("Failed to parse participant")
			continue
		}
		oldParticipants = append(oldParticipants, parsed)
	}
	for _, participant := range groupMetaChange.TargetParticipants {
		parsed, err := uri.ParseIdentifier(participant, uri.ParseiMessageDM)
		if err != nil {
			log.Err(err).Msg("Failed to parse participant")
			continue
		}
		newParticipants = append(newParticipants, parsed)
	}
	oldParticipants = uri.Sort(oldParticipants)
	newParticipants = uri.Sort(newParticipants)

	var id [16]byte
	copy(id[:], sendMessagePayload.MessageUUID)
	var chatURI uri.ParsedURI
	if len(oldParticipants) == 2 {
		// TODO deduplicate this with handleIMessage?
		var otherUser uri.ParsedURI
		for _, participant := range oldParticipants {
			if participant != *sendMessagePayload.DestinationID {
				otherUser = participant
			}
		}
		if otherUser.IsEmpty() || !slices.Contains(oldParticipants, *sendMessagePayload.DestinationID) {
			log.Error().
				Array("participants", uri.ToZerologArray(oldParticipants)).
				Array("own_handles", uri.ToZerologArray(dc.User.Handles)).
				Str("other_user", otherUser.String()).
				Str("destination_id", sendMessagePayload.DestinationID.String()).
				Msg("Failed to find other user in 2-person chat")
			return
		}
		oldParticipants = []uri.ParsedURI{otherUser}
		newParticipants = nil
		chatURI = otherUser
	} else {
		if groupMetaChange.GroupID == "" {
			log.Warn().Msg("Ignoring suspicious group meta change without group ID")
			return
		}
		chatURI = uri.ParsedURI{
			Scheme:     uri.SchemeGroup,
			Identifier: groupMetaChange.GroupID,
		}
	}

	msg := &imessage.GroupInfoChange{
		ID:                id,
		PropertiesVersion: groupMetaChange.PropertiesVersion,

		GroupID:  groupMetaChange.GroupID,
		Chat:     chatURI,
		Time:     sendMessagePayload.Timestamp.Time,
		Sender:   *sendMessagePayload.SenderID,
		IsFromMe: slices.Contains(dc.User.Handles, *sendMessagePayload.SenderID),

		OldName: groupMetaChange.OldGroupName,
		NewName: groupMetaChange.NewGroupName,

		OldParticipants: oldParticipants,
		NewParticipants: newParticipants,
	}
	if groupMetaChange.Type == GroupMetaChangeAvatar && groupMetaChange.NewGroupAvatar == nil {
		msg.RemoveAvatar = true
	} else if groupMetaChange.NewGroupAvatar != nil {
		msg.AvatarFileTransferGUID = &groupMetaChange.NewGroupAvatar.IMFileTransferGUID
		sig, err := hex.DecodeString(groupMetaChange.NewGroupAvatar.IMFileTransferLocalUserInfoKey.MMCSSignatureHex)
		if err != nil {
			log.Err(err).Msg("Failed to decode signature")
		}

		decryptionKey, err := hex.DecodeString(groupMetaChange.NewGroupAvatar.IMFileTransferLocalUserInfoKey.DecryptionKey)
		if err != nil {
			log.Err(err).Msg("Failed to decode decryption key")
		}
		msg.NewAvatar = ids.NewAttachmentDownloader(
			groupMetaChange.NewGroupAvatar.IMFileTransferLocalUserInfoKey.MMCSURL,
			groupMetaChange.NewGroupAvatar.IMFileTransferLocalUserInfoKey.MMCSOwner,
			sig,
			decryptionKey,
		)
	}

	dc.EventHandler(msg)
}

func (dc *Connector) handleIMessageSMSEnableRequestCode(ctx context.Context, payload *apns.SendMessagePayload, decompressed []byte) {
	log := zerolog.Ctx(ctx)
	var evt SMSForwardingEnableRequestCode
	_, err := plist.Unmarshal(decompressed, &evt)
	if err != nil {
		log.Err(err).Msg("Failed to decode iMessage SMS enable request code body to struct")
		return
	}
	dc.EventHandler(&evt)
}

func (dc *Connector) handleIMessageSMSForwardingToggled(ctx context.Context, payload *apns.SendMessagePayload, decompressed []byte) {
	log := zerolog.Ctx(ctx)
	var evt SMSForwardingToggled
	_, err := plist.Unmarshal(decompressed, &evt)
	if err != nil {
		log.Err(err).Msg("Failed to decode iMessage SMS forwarding toggled body to struct")
		return
	}
	log.Info().
		Str("raw_data", base64.StdEncoding.EncodeToString(decompressed)).
		Any("parsed_data", &evt).
		Msg("SMS forwarding toggle event")
	if evt.AR {
		dc.User.SMSForwarding = &ids.SMSForwarding{Token: payload.Token, Handle: *payload.SenderID}
		// Not sure if this is actually needed, but pypush seemed to do something like this
		err = dc.SendReadReceipt(ctx, *payload.SenderID, []uri.ParsedURI{}, payload.MessageUUID.UUID(), imessage.ServiceSMS)
		if err != nil {
			log.Warn().Err(err).Msg("Failed to send read receipt for SMS forwarding enable event")
		}
		dc.EventHandler(&ConfigUpdated{})
	} else if evt.UD && evt.G != nil {
		log.Error().Str("message_id", strings.ToLower(evt.G.UUID.String())).Msg("Outgoing SMS might have failed")
		dc.EventHandler(&imessage.SendMessageStatus{
			GUID:      evt.G.UUID,
			Status:    "fail",
			Service:   imessage.ServiceSMS,
			Message:   "Phone rejected SMS",
			Timestamp: payload.Timestamp.Time,
		})
	} else if evt.UE && bytes.Equal(dc.User.SMSForwarding.GetToken(), payload.Token) {
		dc.User.SMSForwarding = nil
		dc.EventHandler(&ConfigUpdated{})
	}
	dc.EventHandler(&evt)
}

func (dc *Connector) handleIncomingMMS(ctx context.Context, sendMessagePayload *apns.SendMessagePayload, decompressed []byte) {
	log := zerolog.Ctx(ctx)
	var message IncomingMMS
	_, err := plist.Unmarshal(decompressed, &message)
	if err != nil {
		log.Err(err).Msg("Failed to decode incoming MMS body to struct")
		return
	}
	log.Trace().Any("parsed_message", &message).Msg("DEBUG: Decrypted incoming MMS")

	respDat, err := dc.User.DownloadAttachment(ctx, message.DownloadURL, message.ObjectID, message.Signature, message.EncryptionKey)
	if err != nil {
		log.Err(err).Msg("Failed to download and decrypt attachment")
		return
	}
	dc.handleIncomingSMS(ctx, sendMessagePayload, respDat)
}

func (dc *Connector) handleIncomingAsyncMessage(ctx context.Context, sendMessagePayload *apns.SendMessagePayload, decompressed []byte) {
	log := zerolog.Ctx(ctx)
	var message AsyncMessage
	_, err := plist.Unmarshal(decompressed, &message)
	if err != nil {
		log.Err(err).Msg("Failed to decode incoming async message body to struct")
		return
	}
	log.Trace().Any("parsed_message", &message).Msg("DEBUG: Decrypted incoming async message")

	sig, err := hex.DecodeString(message.SignatureHex)
	if err != nil {
		log.Err(err).Msg("Failed to decode signature")
		return
	}

	data, err := dc.User.DownloadAttachment(ctx, message.DownloadURL, message.ObjectID, sig, nil)
	if err != nil {
		log.Err(err).Msg("Failed to download and decrypt attachment")
		return
	}
	sendMessagePayload.Payload = data
	sendMessagePayload.Command = sendMessagePayload.OriginalCommand
	sendMessagePayload.OriginalCommand = 0
	log.Debug().Msg("Reprocessing downloaded async message")
	dc.handleEncryptedAPNSMessage(ctx, sendMessagePayload)
}

func (dc *Connector) handleIncomingSMS(ctx context.Context, sendMessagePayload *apns.SendMessagePayload, decompressed []byte) {
	log := zerolog.Ctx(ctx)
	var message SMS
	_, err := plist.Unmarshal(decompressed, &message)
	if err != nil {
		log.Err(err).Msg("Failed to decode incoming SMS body to struct")
		return
	}
	// MMSes are big, so don't log them even while developing
	if message.M == "sms" {
		log.Trace().Any("parsed_message", &message).Msg("DEBUG: Decrypted incoming SMS")
	}
	ourNumber := sendMessagePayload.DestinationID.Identifier
	if !strings.HasPrefix(ourNumber, "+") || !uri.IsOnlyNumbers(ourNumber[1:]) {
		log.Error().
			Str("message_id", message.MessageUUID.UUID.String()).
			Str("destination_id", ourNumber).
			Str("sender_id", sendMessagePayload.SenderID.String()).
			Msg("Incoming SMS forward destination ID isn't a phone number")
		return
	}
	log.Debug().
		Str("message_id", message.MessageUUID.UUID.String()).
		Str("sender", message.Sender).
		Str("receiver", message.Receiver).
		Str("own_number", ourNumber).
		Any("recipients", message.Recipients).
		Msg("DEBUG: Raw SMS recipient data")
	ourNumberParsed, err := phonenumbers.Parse(ourNumber, "")
	if err != nil {
		log.Warn().
			Str("number", ourNumber).
			Msg("Failed to parse own phone number")
		return
	}
	region := phonenumbers.GetRegionCodeForNumber(ourNumberParsed)
	senderURI, receiverURI, recipients, err := parseIncomingMMSParticipants(&message, region)
	if err != nil {
		log.Err(err).Msg("Failed to parse participants in incoming SMS")
		return
	}

	var chatURI uri.ParsedURI
	if len(recipients) > 1 {
		chatURI = makeMMSGroupID(recipients)
	} else {
		chatURI = senderURI
	}

	log.Debug().
		Str("message_id", message.MessageUUID.UUID.String()).
		Str("own_number_region", region).
		Str("sender", senderURI.String()).
		Str("receiver", receiverURI.String()).
		Array("recipients", uri.ToZerologArray(recipients)).
		Str("chat_uri", chatURI.String()).
		Msg("DEBUG: Normalized SMS recipient data")
	if receiverURI != *sendMessagePayload.DestinationID {
		log.Warn().
			Str("message_id", message.MessageUUID.UUID.String()).
			Str("destination_id", sendMessagePayload.DestinationID.String()).
			Str("receiver_uri", receiverURI.String()).
			Msg("Incoming SMS forward destination ID doesn't match parsed receiver")
	}

	var text string
	var textPart *imessage.MessagePartInfo
	var attachments []*imessage.Attachment
	startIndex := 0
	for i, part := range message.Content {
		if part.Type == "text/plain" {
			text = string(part.Data)
			textPart = &imessage.MessagePartInfo{
				PartID:     i,
				StartIndex: startIndex,
				Length:     TextLen(text),
			}
			startIndex += textPart.Length
		} else if part.Type != "application/smil" {
			attachments = append(attachments, &imessage.Attachment{
				PartInfo: imessage.MessagePartInfo{
					PartID:     i,
					StartIndex: startIndex,
					Length:     1,
				},
				InlineData: part.Data,
				FileSize:   len(part.Data),
				FileName:   part.ContentLocation,
				MimeType:   part.Type,
			})
			startIndex++
		}
	}

	msg := &imessage.Message{
		ID:           message.MessageUUID.UUID,
		Time:         message.Timestamp,
		Subject:      message.Subject,
		Attachments:  attachments,
		Text:         text,
		TextPart:     textPart,
		Chat:         chatURI,
		Sender:       senderURI,
		Receiver:     receiverURI,
		Service:      imessage.ServiceSMS,
		IsFromMe:     false,
		Participants: recipients,
	}

	trackReceivedEvent(msg)

	dc.EventHandler(msg)
}

func parseIncomingMMSParticipants(msg *SMS, region string) (sender, receiver uri.ParsedURI, participants []uri.ParsedURI, err error) {
	sender, err = uri.ParseIdentifierWithLocalNumbers(msg.Sender, uri.ParseIncomingSMSForward, region)
	if err != nil {
		err = fmt.Errorf("failed to parse sender identifier %q: %w", msg.Sender, err)
		return
	}
	receiver, err = uri.ParseIdentifierWithLocalNumbers(msg.Receiver, uri.ParseIncomingSMSForward, region)
	if err != nil {
		err = fmt.Errorf("failed to parse receiver identifier %q: %w", msg.Receiver, err)
		return
	}
	participants = make([]uri.ParsedURI, len(msg.Recipients), len(msg.Recipients)+1)
	for i, recipient := range msg.Recipients {
		participants[i], err = uri.ParseIdentifierWithLocalNumbers(recipient, uri.ParseIncomingSMSForward, region)
		if err != nil {
			err = fmt.Errorf("failed to parse identifier %q: %w", recipient, err)
			return
		}
	}
	// TODO don't remove self from participant list?
	receiverIndex := slices.Index(participants, receiver)
	if receiverIndex >= 0 {
		participants[receiverIndex] = participants[len(participants)-1]
		participants = participants[:len(participants)-1]
	}
	participants = append(participants, sender)
	participants = uri.Sort(participants)

	return
}

func parseReflectedMMSParticipants(recipients []SMSRecipient) (participants []uri.ParsedURI, chatID uri.ParsedURI, err error) {
	participants = make([]uri.ParsedURI, len(recipients))
	// TODO add self to participant list?
	for i, recipient := range recipients {
		participants[i], err = uri.ParseIdentifier(recipient.IntlPhone, uri.ParseIncomingSMSForward)
		if err != nil {
			err = fmt.Errorf("failed to parse identifier %q: %w", recipient.IntlPhone, err)
			return
		}
	}
	participants = uri.Sort(participants)
	chatID = makeMMSGroupID(participants)
	return
}

func makeMMSGroupID(recipients []uri.ParsedURI) uri.ParsedURI {
	recipientHash := sha256.Sum256([]byte(strings.Join(uri.ToStringSlice(recipients), ",")))
	return uri.ParsedURI{
		Scheme:     uri.SchemeGroupParticipants,
		Identifier: base64.RawURLEncoding.EncodeToString(recipientHash[:]),
	}
}

func (dc *Connector) handleReflectedSMS(ctx context.Context, sendMessagePayload *apns.SendMessagePayload, decompressed []byte) {
	log := zerolog.Ctx(ctx)
	var message ReflectedSMS
	_, err := plist.Unmarshal(decompressed, &message)
	if err != nil {
		log.Err(err).Msg("Failed to decode reflected SMS body to struct")
		return
	}
	log.Trace().Any("parsed_message", &message).Msg("DEBUG: Decrypted incoming reflected SMS")

	var chatURI uri.ParsedURI
	var participants []uri.ParsedURI
	if len(message.Recipients) > 1 {
		participants, chatURI, err = parseReflectedMMSParticipants(message.Recipients)
	} else {
		chatURI, err = uri.ParseIdentifier(message.Data.Handle, uri.ParseIncomingSMSForward)
		participants = []uri.ParsedURI{chatURI}
	}
	log.Debug().
		Str("message_id", message.Data.GUID.UUID.String()).
		Str("handle", message.Data.Handle).
		Any("recipients", message.Recipients).
		Array("parsed_recipients", uri.ToZerologArray(participants)).
		Str("chat_uri", chatURI.String()).
		Msg("DEBUG: Reflected SMS recipient data")

	partID := 0
	var attachments []*imessage.Attachment
	isAudioMessage := false
	if message.Data.XHTML != "" {
		var messageXML AttachmentMessageXML
		err = xml.Unmarshal([]byte(message.Data.XHTML), &messageXML)
		if err != nil {
			log.Err(err).Msg("Failed to decode message XML")
			return
		}
		for i, att := range messageXML.Attachments {
			// MMS attachments don't have message parts
			att.MessagePart = partID
			partID++
			attachment, err := dc.convertAttachment(i, att, &message)
			if err != nil {
				log.Err(err).Msg("Failed to convert attachment")
			} else {
				attachments = append(attachments, attachment)
				if attachment.UTIType == "com.apple.coreaudio-format" || attachment.UTIType == "org.3gpp.adaptive-multi-rate-audio" {
					isAudioMessage = true
				}
			}
		}
	}

	body := strings.TrimLeft(message.Data.PlainBody, "\uFFFC")
	textPart := &imessage.MessagePartInfo{
		PartID:     partID,
		StartIndex: partID,
		Length:     TextLen(body),
	}
	if err != nil {
		log.Err(err).Msg("Failed to parse participant URI in incoming reflected SMS")
		return
	}

	msg := &imessage.Message{
		ID:             message.Data.GUID.UUID,
		Time:           sendMessagePayload.Timestamp.Time,
		Subject:        message.Data.Subject,
		Text:           body,
		TextPart:       textPart,
		Attachments:    attachments,
		IsAudioMessage: isAudioMessage,
		Chat:           chatURI,
		Sender:         *sendMessagePayload.SenderID,
		Receiver:       *sendMessagePayload.SenderID,
		Service:        imessage.ServiceSMS,
		IsFromMe:       true,
		Participants:   participants,
	}

	trackReceivedEvent(msg)

	dc.EventHandler(msg)
}

func (dc *Connector) handleDeleteSync(ctx context.Context, sendMessagePayload *apns.SendMessagePayload, decompressed []byte) {
	log := zerolog.Ctx(ctx)
	var message DeleteSync
	_, err := plist.Unmarshal(decompressed, &message)
	if err != nil {
		log.Err(err).Msg("Failed to decode delete sync body to struct")
		return
	}
	log.Trace().Any("parsed_message", &message).Msg("DEBUG: Decrypted incoming delete sync")

	for _, chat := range message.Chat {
		var chatID uri.ParsedURI
		id := imessage.ParseIdentifier(chat.GUID)
		if id.IsGroup {
			chatID = uri.ParsedURI{Scheme: uri.SchemeGroup, Identifier: chat.GroupID.String()}
		} else if strings.Contains(id.LocalID, "@") {
			chatID = uri.ParsedURI{Scheme: uri.SchemeMailto, Identifier: id.LocalID}
		} else {
			chatID = uri.ParsedURI{Scheme: uri.SchemeTel, Identifier: id.LocalID}
		}

		dc.EventHandler(&imessage.ChatDeleted{
			Chat: chatID,
		})
	}
}

func (dc *Connector) handleMarkUnread(ctx context.Context, sendMessagePayload *apns.SendMessagePayload, decompressed []byte) {
	log := zerolog.Ctx(ctx)
	var message MarkUnread
	_, err := plist.Unmarshal(decompressed, &message)
	if err != nil {
		log.Err(err).Msg("Failed to decode mark unread body to struct")
		return
	}
	log.Trace().Any("parsed_message", &message).Msg("DEBUG: Decrypted incoming mark unread")

	dc.EventHandler(&imessage.MarkUnread{
		MessageID: message.MessageID.UUID,
	})
}
