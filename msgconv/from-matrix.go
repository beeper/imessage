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

package msgconv

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"strconv"
	"strings"

	"github.com/gabriel-vasile/mimetype"
	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"github.com/tidwall/gjson"
	"go.mau.fi/util/exgjson"
	"go.mau.fi/util/ffmpeg"
	"howett.net/plist"
	log "maunium.net/go/maulogger/v2"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"

	"github.com/beeper/imessage/imessage"
	"github.com/beeper/imessage/imessage/direct"
	"github.com/beeper/imessage/imessage/direct/ids"
	"github.com/beeper/imessage/imessage/direct/util/nskeyedarchive"
	"github.com/beeper/imessage/imessage/direct/util/plistuuid"
	"github.com/beeper/imessage/imessage/direct/util/uri"
)

func (mc *MessageConverter) ToSMS(ctx context.Context, im *direct.IMessage, id uuid.UUID) (*direct.ReflectedSMS, error) {
	if mc.GetData(ctx).URI.Scheme == uri.SchemeMailto {
		return nil, fmt.Errorf("sending MMS to email isn't supported yet")
	}
	sms := &direct.ReflectedSMS{
		Data: direct.ReflectedSMSData{
			GUID:      plistuuid.NewFromUUID(id),
			PlainBody: im.Text,
			XHTML:     im.XML,
			Service:   "SMS",
			SV:        "1",

			PreviousMessageGUID: im.PreviousMessageID,
		},
		// Setting this breaks sending SMS for some reason
		//FR: true,
		IC: 0,
	}
	if mc.IsPrivateChat(ctx) {
		sms.ChatStyle = "im"
		sms.Data.Handle = mc.GetData(ctx).URI.Identifier
		sms.Recipients = []direct.SMSRecipient{{
			IntlPhone: mc.GetData(ctx).URI.Identifier,
		}}
	} else {
		sms.ChatStyle = "chat"
		sms.Recipients = make([]direct.SMSRecipient, len(mc.GetData(ctx).Participants))
		// TODO this will be wrong if MMS group participant lists are changed to include self
		for i, participant := range mc.GetData(ctx).Participants {
			sms.Recipients[i] = direct.SMSRecipient{
				IntlPhone: participant.Identifier,
			}
		}
	}
	return sms, nil
}

var targetContentPath = exgjson.Path("com.beeper.target_event_content")

func GetReactionTargetContent(ctx context.Context, raw json.RawMessage) *event.MessageEventContent {
	res := gjson.GetBytes(raw, targetContentPath)
	if !res.Exists() || !res.IsObject() {
		return nil
	}
	var rawPart []byte
	if res.Index > 0 {
		rawPart = raw[res.Index : res.Index+len(res.Raw)]
	} else {
		rawPart = []byte(res.Raw)
	}
	var content event.MessageEventContent
	err := json.Unmarshal(rawPart, &content)
	if err != nil {
		zerolog.Ctx(ctx).Err(err).Msg("Failed to parse target_event_content in reaction event")
		return nil
	}
	return &content
}

func (mc *MessageConverter) BuildTapback(ctx context.Context, msgID uuid.UUID, partInfo imessage.MessagePartInfo, tapback imessage.TapbackType, remove bool, originalContent *event.MessageEventContent) *direct.IMessage {
	summaryInfo := direct.AMSummaryInfo{
		ContentType: direct.AMContentTypeCustom,
		SourceText:  "a message",
	}
	if originalContent != nil {
		switch originalContent.MsgType {
		case event.MsgText, event.MsgNotice, event.MsgEmote:
			summaryInfo.SourceText = originalContent.Body
			if len(summaryInfo.SourceText) > 50 {
				summaryInfo.SourceText = summaryInfo.SourceText[:50] + "…"
			}
			summaryInfo.ContentType = direct.AMContentTypeText
		case event.MsgImage:
			summaryInfo.ContentType = direct.AMContentTypeImage
		case event.MsgVideo:
			summaryInfo.ContentType = direct.AMContentTypeMovie
		case event.MsgAudio:
			summaryInfo.ContentType = direct.AMContentTypeAudioMessage
		case event.MsgFile:
			summaryInfo.ContentType = direct.AMContentTypeAttachment
		case event.MsgLocation:
			summaryInfo.ContentType = direct.AMContentTypeLocation
		}
	}
	msiBytes, err := plist.Marshal(&summaryInfo, plist.BinaryFormat)
	if err != nil {
		panic(fmt.Errorf("failed to marshal message summary info: %w", err))
	}

	return &direct.IMessage{
		Participants: mc.GetData(ctx).Participants,
		//PreviousMessageID: TODO,
		GroupID: mc.GetData(ctx).GroupID,

		Text:                      tapback.ActionString(summaryInfo.String()),
		TapbackType:               tapback.Redacted(remove),
		TapbackTargetStartIndex:   &partInfo.StartIndex,
		TapbackTargetLength:       partInfo.Length,
		GroupVersion:              direct.CurrentGroupVersion,
		ProtocolVersion:           direct.CurrentProtocolVersion,
		PropertiesVersion:         0,
		TapbackMessageSummaryInfo: msiBytes,
		TapbackTargetFullID:       fmt.Sprintf("p:%d/%s", partInfo.PartID, strings.ToUpper(msgID.String())),
	}
}

func (mc *MessageConverter) ToiMessage(ctx context.Context, evt *event.Event, content *event.MessageEventContent) (*direct.IMessage, error) {
	msg := &direct.IMessage{
		Participants: mc.GetData(ctx).Participants,
		GroupID:      mc.GetData(ctx).GroupID,

		ThreadRoot: mc.GetiMessageThreadRoot(ctx, content),

		PropertiesVersion: 0,
		GroupVersion:      direct.CurrentGroupVersion,
		ProtocolVersion:   direct.CurrentProtocolVersion,
	}
	if !mc.IsPrivateChat(ctx) {
		msg.GroupName = mc.GetData(ctx).Name
		msg.PropertiesVersion = mc.GetData(ctx).PropertiesVersion
	}
	// TODO fill previous message ID

	if effectID, ok := evt.Content.Raw[EffectIDField].(string); ok {
		msg.EffectID = direct.EffectID(effectID)
		if !msg.EffectID.IsValid() {
			zerolog.Ctx(ctx).Warn().Str("effect_id", effectID).Msg("Unrecognized effect ID")
		}
	} else if strings.Contains(content.FormattedBody, "<span data-mx-spoiler") {
		// This is an extremely hacky way to make spoilers somewhat work
		msg.EffectID = direct.EffectInvisibleInk
	}

	if content.MsgType == event.MsgText || content.MsgType == event.MsgNotice || content.MsgType == event.MsgEmote {
		if content.MsgType == event.MsgEmote {
			content.Body = "/me " + content.Body
		}
		msg.Text = content.Body
	} else if len(content.URL) > 0 || content.File != nil || content.GeoURI != "" {
		uploaded, caption, isVoiceNote, err := mc.handleMatrixMedia(ctx, content, evt)
		if err != nil {
			return msg, fmt.Errorf("failed to reupload attachment: %w", err)
		}

		mmcsMsg := &direct.AttachmentMessageXML{
			Attachments: []*ids.UploadedAttachment{uploaded},
		}
		if caption != "" {
			mmcsMsg.Text = []*imessage.MessagePart{
				{PartIdx: 1, Value: event.TextToHTML(caption)},
			}
		}
		encoded, err := xml.Marshal(mmcsMsg)
		if err != nil {
			return msg, fmt.Errorf("couldn't format message body to xml: %w", err)
		}

		msg.AttachmentCount = 1
		msg.Text = "\ufffc" + caption
		msg.XML = string(encoded)
		if isVoiceNote {
			msg.IsAudioMessage = true
			msg.AudioMessageExpires = true
		}
	}

	if err := mc.parseURLPreview(ctx, evt, msg); err != nil {
		return nil, err
	}

	return msg, nil
}

func (mc *MessageConverter) MultipartToIMessage(ctx context.Context, events []*event.Event) (*direct.IMessage, error) {
	msg := &direct.IMessage{
		Participants: mc.GetData(ctx).Participants,
		GroupID:      mc.GetData(ctx).GroupID,

		ThreadRoot: mc.GetiMessageThreadRoot(ctx, events[0].Content.AsMessage()),

		PropertiesVersion: 0,
		GroupVersion:      direct.CurrentGroupVersion,
		ProtocolVersion:   direct.CurrentProtocolVersion,
	}
	if !mc.IsPrivateChat(ctx) {
		msg.GroupName = mc.GetData(ctx).Name
		msg.PropertiesVersion = mc.GetData(ctx).PropertiesVersion
	}
	// TODO fill previous message ID

	var caption string
	var attachments []*ids.UploadedAttachment
	for i, evt := range events {
		content := evt.Content.AsMessage()
		if effectID, ok := evt.Content.Raw[EffectIDField].(string); ok {
			if msg.EffectID != "" && msg.EffectID != direct.EffectID(effectID) {
				return nil, fmt.Errorf("different effect IDs within a multipart message are not supported")
			}
			msg.EffectID = direct.EffectID(effectID)
			if !msg.EffectID.IsValid() {
				zerolog.Ctx(ctx).Warn().Str("effect_id", effectID).Msg("Unrecognized effect ID")
			}
		}

		if content.MsgType == event.MsgText || content.MsgType == event.MsgNotice || content.MsgType == event.MsgEmote {
			if caption != "" {
				return nil, fmt.Errorf("multiple captions within a multipart message are not supported")
			}
			if content.MsgType == event.MsgEmote {
				content.Body = "/me " + content.Body
			}
			caption = content.Body
		} else if len(content.URL) > 0 || content.File != nil || content.GeoURI != "" {
			uploaded, caption, isVoiceNote, err := mc.handleMatrixMedia(ctx, content, evt)
			if err != nil {
				return nil, fmt.Errorf("failed to reupload attachment: %w", err)
			}
			uploaded.MessagePart = i
			attachments = append(attachments, uploaded)
			if caption != "" {
				return nil, fmt.Errorf("captions on media within multipart message are not supported, just include a text message at the end")
			}
			if isVoiceNote {
				return nil, fmt.Errorf("voice notes within multipart message are not supported")
			}
		} else {
			return nil, fmt.Errorf("unsupported message type: %s", content.MsgType)
		}
	}

	mmcsMsg := &direct.AttachmentMessageXML{
		Attachments: attachments,
	}
	if caption != "" {
		mmcsMsg.Text = []*imessage.MessagePart{
			{PartIdx: len(attachments), Value: event.TextToHTML(caption)},
		}
	}
	encoded, err := xml.Marshal(mmcsMsg)
	if err != nil {
		return msg, fmt.Errorf("couldn't format message body to xml: %w", err)
	}

	msg.AttachmentCount = len(attachments)
	msg.Text = strings.Repeat("\ufffc", len(attachments)) + caption
	msg.XML = string(encoded)
	return msg, nil
}

func (mc *MessageConverter) parseURLPreview(ctx context.Context, evt *event.Event, msg *direct.IMessage) error {
	log := zerolog.Ctx(ctx)
	richLinkMetadata := mc.convertURLPreviewToIMessage(ctx, evt)
	if richLinkMetadata == nil {
		return nil
	}

	if richLinkMetadata.OriginalURL == "" || richLinkMetadata.URL == "" {
		log.Warn().Msg("URL preview is missing URL or OriginalURL")
		return nil
	}

	balloonPayload := direct.BalloonPayload{}

	richLinkMetadataRaw := map[string]any{
		"$class":            plist.UID(8),
		"collaborationType": 0,
		"originalURL":       plist.UID(3),
		"URL":               plist.UID(5),
		"usesActivityPub":   false,
		"version":           1,
	}

	archive := &nskeyedarchive.NSKeyedArchivePayload{
		Archiver: "NSKeyedArchiver",
		Objects: []any{
			"$null", // 0
			map[string]any{ // 1 - object root
				"$class":                plist.UID(9),
				"richLinkIsPlaceholder": false,
				"richLinkMetadata":      plist.UID(2),
			},
			richLinkMetadataRaw, // 2 - rich link metadata
			map[string]any{ // 3 - Original URL
				"$class":      plist.UID(7),
				"NS.base":     plist.UID(0),
				"NS.relative": plist.UID(4),
			},
			richLinkMetadata.OriginalURL, // 4 - original URL
			map[string]any{ // 5 - URL
				"$class":      plist.UID(7),
				"NS.base":     plist.UID(0),
				"NS.relative": plist.UID(6),
			},
			richLinkMetadata.URL, // 6 - URL
			map[string]any{ // 7 - NSURL class
				"$classes":   []string{"NSURL", "NSObject"},
				"$classname": "NSURL",
			},
			map[string]any{ // 8 - LPLinkMetadata class
				"$classes":   []string{"LPLinkMetadata", "NSObject"},
				"$classname": "LPLinkMetadata",
			},
			map[string]any{ // 9 - RichLink class
				"$classname": "RichLink",
			},
			map[string]any{ // 10 - RichLinkImageAttachmentSubstitute class
				"$classname": "RichLinkImageAttachmentSubstitute",
			},
		},
		Top:     nskeyedarchive.NSKeyedArchiveRoot{Root: plist.UID(1)},
		Version: 100000,
	}

	if richLinkMetadata.Title != "" {
		richLinkMetadataRaw["title"] = plist.UID(len(archive.Objects))
		archive.Objects = append(archive.Objects, richLinkMetadata.Title)
	}

	if richLinkMetadata.Summary != "" {
		richLinkMetadataRaw["summary"] = plist.UID(len(archive.Objects))
		archive.Objects = append(archive.Objects, richLinkMetadata.Summary)
	}

	if richLinkMetadata.Image != nil {
		richLinkMetadataRaw["image"] = plist.UID(len(archive.Objects))
		mimeTypeUID := plist.UID(len(archive.Objects) + 1)
		archive.Objects = append(archive.Objects, map[string]any{
			"$class":                                 plist.UID(10),
			"imageType":                              0,
			"MIMEType":                               mimeTypeUID,
			"richLinkImageAttachmentSubstituteIndex": 0,
		})
		archive.Objects = append(archive.Objects, richLinkMetadata.Image.MimeType)
		balloonPayload.Attachments = append(balloonPayload.Attachments, richLinkMetadata.Image.Source.Data)
	}

	var err error
	balloonPayload.Payload, err = plist.Marshal(archive, plist.BinaryFormat)
	if err != nil {
		return fmt.Errorf("couldn't encode rich link metadata: %w", err)
	}

	payload, err := plist.Marshal(balloonPayload, plist.BinaryFormat)
	if err != nil {
		return fmt.Errorf("couldn't encode rich link metadata: %w", err)
	}

	msg.BalloonID = direct.BalloonURL

	resp, err := mc.GetIM().User.UploadAttachment(ctx, payload, "", "application/x-apple-plist")
	if err != nil {
		return fmt.Errorf("failed to reupload balloon data: %w", err)
	}
	decryptionKey, err := hex.DecodeString(resp.DecryptionKey)
	if err != nil {
		return fmt.Errorf("failed to decode decryption key: %w", err)
	}
	signature, err := hex.DecodeString(resp.MMCSSignatureHex)
	if err != nil {
		return fmt.Errorf("failed to decode signature: %w", err)
	}

	msg.BalloonInfo = &direct.BaloonPayloadDownloadInfo{
		DecryptionKey: decryptionKey,
		FileSize:      resp.FileSize,
		MMCSOwner:     resp.MMCSOwner,
		MMCSURL:       resp.MMCSURL,
		MMCSSignature: signature,
	}
	return nil
}

const locationVCardTemplate = `BEGIN:VCARD
VERSION:3.0
PRODID:-//Apple Inc.//iPhone OS//EN
N:;Current Location;;;
FN:Current Location
URL;type=pref:http://maps.apple.com/?ll=%.6[1]f\,%.6[2]f&q=%.6[1]f\,%.6[2]f
END:VCARD
`

func parseGeoURI(uri string) (lat, long float64, err error) {
	if !strings.HasPrefix(uri, "geo:") {
		err = fmt.Errorf("uri doesn't have geo: prefix")
		return
	}
	// Remove geo: prefix and anything after ;
	coordinates := strings.Split(strings.TrimPrefix(uri, "geo:"), ";")[0]

	if splitCoordinates := strings.Split(coordinates, ","); len(splitCoordinates) != 2 {
		err = fmt.Errorf("didn't find exactly two numbers separated by a comma")
	} else if lat, err = strconv.ParseFloat(splitCoordinates[0], 64); err != nil {
		err = fmt.Errorf("latitude is not a number: %w", err)
	} else if long, err = strconv.ParseFloat(splitCoordinates[1], 64); err != nil {
		err = fmt.Errorf("longitude is not a number: %w", err)
	}
	return
}

func makeVCardLocation(geoURI string) (string, error) {
	lat, long, err := parseGeoURI(geoURI)
	return fmt.Sprintf(locationVCardTemplate, lat, long), err
}

func (mc *MessageConverter) handleMatrixMedia(ctx context.Context, msg *event.MessageEventContent, evt *event.Event) (resp *ids.UploadedAttachment, caption string, isVoiceNote bool, err error) {
	if msg.MsgType == event.MsgLocation {
		var body string
		body, err = makeVCardLocation(msg.GeoURI)
		if err != nil {
			return
		}
		resp, err = mc.GetIM().User.UploadAttachment(ctx, []byte(body), "CL.loc.vcf", "text/x-vlocation")
		return
	}
	var url id.ContentURIString
	var file *event.EncryptedFileInfo
	if msg.File != nil {
		file = msg.File
		url = msg.File.URL
	} else {
		url = msg.URL
	}
	filename := msg.Body
	if msg.FileName != "" && msg.FileName != msg.Body {
		filename = msg.FileName
		caption = msg.Body
	}

	var data []byte
	data, err = mc.DownloadMatrixMedia(ctx, url)
	if err != nil {
		return
	}
	if file != nil {
		err = file.DecryptInPlace(data)
		if err != nil {
			err = fmt.Errorf("failed to decrypt attachment: %w", err)
			return
		}
	}

	// Only convert when sending to iMessage. SMS users probably don't want CAF.
	// TODO: check the service and convert the voice message as it used to
	mimeType := msg.GetInfo().MimeType
	if mimeType == "" {
		mimeType = mimetype.Detect(data).String()
	}
	_, isMSC3245Voice := evt.Content.Raw["org.matrix.msc3245.voice"]
	if mc.GetData(ctx).Service == imessage.ServiceIMessage && isMSC3245Voice && strings.HasPrefix(mimeType, "audio/") {
		if mimeType != "audio/x-caf" {
			data, err = ffmpeg.ConvertBytes(context.TODO(), data, ".caf", []string{}, []string{"-c:a", "libopus"}, mimeType)
			mimeType = "audio/x-caf"
			if err != nil {
				log.Errorfln("Failed to transcode voice message to CAF. Error: %w", err)
				return
			}
		}
		isVoiceNote = true
		filename = "Audio Message.caf"
	}

	resp, err = mc.GetIM().User.UploadAttachment(ctx, data, filename, mimeType)
	return
}
