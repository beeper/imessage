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
	"bytes"
	"context"
	"fmt"
	"image"
	_ "image/gif"
	_ "image/jpeg"
	_ "image/png"
	"net/url"
	"strconv"
	"strings"

	"github.com/emersion/go-vcard"
	"github.com/gabriel-vasile/mimetype"
	"github.com/rs/zerolog"
	"go.mau.fi/util/ffmpeg"
	"go4.org/media/heif"
	_ "golang.org/x/image/tiff"
	_ "golang.org/x/image/webp"
	"maunium.net/go/mautrix/crypto/attachment"
	"maunium.net/go/mautrix/event"

	"github.com/beeper/imessage/imessage"
	"github.com/beeper/imessage/imessage/direct"
)

func (mc *MessageConverter) encryptFile(ctx context.Context, data []byte) *event.EncryptedFileInfo {
	if !mc.GetData(ctx).Encrypted {
		return nil
	}

	file := &event.EncryptedFileInfo{
		EncryptedFile: *attachment.NewEncryptedFile(),
		URL:           "",
	}
	file.EncryptInPlace(data)
	return file
}

func parseVLocationURL(addr string) (lat, long float64, query string, err error) {
	var parsed *url.URL
	parsed, err = url.Parse(addr)
	if err != nil {
		err = fmt.Errorf("failed to parse URL: %w", err)
	} else if parsed.Host != "maps.apple.com" {
		err = fmt.Errorf("unexpected host %q", parsed.Host)
	} else if ll := parsed.Query().Get("ll"); len(ll) == 0 {
		err = fmt.Errorf("missing ll query parameter")
	} else if latLong := strings.Split(ll, ","); len(latLong) != 2 {
		err = fmt.Errorf("invalid ll query parameter")
	} else if lat, err = strconv.ParseFloat(latLong[0], 64); err != nil {
		err = fmt.Errorf("failed to parse latitude: %w", err)
	} else if long, err = strconv.ParseFloat(latLong[1], 64); err != nil {
		err = fmt.Errorf("failed to parse longitude: %w", err)
	}
	query = parsed.Query().Get("q")
	return
}

func mimeToMsgType(mimeType string) event.MessageType {
	switch strings.Split(mimeType, "/")[0] {
	case "image":
		return event.MsgImage
	case "video":
		return event.MsgVideo
	case "audio":
		return event.MsgAudio
	default:
		return event.MsgFile
	}
}

func (mc *MessageConverter) convertIMAttachment(ctx context.Context, msg *imessage.Message, attach *imessage.Attachment) (*event.MessageEventContent, map[string]interface{}, error) {
	if mc.MaxFileSize > 0 && int64(attach.FileSize) > mc.MaxFileSize {
		return nil, nil, fmt.Errorf("attachment too large (size: %d MiB, max: %d MiB)", attach.FileSize/1024/1024, mc.MaxFileSize/1024/1024)
	}
	log := zerolog.Ctx(ctx)
	var data []byte
	if attach.InlineData != nil {
		data = attach.InlineData
	} else if queuer, ok := mc.PortalMethods.(ExtendedPortalMethods); ok && mc.AsyncFiles && attach.MimeType != "text/x-vlocation" {
		mxc, err := queuer.QueueFileTransfer(ctx, msg.ID, attach.PartInfo, attach.FileName, attach.Downloader)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to queue transfer: %w", err)
		}
		extra := map[string]any{}
		if msg.IsAudioMessage {
			extra["org.matrix.msc1767.audio"] = map[string]interface{}{}
			extra["org.matrix.msc3245.voice"] = map[string]interface{}{}
		}
		return &event.MessageEventContent{
			Body: attach.FileName,
			Info: &event.FileInfo{
				MimeType: attach.MimeType,
				Size:     attach.FileSize,
			},
			MsgType: mimeToMsgType(attach.MimeType),
			URL:     mxc,
		}, extra, nil
	} else {
		var err error
		data, err = attach.Downloader.DownloadMemory(ctx, mc.GetIM().User)
		if err != nil {
			log.Err(err).Msg("Failed to download attachment")
			return nil, nil, err
		}
	}

	mimeType := attach.MimeType
	if mimeType == "" {
		detected := mimetype.Detect(data)
		if detected != nil {
			mimeType = detected.String()
		}
	}
	fileName := attach.FileName
	extraContent := map[string]any{}

	if msg.IsAudioMessage {
		extraContent["org.matrix.msc1767.audio"] = map[string]interface{}{}
		extraContent["org.matrix.msc3245.voice"] = map[string]interface{}{}
	}
	if mc.ConvertCAF && msg.IsAudioMessage {
		ogg, err := ffmpeg.ConvertBytes(context.TODO(), data, ".ogg", []string{}, []string{"-c:a", "libopus"}, mimeType)
		if err == nil {
			mimeType = "audio/ogg"
			fileName = "Voice Message.ogg"
			data = ogg
		} else {
			log.Warn().Err(err).Msg("Failed to convert audio message to ogg/opus, sending without conversion")
		}
	}

	if CanConvertHEIF && mc.ConvertHEIF && (mimeType == "image/heic" || mimeType == "image/heif") {
		convertedData, err := ConvertHEIF(data)
		if err == nil {
			mimeType = "image/jpeg"
			fileName += ".jpg"
			data = convertedData
		} else {
			log.Warn().Err(err).Msg("Failed to convert heif image to jpeg, sending without conversion")
		}
	}

	if mc.ConvertTIFF && mimeType == "image/tiff" {
		convertedData, err := ConvertTIFF(data)
		if err == nil {
			mimeType = "image/jpeg"
			fileName += ".jpg"
			data = convertedData
		} else {
			log.Warn().Err(err).Msg("Failed to convert tiff image to jpeg, sending without conversion")
		}
	}

	if mc.ConvertMOV && mimeType == "video/quicktime" {
		convertedData, err := ffmpeg.ConvertBytes(
			ctx, data, ".mp4", []string{},
			[]string{"-c:v", "libx264", "-preset", "faster", "-crf", "22", "-c:a", "copy"},
			"video/quicktime",
		)
		if err == nil {
			mimeType = "video/mp4"
			fileName += ".mp4"
			data = convertedData
		} else {
			log.Warn().Err(err).Msg("Failed to convert quicktime video to mp4, sending without conversion")
		}
	}

	if mimeType == "text/x-vlocation" {
		card, err := vcard.NewDecoder(bytes.NewReader(data)).Decode()
		if err != nil {
			log.Warn().Err(err).Msg("Failed to parse vcard in x-vlocation attachment")
		} else if field := card.Get(vcard.FieldURL); field == nil {
			log.Warn().Msg("Location vcard doesn't have URL")
		} else if lat, long, query, err := parseVLocationURL(field.Value); err != nil {
			log.Warn().Err(err).Msg("Failed to parse location vcard URL")
		} else {
			name := query
			nameField := card.Get(vcard.FieldFormattedName)
			if nameField != nil {
				name = nameField.Value
			}
			if len(name) == 0 {
				name = "Location"
			}
			return &event.MessageEventContent{
				MsgType: event.MsgLocation,
				Body:    name,
				GeoURI:  fmt.Sprintf("geo:%.6f,%.6f", lat, long),
			}, nil, nil
		}
	}

	content := event.MessageEventContent{
		Body: fileName,
		Info: &event.FileInfo{
			MimeType: mimeType,
			Size:     len(data),
		},
		MsgType: mimeToMsgType(mimeType),
	}
	if content.MsgType == event.MsgImage {
		if mimeType == "image/heic" || mimeType == "image/heif" {
			item, err := heif.Open(bytes.NewReader(data)).PrimaryItem()
			if err != nil {
				log.Warn().Err(err).Msg("Failed to decode heif image config")
			} else {
				content.Info.Width, content.Info.Height, _ = item.VisualDimensions()
			}
		} else {
			cfg, _, err := image.DecodeConfig(bytes.NewReader(data))
			if err != nil {
				log.Warn().Err(err).Msg("Failed to decode image config")
			} else {
				content.Info.Width = cfg.Width
				content.Info.Height = cfg.Height
			}
		}
	}

	uploadFileName := fmt.Sprintf("%s.%d-%s", msg.ID, attach.PartInfo.PartID, fileName)
	uploadMime := mimeType
	uploadInfo := mc.encryptFile(ctx, data)
	if uploadInfo != nil {
		uploadMime = "application/octet-stream"
		uploadFileName = ""
	}
	mxc, err := mc.UploadMatrixMedia(ctx, data, uploadFileName, uploadMime)
	if err != nil {
		log.Err(err).Msg("Failed to upload attachment")
		return nil, nil, err
	}

	if uploadInfo != nil {
		uploadInfo.URL = mxc
		content.File = uploadInfo
	} else {
		content.URL = mxc
	}
	return &content, extraContent, nil
}

type ConvertedMessage struct {
	PartInfo imessage.MessagePartInfo
	Type     event.Type
	Content  *event.MessageEventContent
	Extra    map[string]any
}

func (mc *MessageConverter) convertIMAttachments(ctx context.Context, msg *imessage.Message) []*ConvertedMessage {
	log := zerolog.Ctx(ctx)
	converted := make([]*ConvertedMessage, len(msg.Attachments))
	for index, attach := range msg.Attachments {
		ctx := log.With().Int("attachment_index", index).Str("message_part", "attachment").Logger().WithContext(ctx)
		content, extra, err := mc.convertIMAttachment(ctx, msg, attach)
		if extra == nil {
			extra = map[string]interface{}{}
		}
		if err != nil {
			content = &event.MessageEventContent{
				MsgType: event.MsgNotice,
				Body:    err.Error(),
			}
		}
		converted[index] = &ConvertedMessage{
			PartInfo: attach.PartInfo,
			Type:     event.EventMessage,
			Content:  content,
			Extra:    extra,
		}
	}
	return converted
}

func (mc *MessageConverter) convertIMText(ctx context.Context, msg *imessage.Message) *ConvertedMessage {
	log := zerolog.Ctx(ctx).With().Str("message_part", "text").Logger()
	replacer := strings.NewReplacer("\ufffc", "", "\ufffd", "")
	msg.Text = replacer.Replace(msg.Text)
	msg.Subject = replacer.Replace(msg.Subject)
	if len(msg.Text) == 0 && len(msg.Subject) == 0 && len(msg.HTML) == 0 {
		return nil
	}
	content := &event.MessageEventContent{
		MsgType: event.MsgText,
		Body:    msg.Text,
	}
	if len(msg.Subject) > 0 {
		content.Format = event.FormatHTML
		content.FormattedBody = fmt.Sprintf("<strong>%s</strong><br>%s", event.TextToHTML(msg.Subject), event.TextToHTML(content.Body))
		content.Body = fmt.Sprintf("**%s**\n%s", msg.Subject, msg.Text)
	}
	if len(msg.HTML) > 0 {
		content.Format = event.FormatHTML
		if content.FormattedBody == "" {
			content.FormattedBody = msg.HTML
		} else {
			content.FormattedBody = fmt.Sprintf("%s<br><br>%s", content.FormattedBody, msg.HTML)
		}
		if content.Body == "" {
			content.Body = msg.HTML
		} else {
			content.Body = fmt.Sprintf("%s\n\n%s", content.Body, msg.HTML)
		}
	}
	extraAttrs := map[string]any{}
	if msg.RichLink != nil {
		log.Debug().Msg("Handling rich link in iMessage")
		linkPreview := mc.ConvertRichLinkToBeeper(ctx, msg.ID, msg.RichLink)
		if linkPreview != nil {
			extraAttrs["com.beeper.linkpreviews"] = []*BeeperLinkPreview{linkPreview}
			log.Debug().Msg("Link preview metadata converted")
		}
	}
	if direct.EffectID(msg.EffectID) == direct.EffectInvisibleInk {
		content.EnsureHasHTML()
		content.FormattedBody = fmt.Sprintf("<span data-mx-spoiler>%s</span>", content.FormattedBody)
	}
	return &ConvertedMessage{
		PartInfo: *msg.TextPart,
		Type:     event.EventMessage,
		Content:  content,
		Extra:    extraAttrs,
	}
}

const (
	EffectIDField  = "com.beeper.imessage.effect"
	MessageIDField = "com.beeper.imessage.id"
)

func (mc *MessageConverter) ToMatrix(ctx context.Context, msg *imessage.Message) []*ConvertedMessage {
	attachments := mc.convertIMAttachments(ctx, msg)
	if len(attachments) > 0 && msg.Subject != "" {
		// If there are attachments, then the subject is sent above the text and has a special -1 index.
		// The start index is also 0 even though the first attachment also has index 0.
		attachments = append([]*ConvertedMessage{{
			PartInfo: imessage.MessagePartInfo{
				PartID:     -1,
				StartIndex: 0,
				Length:     1,
			},
			Type: event.EventMessage,
			Content: &event.MessageEventContent{
				MsgType:       event.MsgText,
				Body:          msg.Subject,
				Format:        event.FormatHTML,
				FormattedBody: fmt.Sprintf("<strong>%s</strong>", event.TextToHTML(msg.Subject)),
			},
		}}, attachments...)
		// Tell convertIMText to not include the subject
		msg.Subject = ""
	}
	if text := mc.convertIMText(ctx, msg); text != nil {
		attachments = append(attachments, text)
	}
	threadRoot, replyFallback := mc.GetMatrixReply(ctx, msg)

	for _, part := range attachments {
		if threadRoot != "" {
			if mc.Threads {
				part.Content.RelatesTo = (&event.RelatesTo{}).SetThread(threadRoot, replyFallback)
			} else {
				part.Content.RelatesTo = (&event.RelatesTo{}).SetReplyTo(replyFallback)
			}
		}
		if part.Extra == nil {
			part.Extra = make(map[string]any)
		}
		if msg.EffectID != "" {
			part.Extra[EffectIDField] = msg.EffectID
		}
		part.Extra[MessageIDField] = &imessage.ParsedThreadRoot{
			MessagePartInfo: part.PartInfo,
			ID:              msg.ID,
		}
	}
	return attachments
}
