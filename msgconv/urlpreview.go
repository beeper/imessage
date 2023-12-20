// beeper-imessage - A Matrix-iMessage puppeting bridge.
// Copyright (C) 2021 Tulir Asokan, Sumner Evans
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
	"encoding/json"
	"fmt"
	"image"
	"io"
	"net/http"
	"time"

	"github.com/gabriel-vasile/mimetype"
	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"github.com/tidwall/gjson"
	"maunium.net/go/mautrix/crypto/attachment"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"

	"github.com/beeper/imessage/imessage"
	"github.com/beeper/imessage/imessage/direct/util/httputil"
)

type BeeperLinkPreview struct {
	MatchedURL   string `json:"matched_url"`
	CanonicalURL string `json:"og:url,omitempty"`
	Title        string `json:"og:title,omitempty"`
	Type         string `json:"og:type,omitempty"`
	Description  string `json:"og:description,omitempty"`

	ImageURL        id.ContentURIString      `json:"og:image,omitempty"`
	ImageEncryption *event.EncryptedFileInfo `json:"beeper:image:encryption,omitempty"`

	ImageSize   int    `json:"matrix:image:size,omitempty"`
	ImageWidth  int    `json:"og:image:width,omitempty"`
	ImageHeight int    `json:"og:image:height,omitempty"`
	ImageType   string `json:"og:image:type,omitempty"`
}

func (mc *MessageConverter) convertURLPreviewToIMessage(ctx context.Context, evt *event.Event) (output *imessage.RichLinkMetadata) {
	rawPreview := gjson.GetBytes(evt.Content.VeryRaw, `com\.beeper\.linkpreviews`)
	if !rawPreview.Exists() || !rawPreview.IsArray() {
		return
	}
	var previews []BeeperLinkPreview
	if err := json.Unmarshal([]byte(rawPreview.Raw), &previews); err != nil || len(previews) == 0 {
		return
	}
	// iMessage only supports a single preview.
	preview := previews[0]
	if len(preview.MatchedURL) == 0 && len(preview.CanonicalURL) == 0 {
		return
	}

	output = &imessage.RichLinkMetadata{
		OriginalURL: preview.MatchedURL,
		URL:         preview.CanonicalURL,
		Title:       preview.Title,
		Summary:     preview.Description,
		ItemType:    preview.Type,
	}

	if output.URL == "" {
		output.URL = preview.MatchedURL
	} else if output.OriginalURL == "" {
		output.OriginalURL = preview.CanonicalURL
	}

	if preview.ImageURL != "" || preview.ImageEncryption != nil {
		output.Image = &imessage.RichLinkAsset{
			MimeType: preview.ImageType,
			Size: &imessage.RichLinkAssetSize{
				Width:  preview.ImageWidth,
				Height: preview.ImageHeight,
			},
			Source: &imessage.RichLinkAssetSource{},
		}

		var contentURI id.ContentURIString
		if preview.ImageURL == "" {
			contentURI = preview.ImageEncryption.URL
		} else {
			contentURI = preview.ImageURL
		}

		imgBytes, err := mc.DownloadMatrixMedia(ctx, contentURI)
		if err != nil {
			return
		}

		if preview.ImageEncryption != nil {
			err = preview.ImageEncryption.DecryptInPlace(imgBytes)
			if err != nil {
				return
			}
		}
		output.Image.Source.Data = imgBytes
	}
	return
}

func (mc *MessageConverter) ConvertRichLinkToBeeper(ctx context.Context, msgID uuid.UUID, richLink *imessage.RichLinkMetadata) (output *BeeperLinkPreview) {
	if richLink == nil {
		return
	}
	description := richLink.SelectedText
	if description == "" {
		description = richLink.Summary
	}

	output = &BeeperLinkPreview{
		MatchedURL:   richLink.OriginalURL,
		CanonicalURL: richLink.URL,
		Title:        richLink.Title,
		Description:  description,
	}

	if richLink.Image != nil {
		if richLink.Image.Size != nil {
			output.ImageWidth = int(richLink.Image.Size.Width)
			output.ImageHeight = int(richLink.Image.Size.Height)
		}
		output.ImageType = richLink.ItemType

		if richLink.Image.Source != nil {
			thumbnailData := richLink.Image.Source.Data
			if thumbnailData == nil {
				if url := richLink.Image.Source.URL; url != "" {
					ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
					defer cancel()
					req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
					if err != nil {
						return
					}
					resp, err := httputil.Media.Do(req)
					if err != nil {
						return
					}
					defer resp.Body.Close()
					thumbnailData, _ = io.ReadAll(resp.Body)
				}
			}

			if output.ImageHeight == 0 || output.ImageWidth == 0 {
				src, _, err := image.Decode(bytes.NewReader(thumbnailData))
				if err == nil {
					imageBounds := src.Bounds()
					output.ImageWidth, output.ImageHeight = imageBounds.Max.X, imageBounds.Max.Y
				}
			}

			output.ImageSize = len(thumbnailData)
			if output.ImageType == "" {
				output.ImageType = mimetype.Detect(thumbnailData).String()
			}

			uploadData, uploadMime := thumbnailData, output.ImageType
			var uploadFileName string
			if mc.GetData(ctx).Encrypted {
				crypto := attachment.NewEncryptedFile()
				crypto.EncryptInPlace(uploadData)
				uploadMime = "application/octet-stream"
				output.ImageEncryption = &event.EncryptedFileInfo{EncryptedFile: *crypto}
			} else {
				ext := ""
				if mime := mimetype.Lookup(output.ImageType); mime != nil {
					ext = mime.Extension()
				}
				uploadFileName = fmt.Sprintf("%s-urlpreview%s", msgID, ext)
			}
			mxc, err := mc.UploadMatrixMedia(ctx, uploadData, uploadFileName, uploadMime)
			if err != nil {
				zerolog.Ctx(ctx).Warn().Err(err).Msg("Failed to reupload thumbnail for link preview")
			} else {
				if output.ImageEncryption != nil {
					output.ImageEncryption.URL = mxc
				} else {
					output.ImageURL = mxc
				}
			}
		}

	}

	return
}
