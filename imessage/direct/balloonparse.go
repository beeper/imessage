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
	"context"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/rs/zerolog"
	"howett.net/plist"

	"github.com/beeper/imessage/imessage"
	"github.com/beeper/imessage/imessage/direct/util/gnuzip"
	"github.com/beeper/imessage/imessage/direct/util/httputil"
	"github.com/beeper/imessage/imessage/direct/util/nskeyedarchive"
)

func getKeyAsString(ctx context.Context, raw map[string]any, key string) string {
	if raw == nil {
		return ""
	}
	if val, ok := raw[key].(string); ok {
		return val
	} else {
		zerolog.Ctx(ctx).Debug().Str("key", key).Type("field_type", val).Msg("unexpected type for field")
		return ""
	}
}

func getRichLinkURL(ctx context.Context, urlMetadata any) (string, error) {
	if mapMeta, ok := urlMetadata.(map[string]any); !ok {
		return "", fmt.Errorf("URL metadata is not a map")
	} else {
		return getKeyAsString(ctx, mapMeta, "NS.relative"), nil
	}
}

var imageSizeRe = regexp.MustCompile(`\{(\d+),\s*(\d+)\}`)

func parseBalloonImageSize(imageSizeStr string) (int, int) {
	match := imageSizeRe.FindStringSubmatch(imageSizeStr)
	if len(match) != 3 {
		return 0, 0
	}
	width, _ := strconv.Atoi(match[1])
	height, _ := strconv.Atoi(match[2])
	return width, height
}

func parseBalloonImage(ctx context.Context, attachments [][]byte, richLinkMetadata map[string]any, key string) (*imessage.RichLinkAsset, error) {
	log := zerolog.Ctx(ctx)
	var asset *imessage.RichLinkAsset
	var err error
	if image, ok := richLinkMetadata[key]; ok {
		if imageMap, ok := image.(map[string]any); !ok {
			return nil, fmt.Errorf("unexpected type for richLinkMetadata.%s: %T", key, image)
		} else {
			asset = &imessage.RichLinkAsset{
				MimeType: getKeyAsString(ctx, imageMap, "MIMEType"),
				Source:   &imessage.RichLinkAssetSource{},
				Size:     &imessage.RichLinkAssetSize{},
			}
			if idx, ok := imageMap["richLinkImageAttachmentSubstituteIndex"].(uint64); ok && int(idx) < len(attachments) {
				log.Debug().Uint64("substitute_index", idx).Msg("Using substitute image from attachments array")
				asset.Source.Data = attachments[idx]
			}
		}
	}
	if imageMetadata, ok := richLinkMetadata[key+"Metadata"]; ok {
		if imageMap, ok := imageMetadata.(map[string]any); !ok {
			return nil, fmt.Errorf("unexpected type for richLinkMetadata.%sMetadata: %T", key, imageMetadata)
		} else {
			if asset == nil {
				asset = &imessage.RichLinkAsset{
					Source: &imessage.RichLinkAssetSource{},
					Size:   &imessage.RichLinkAssetSize{},
				}
			}
			asset.Source.URL, err = getRichLinkURL(ctx, imageMap["URL"])
			if err != nil {
				return nil, err
			}

			if asset.Source.Data == nil {
				log.Debug().Str("url", asset.Source.URL).Msg("Downloading image from URL")
				if req, err := http.NewRequestWithContext(ctx, http.MethodGet, asset.Source.URL, nil); err != nil {
					return nil, err
				} else if resp, err := httputil.Media.Do(req); err != nil {
					return nil, err
				} else {
					defer resp.Body.Close()
					if asset.Source.Data, err = io.ReadAll(resp.Body); err != nil {
						return nil, err
					}
				}
			}

			if width, height := parseBalloonImageSize(getKeyAsString(ctx, imageMap, "size")); width != 0 && height != 0 {
				asset.Size.Width = width
				asset.Size.Height = height
			}
		}
	}
	return asset, nil
}

func handleYouTubeBalloonData(ctx context.Context, data []byte) (string, error) {
	log := zerolog.Ctx(ctx)
	var metadata map[string]any
	var ok bool
	if payload, err := gnuzip.MaybeGUnzip(data); err != nil {
		log.Err(err).Msg("Failed to decompress balloon payload")
		return "", err
	} else if metadataRaw, err := nskeyedarchive.Parse(payload); err != nil {
		log.Err(err).Msg("failed to parse balloon payload as NSKeyedArchive")
		return "", err
	} else if metadata, ok = metadataRaw.(map[string]any); !ok {
		return "", fmt.Errorf("unexpected type for metadata: %T", metadataRaw)
	}

	url, err := getRichLinkURL(ctx, metadata["URL"])
	if err != nil {
		return "", err
	}

	if userInfo, exists := metadata["userInfo"]; !exists {
		return url, nil
	} else if userInfoMap, ok := userInfo.(map[string]any); !ok {
		return url, nil
	} else {
		var builder strings.Builder
		builder.WriteString(url)
		if caption := getKeyAsString(ctx, userInfoMap, "caption"); caption != "" {
			builder.WriteString("<br><br><b>")
			builder.WriteString(caption)
			builder.WriteString("</b>")
		}
		if subcaption := getKeyAsString(ctx, userInfoMap, "subcaption"); subcaption != "" {
			builder.WriteString("<br>")
			builder.WriteString(subcaption)
		}
		return builder.String(), nil
	}
}

func handleLinkBalloonData(ctx context.Context, data []byte) (*imessage.RichLinkMetadata, error) {
	log := zerolog.Ctx(ctx)
	var balloonPayload BalloonPayload
	var metadata map[string]any
	var ok bool
	if payload, err := gnuzip.MaybeGUnzip(data); err != nil {
		log.Err(err).Msg("Failed to decompress balloon payload")
		return nil, err
	} else if _, err := plist.Unmarshal(payload, &balloonPayload); err != nil {
		log.Err(err).Msg("failed to parse balloon payload")
		return nil, err
	} else if len(balloonPayload.Attachments) == 0 && balloonPayload.Payload == nil {
		// There are no attachments and the payload is nil, the payload isn't wrapped.
		if metadataRaw, err := nskeyedarchive.Parse(payload); err != nil {
			log.Err(err).Msg("failed to parse balloon payload as NSKeyedArchive")
			return nil, err
		} else if metadata, ok = metadataRaw.(map[string]any); !ok {
			return nil, fmt.Errorf("unexpected type for metadata: %T", metadataRaw)
		}
	} else if metadataRaw, err := nskeyedarchive.Parse(balloonPayload.Payload); err != nil {
		log.Err(err).Msg("failed to parse balloon payload as NSKeyedArchive")
		return nil, err
	} else if metadata, ok = metadataRaw.(map[string]any); !ok {
		return nil, fmt.Errorf("unexpected type for metadata: %T", metadataRaw)
	}

	// Check for rich link metadata
	if rlm, exists := metadata["richLinkMetadata"]; !exists {
		return nil, nil
	} else if rlmMap, ok := rlm.(map[string]any); !ok {
		return nil, fmt.Errorf("unexpected type for richLinkMetadata: %T", rlm)
	} else {
		var err error
		var richLink imessage.RichLinkMetadata

		richLink.URL, err = getRichLinkURL(ctx, rlmMap["URL"])
		if err != nil {
			return nil, err
		}
		richLink.OriginalURL, err = getRichLinkURL(ctx, rlmMap["originalURL"])
		if err != nil {
			return nil, err
		}

		richLink.Title = getKeyAsString(ctx, rlmMap, "title")
		richLink.Summary = getKeyAsString(ctx, rlmMap, "summary")
		richLink.SelectedText = getKeyAsString(ctx, rlmMap, "selectedText")

		// TODO itemType?

		// Icon
		richLink.Icon, err = parseBalloonImage(ctx, balloonPayload.Attachments, rlmMap, "icon")
		if err != nil {
			return nil, err
		}

		// Image
		richLink.Image, err = parseBalloonImage(ctx, balloonPayload.Attachments, rlmMap, "image")
		if err != nil {
			return nil, err
		}

		return &richLink, nil
	}
}
