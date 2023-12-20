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

package ids

import (
	"bytes"
	"context"
	"crypto/md5"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"go.mau.fi/util/random"
	"google.golang.org/protobuf/proto"
	"howett.net/plist"

	"github.com/beeper/imessage/imessage/direct/apns"
	"github.com/beeper/imessage/imessage/direct/ids/mmcsproto"
	"github.com/beeper/imessage/imessage/direct/ids/types"
	"github.com/beeper/imessage/imessage/direct/util/httputil"
	"github.com/beeper/imessage/imessage/direct/util/utitype"
)

func (u *User) UploadAttachment(ctx context.Context, data []byte, filename, mimeType string) (*UploadedAttachment, error) {
	log := zerolog.Ctx(ctx).With().
		Str("action", "upload attachment").
		Int("attachment_size", len(data)).
		Logger()
	ctx = log.WithContext(ctx)
	log.Debug().Msg("Preparing file upload")
	decryptionKey := generateMMCSKey()
	err := aes256CTR(data, decryptionKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	sig := encryptedMMCSSignature(data, 0x81)
	authorizePutReq, chunkMap := buildAuthorizePut(data, sig)
	resp, apnsResp, err := u.authorizePut(ctx, authorizePutReq, sig, len(data))
	if err != nil {
		if apnsResp != nil && apnsResp.ContentBody != nil {
			log.Debug().
				Str("authorize_put_response", base64.StdEncoding.EncodeToString(apnsResp.ContentBody)).
				Msg("DEBUG: Failed authorize put response")
		}
		return nil, fmt.Errorf("failed to authorize upload: %w", err)
	}

	log.Debug().
		Int("container_count", len(resp.Targets)).
		Int("chunk_count", len(authorizePutReq.Data.Chunks)).
		Msg("Prepared file upload")
	for i, target := range resp.Targets {
		log := log.With().Int("container_index", i).Logger()
		err = u.uploadChunk(log.WithContext(ctx), apnsResp.MMCSAuthURL, apnsResp.MMCSAuthID, target, chunkMap, resp.ConfirmData)
		if err != nil {
			log.Err(err).Any("target", target).Msg("DEBUG: Failed to upload container")
			if apnsResp.ContentBody != nil {
				log.Debug().
					Str("auth_url", apnsResp.MMCSAuthURL).
					Str("auth_id", apnsResp.MMCSAuthID).
					Str("auth_token", apnsResp.MMCSAuthToken).
					Str("authorize_put_response", base64.StdEncoding.EncodeToString(apnsResp.ContentBody)).
					Msg("DEBUG: Authorize put data of failed upload")
			}
			return nil, fmt.Errorf("failed to upload container #%d: %w", i+1, err)
		}
	}

	return &UploadedAttachment{
		Name:             filename,
		Width:            0,
		Height:           0,
		Datasize:         len(data),
		MimeType:         mimeType,
		UTIType:          utitype.MIME(mimeType),
		FileSize:         len(data),
		MessagePart:      0,
		MMCSSignatureHex: strings.ToUpper(hex.EncodeToString(sig)),
		MMCSURL:          fmt.Sprintf("%s/%s", apnsResp.MMCSAuthURL, apnsResp.MMCSAuthID),
		MMCSOwner:        apnsResp.MMCSAuthID,
		DecryptionKey:    strings.ToUpper(hex.EncodeToString(decryptionKey)),
	}, nil
}

type UploadChunk struct {
	OffsetInFile int64
	Size         int
}

type PreparedUpload struct {
	DecryptionKey []byte
	Signature     []byte
	TotalSize     int
	AuthRequest   *mmcsproto.AuthorizePut
	Chunks        map[[21]byte][]byte
}

const MaxChunkSize = 5 * 1024 * 1024

func buildAuthorizePut(encrypted []byte, signature []byte) (*mmcsproto.AuthorizePut, map[ChunkChecksum][]byte) {
	chunks := make([]*mmcsproto.AuthorizePut_PutData_Chunk, 0, len(encrypted)/MaxChunkSize)
	chunkMap := make(map[ChunkChecksum][]byte, cap(chunks))
	for i := 0; i < len(encrypted); i += MaxChunkSize {
		chunkSize := MaxChunkSize
		if i+chunkSize > len(encrypted) {
			chunkSize = len(encrypted) - i
		}
		data := encrypted[i : i+chunkSize]
		chunkSignature := chunkMMCSSignature(data)

		chunks = append(chunks, &mmcsproto.AuthorizePut_PutData_Chunk{
			Sig:  chunkSignature[:],
			Size: uint32(chunkSize),
		})
		chunkMap[chunkSignature] = data
	}

	return &mmcsproto.AuthorizePut{
		Data: &mmcsproto.AuthorizePut_PutData{
			Sig:    signature,
			Token:  "",
			Chunks: chunks,
			Footer: &mmcsproto.AuthorizePut_PutData_Footer{
				ChunkCount:  uint32(len(chunks)),
				ProfileType: "kCKProfileTypeFixed",
				F103:        0,
			},
		},
		F3: 81,
	}, chunkMap
}

func (u *User) authorizePut(ctx context.Context, req *mmcsproto.AuthorizePut, sig []byte, encryptedLength int) (*mmcsproto.AuthorizePutResponse, *apns.SendMessagePayload, error) {
	reqBytes, err := proto.Marshal(req)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal request protobuf: %w", err)
	}
	msgID := random.Bytes(4)
	msg := &apns.SendMessagePayload{
		Command:   apns.MessageTypeMMCSUpload,
		Version:   8,
		UserAgent: u.Versions.CombinedVersion(),
		MessageID: binary.BigEndian.Uint32(msgID),

		MMCSFileSignature: sig,
		MMCSFileLength:    encryptedLength,

		ContentVersion: 2,
		ContentHeaders: makeMMCSHeaders(u.Versions),
		ContentBody:    reqBytes,
	}
	commandBodyBytes, err := plist.Marshal(msg, plist.BinaryFormat)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	respChan := u.Conn.WaitResponseID(msg.MessageID)
	err = u.Conn.SendMessage(apns.TopicMadrid, commandBodyBytes, msgID)
	if err != nil {
		u.Conn.CancelResponseID(msg.MessageID)
		return nil, nil, fmt.Errorf("failed to send request: %w", err)
	}
	select {
	case respDat := <-respChan:
		if respDat.ResponseStatus != types.IDSStatusSuccess {
			return nil, nil, fmt.Errorf("request returned error: %w", types.IDSError{ErrorCode: respDat.ResponseStatus})
		}
		var mmcsData mmcsproto.AuthorizePutResponse
		err = proto.Unmarshal(respDat.ContentBody, &mmcsData)
		if err != nil {
			return nil, respDat, fmt.Errorf("failed to unmarshal response: %w", err)
		}
		return &mmcsData, respDat, nil
	case <-time.After(1 * time.Minute):
		u.Conn.CancelResponseID(msg.MessageID)
		return nil, nil, errors.New("timed out waiting for response")
	case <-ctx.Done():
		u.Conn.CancelResponseID(msg.MessageID)
		return nil, nil, ctx.Err()
	}
}

type UploadedAttachment struct {
	Name             string `xml:"name,attr,omitempty"`
	Width            int    `xml:"width,attr"`
	Height           int    `xml:"height,attr"`
	Datasize         int    `xml:"datasize,attr,omitempty"`
	MimeType         string `xml:"mime-type,attr,omitempty"`
	UTIType          string `xml:"uti-type,attr,omitempty"`
	FileSize         int    `xml:"file-size,attr,omitempty"`
	MessagePart      int    `xml:"message-part,attr"` // don't omitempty, as we always require this, even if 0
	MMCSSignatureHex string `xml:"mmcs-signature-hex,attr,omitempty"`
	MMCSURL          string `xml:"mmcs-url,attr,omitempty"`
	MMCSOwner        string `xml:"mmcs-owner,attr,omitempty"`
	DecryptionKey    string `xml:"decryption-key,attr,omitempty"`
	InlineAttachment string `xml:"inline-attachment,attr,omitempty"`
}

func (u *User) uploadChunk(
	ctx context.Context,
	authURL, authID string,
	target *mmcsproto.AuthorizePutResponse_UploadTarget,
	chunkMap map[ChunkChecksum][]byte,
	confirmData []byte,
) error {
	var putCompleteAtEdge bool
	for _, header := range target.GetRequest().GetHeaders() {
		if header.GetName() == putCompleteAtEdgeHeader {
			if header.GetValue() == "2" {
				putCompleteAtEdge = true
			} else {
				return fmt.Errorf("unsupported x-apple-put-complete-at-edge-version %s", header.GetValue())
			}
		}
	}

	hasher := md5.New()
	chunkDatas := make([][]byte, len(target.Chunks), len(target.Chunks)+1)
	totalLength := 0
	for i, targetChunk := range target.Chunks {
		chunkIDBytes := targetChunk.GetChunkId()
		if len(chunkIDBytes) != ChunkChecksumLength {
			return fmt.Errorf("target chunk #%d ID is %d bytes (%x), expected %d", i+1, len(chunkIDBytes), chunkIDBytes, ChunkChecksumLength)
		}
		chunkData, ok := chunkMap[*(*ChunkChecksum)(chunkIDBytes)]
		if !ok {
			return fmt.Errorf("couldn't find target chunk #%d (%x)", i+1, chunkIDBytes)
		}
		chunkDatas[i] = chunkData
		hasher.Write(chunkData)
		totalLength += len(chunkData)
	}
	md5Sum := hasher.Sum(nil)
	if putCompleteAtEdge {
		putFooter, err := proto.Marshal(&mmcsproto.PutFooter{
			Md5Sum:      md5Sum,
			ConfirmData: confirmData,
		})
		if err != nil {
			return fmt.Errorf("failed to marshal put footer: %w", err)
		}
		putFooterWithLength := make([]byte, 4+len(putFooter))
		binary.BigEndian.PutUint32(putFooterWithLength, uint32(len(putFooter)))
		copy(putFooterWithLength[4:], putFooter)
		chunkDatas = append(chunkDatas, putFooterWithLength)
		totalLength += len(putFooterWithLength)
	}
	log := zerolog.Ctx(ctx).With().
		Int("upload_size", totalLength).
		Int("chunk_count", len(target.Chunks)).
		Bool("put_complete_at_edge", putCompleteAtEdge).
		Logger()
	ctx = log.WithContext(ctx)

	httpReq, err := httputil.PrepareCustom(ctx, target.Request.Method, getContainerURL(target.Request), func() (io.ReadCloser, error) {
		readers := make([]io.Reader, len(chunkDatas))
		for i, chunkData := range chunkDatas {
			readers[i] = bytes.NewReader(chunkData)
		}
		return io.NopCloser(io.MultiReader(readers...)), nil
	})
	if err != nil {
		return fmt.Errorf("failed to prepare request: %w", err)
	}

	httpReq.Header.Set(appleRequestUUIDHeader, strings.ToUpper(uuid.New().String()))
	httpReq.Header.Set("User-Agent", u.Versions.IMTransferUserAgent())
	for _, header := range target.Request.Headers {
		httpReq.Header.Set(header.Name, header.Value)
	}
	httpReq.Host = httpReq.Header.Get("Host")
	if !putCompleteAtEdge {
		if httpReq.Header.Get("Content-Length") != strconv.Itoa(totalLength) {
			log.Warn().
				Str("content_length_header", httpReq.Header.Get("Content-Length")).
				Msg("Content-Length header doesn't match total upload size")
		}
		httpReq.ContentLength = int64(totalLength)
	}
	httpReq.Header.Del("Content-Length")

	log.Debug().Str("target_url", httpReq.URL.String()).Msg("Uploading container")
	httpResp, respData, err := httputil.Do(httputil.Media, httpReq)
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	} else if httpResp.StatusCode != http.StatusOK {
		log.Debug().
			Int("status_code", httpResp.StatusCode).
			Str("failed_upload_response_data", base64.StdEncoding.EncodeToString(respData)).
			Msg("DEBUG: Response data of failed upload")
		return fmt.Errorf("unexpected HTTP status %d", httpResp.StatusCode)
	} else if putCompleteAtEdge {
		if httpResp.Header.Get("X-Apple-Put-Complete-Response") != "true" {
			return errors.New("response headers didn't contain X-Apple-Put-Complete-Response=true")
		}
	} else {
		log.Debug().Msg("Uploading container complete, sending putComplete request")
		return u.putComplete(
			ctx,
			httpReq.URL.String(), authURL, authID, httpResp.Header.Get("ETag"), httpResp.Header.Get("x-apple-edge-info"),
			totalLength, httpResp.StatusCode, md5Sum, confirmData, target,
		)
	}
	return nil
}

func (u *User) putComplete(
	ctx context.Context,
	reqURL, authURL, authID, etag, edgeInfo string,
	totalLength, statusCode int,
	md5Sum, confirmData []byte,
	target *mmcsproto.AuthorizePutResponse_UploadTarget,
) error {
	confirmResponse := mmcsproto.ConfirmResponse_Request{
		Url:    reqURL,
		Status: uint32(statusCode),
		EdgeInfo: []*mmcsproto.ConfirmResponse_Request_Metric{
			{
				N: "Etag",
				V: etag,
			},
		},
		Md5Sum:   md5Sum,
		Metrics:  []*mmcsproto.ConfirmResponse_Request_Metric{},
		Metrics2: []*mmcsproto.ConfirmResponse_Request_Metric{},
		Token:    target.ClAuthP2,
		F13:      0,
	}
	if edgeInfo != "" {
		confirmResponse.EdgeInfo = append(confirmResponse.EdgeInfo, &mmcsproto.ConfirmResponse_Request_Metric{
			N: "x-apple-edge-info",
			V: edgeInfo,
		})
	}

	confirmation, err := proto.Marshal(&mmcsproto.ConfirmResponse{
		Inner: []*mmcsproto.ConfirmResponse_Request{
			&confirmResponse,
		},
		ConfirmData: confirmData,
	})
	if err != nil {
		return fmt.Errorf("failed to marshal putComplete request: %w", err)
	}

	putCompleteURL := fmt.Sprintf("%s/%s/putComplete", authURL, authID)
	putCompleteAuth := fmt.Sprintf("%s %d %s", target.ClAuthP1, totalLength, target.ClAuthP2)
	putCompleteReq, err := httputil.Prepare(ctx, http.MethodPost, putCompleteURL, confirmation)
	if err != nil {
		return fmt.Errorf("failed to prepare putComplete request: %w", err)
	}
	//for _, header := range target.GetRequest().GetF12() {
	//	putCompleteReq.Header.Set(header.GetName(), header.GetValue())
	//}

	addHeaders(putCompleteReq.Header, u.Versions, putCompleteAuth, authID)

	putCompleteResp, respDat, err := httputil.Do(httputil.Normal, putCompleteReq)
	if err != nil {
		return fmt.Errorf("failed to send putComplete request: %w", err)
	}
	logFailedData := func() {
		zerolog.Ctx(ctx).Debug().
			Str("md5_sum", base64.StdEncoding.EncodeToString(md5Sum)).
			Str("put_complete_response_data", base64.StdEncoding.EncodeToString(respDat)).
			Str("put_complete_request_data", base64.StdEncoding.EncodeToString(confirmation)).
			Str("put_complete_auth", putCompleteAuth).
			Msg("DEBUG: Failed putComplete response data")
	}
	if putCompleteResp.StatusCode != http.StatusOK {
		logFailedData()
		return fmt.Errorf("unexpected HTTP status %d in putComplete response", putCompleteResp.StatusCode)
	}
	var resp mmcsproto.PutCompleteResponse
	err = proto.Unmarshal(respDat, &resp)
	if err != nil {
		logFailedData()
		return fmt.Errorf("failed to unmarshal putComplete response: %w", err)
	} else if resp.GetF1().GetInfo().GetMessage() != "" {
		logFailedData()
		return fmt.Errorf("putComplete failed: %d: %s", resp.GetF1().GetInfo().GetCode(), resp.GetF1().GetInfo().GetMessage())
	}
	return nil
}
