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
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"io"
	"net/http"
	"os"
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
	"github.com/beeper/imessage/imessage/direct/util/fallocate"
	"github.com/beeper/imessage/imessage/direct/util/httputil"
)

func (u *User) DownloadAttachment(ctx context.Context, url, ownerID string, sig, decryptionKey []byte) ([]byte, error) {
	return NewAttachmentDownloader(url, ownerID, sig, decryptionKey).DownloadMemory(ctx, u)
}

type AttachmentDownloader struct {
	URL           string
	OwnerID       string
	Signature     []byte
	DecryptionKey []byte

	MD      *MMCSDownloader
	RawData []byte
}

func NewAttachmentDownloader(url, ownerID string, signature, decryptionKey []byte) *AttachmentDownloader {
	return &AttachmentDownloader{
		URL:           url,
		OwnerID:       ownerID,
		Signature:     signature,
		DecryptionKey: decryptionKey,
	}
}

func (ad *AttachmentDownloader) Prepare(ctx context.Context, u *User) error {
	if ad.MD != nil && time.Until(ad.MD.Expiry) > 10*time.Minute {
		zerolog.Ctx(ctx).Trace().
			Str("attachment_object_id", ad.OwnerID).
			Msg("Not re-fetching attachment metadata as it's already cached")
		return nil
	}
	getResp, respDat, authID, err := u.authorizeGet(ctx, ad.URL, ad.OwnerID, ad.Signature)
	if err != nil {
		if errors.Is(err, types.IDSError{ErrorCode: types.IDSStatusMissingRequiredKey}) {
			zerolog.Ctx(ctx).Debug().
				Str("url", ad.URL).
				Str("owner_id", ad.OwnerID).
				Str("signature", base64.StdEncoding.EncodeToString(ad.Signature)).
				Msg("DEBUG: data of download that failed with MissingRequiredKey")
		}
		return fmt.Errorf("failed to authorize download: %w", err)
	} else if errorInfo := getResp.GetError().GetInfo(); errorInfo != nil {
		if getResp.GetData() == nil {
			return fmt.Errorf("server returned error: %d: %s", errorInfo.GetCode(), errorInfo.GetMessage())
		}
		zerolog.Ctx(ctx).Warn().
			Any("error_data", errorInfo).
			Msg("Server returned error in authorize get response, but also some data")
	}
	zerolog.Ctx(ctx).Trace().
		Str("attachment_object_id", ad.OwnerID).
		Msg("Parsing attachment metadata")
	md, err := ParseMMCSAuthorizeGetResponse(getResp, authID, ad.Signature, ad.DecryptionKey)
	if err != nil {
		return fmt.Errorf("failed to parse attachment metadata: %w", err)
	}
	ad.RawData = respDat
	ad.MD = md
	return nil
}

func (u *User) authorizeGet(ctx context.Context, url, ownerID string, sig []byte) (*mmcsproto.AuthorizeGetResponse, []byte, string, error) {
	messageID := random.Bytes(4)
	req := &apns.SendMessagePayload{
		Command:   apns.MessageTypeMMCSDownload,
		Version:   8,
		UserAgent: u.Versions.CombinedVersion(),
		MessageID: binary.BigEndian.Uint32(messageID),

		ContentVersion: 2,
		ContentHeaders: makeMMCSHeaders(u.Versions),

		MMCSFileSignature: sig,
		// This is a bit weird
		MMCSAuthURL: strings.ReplaceAll(url, "/"+ownerID, ""),
		MMCSOwnerID: ownerID,
	}

	zerolog.Ctx(ctx).Trace().Any("req", req).Msg("Requesting attachment metadata")
	commandBodyBytes, err := plist.Marshal(req, plist.BinaryFormat)
	if err != nil {
		return nil, nil, "", fmt.Errorf("failed to marshal request: %w", err)
	}

	respChan := u.Conn.WaitResponseID(req.MessageID)
	err = u.Conn.SendMessage(apns.TopicMadrid, commandBodyBytes, messageID)
	if err != nil {
		u.Conn.CancelResponseID(req.MessageID)
		return nil, nil, "", fmt.Errorf("failed to send request: %w", err)
	}
	select {
	case respDat := <-respChan:
		if respDat.ResponseStatus != types.IDSStatusSuccess {
			return nil, nil, "", fmt.Errorf("request returned error: %w", types.IDSError{ErrorCode: respDat.ResponseStatus})
		}
		var mmcsData mmcsproto.AuthorizeGetResponse
		err = proto.Unmarshal(respDat.ContentBody, &mmcsData)
		if err != nil {
			return nil, respDat.ContentBody, "", fmt.Errorf("failed to unmarshal response: %w", err)
		}
		return &mmcsData, respDat.ContentBody, respDat.MMCSAuthID, err
	case <-time.After(1 * time.Minute):
		u.Conn.CancelResponseID(req.MessageID)
		return nil, nil, "", errors.New("timed out waiting for response")
	case <-ctx.Done():
		u.Conn.CancelResponseID(req.MessageID)
		return nil, nil, "", ctx.Err()
	}
}

func (ad *AttachmentDownloader) GetFileSize() int {
	if ad.MD == nil {
		panic(errors.New("GetFileSize called before Prepare"))
	}
	return ad.MD.TotalSize
}

func (ad *AttachmentDownloader) DownloadMemory(ctx context.Context, u *User) ([]byte, error) {
	ctx = zerolog.Ctx(ctx).With().
		Str("action", "download attachment to memory").
		Str("attachment_object_id", ad.OwnerID).
		Logger().
		WithContext(ctx)
	var prog DownloadProgress
	err := ad.Prepare(ctx, u)
	if err != nil {
		return nil, err
	}
	mem := &inMemoryAttachmentStore{
		data: make([]byte, ad.MD.TotalSize),
	}
	prog.Prepared = true
	prog.Size = ad.MD.TotalSize
	err = ad.MD.DownloadAndDecrypt(ctx, &prog, u.Versions, mem, ad.URL)
	if err != nil {
		if ad.RawData != nil && ctx.Err() == nil {
			zerolog.Ctx(ctx).Debug().
				Str("authorize_get_response", base64.StdEncoding.EncodeToString(ad.RawData)).
				Msg("DEBUG: Authorize get data of failed download")
		}
		return nil, err
	}
	return mem.data, nil
}

type DownloadProgress struct {
	Prepared        bool `json:"prepared"`
	Allocated       bool `json:"allocated"`
	GetCompleted    bool `json:"get_completed"`
	DownloadedBytes int  `json:"downloaded_bytes"`
	DecryptedBytes  int  `json:"decrypted_bytes"`
	Size            int  `json:"total_bytes"`

	callback func(*DownloadProgress, bool)
}

func (dp *DownloadProgress) callCallback(save bool) {
	if dp != nil && dp.callback != nil {
		dp.callback(dp, save)
	}
}

func (dp *DownloadProgress) Percent() float64 {
	if dp == nil {
		return 0
	}
	// 0-4: file metadata fetching
	// 4-5: disk allocation
	// 5-75: download
	// 75-95: decryption
	// 95-99: get complete
	// 99-100: rename to destination
	if !dp.Prepared {
		return 0
	} else if !dp.Allocated {
		return 4
	} else if dp.DownloadedBytes < dp.Size {
		return 5 + float64(dp.DownloadedBytes)/float64(dp.Size)*70
	} else if dp.DecryptedBytes < dp.Size {
		return 75 + float64(dp.DecryptedBytes)/float64(dp.Size)*20
	} else if !dp.GetCompleted {
		return 95
	} else {
		return 99
	}
}

func (ad *AttachmentDownloader) DownloadFile(ctx context.Context, u *User, path string, progressFunc func(progress *DownloadProgress, save bool)) error {
	ctx = zerolog.Ctx(ctx).With().
		Str("action", "download attachment to file").
		Str("output_path", path).
		Str("attachment_object_id", ad.OwnerID).
		Logger().
		WithContext(ctx)
	var prog DownloadProgress
	prog.callback = progressFunc
	prog.callCallback(false)
	err := ad.Prepare(ctx, u)
	if err != nil {
		return err
	}
	prog.Prepared = true
	prog.Size = ad.MD.TotalSize
	prog.callCallback(true)
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return fmt.Errorf("failed to open file: %w", err)
	}
	defer func() {
		closeErr := file.Close()
		if closeErr != nil {
			zerolog.Ctx(ctx).Warn().Err(closeErr).Msg("Failed to close file")
		}
	}()
	err = fallocate.Fallocate(file, ad.MD.TotalSize)
	if err != nil {
		if errors.Is(err, fallocate.ErrOutOfSpace) {
			return fmt.Errorf("failed to allocate space for file: %w", err)
		}
		zerolog.Ctx(ctx).Warn().Err(err).Msg("Failed to allocate space for file")
	}
	prog.Allocated = true
	prog.callCallback(false)
	err = ad.MD.DownloadAndDecrypt(ctx, &prog, u.Versions, file, ad.URL)
	if err != nil {
		if ad.RawData != nil && ctx.Err() == nil {
			zerolog.Ctx(ctx).Debug().
				Str("authorize_get_response", base64.StdEncoding.EncodeToString(ad.RawData)).
				Msg("DEBUG: Authorize get data of failed download")
		}
		return err
	}
	return nil
}

type inMemoryAttachmentStore struct {
	data    []byte
	readPtr int
}

func (i *inMemoryAttachmentStore) Read(p []byte) (n int, err error) {
	if i.readPtr >= len(i.data) {
		return 0, io.EOF
	}
	n = copy(p, i.data[i.readPtr:])
	i.readPtr += n
	return
}

func (i *inMemoryAttachmentStore) ReadAt(p []byte, off int64) (n int, err error) {
	if off >= int64(len(i.data)) {
		return 0, io.EOF
	}
	n = copy(p, i.data[off:])
	if n < len(p) {
		err = io.EOF
	}
	return
}

func (i *inMemoryAttachmentStore) WriteAt(p []byte, off int64) (n int, err error) {
	n = copy(i.data[off:], p)
	if n < len(p) {
		err = io.ErrShortWrite
	}
	return
}

type MMCSDownloader struct {
	AuthID string

	Signature     []byte
	DecryptionKey []byte

	TotalSize     int
	Containers    []*DownloadContainer
	Confirmations []*mmcsproto.ConfirmResponse_Request
	Expiry        time.Time
}

type DownloadContainer struct {
	Downloaded bool
	Chunks     []DownloadChunk
	Request    *mmcsproto.HTTPRequest
	CLAuthP1   string
	CLAuthP2   string
}

const ChunkChecksumLength = 21

type ChunkChecksum [ChunkChecksumLength]byte

type DownloadChunk struct {
	Downloaded bool

	Checksum ChunkChecksum
	// Size is the number of bytes in this chunk.
	Size int
	// Offset is the byte offset from the start of the container containing this chunk.
	Offset int
	// OffsetInFile is the byte offset of this chunk from the start of the entire file.
	OffsetInFile int64
}

func ParseMMCSAuthorizeGetResponse(auth *mmcsproto.AuthorizeGetResponse, authID string, signature, decryptionKey []byte) (*MMCSDownloader, error) {
	containers := auth.GetData().GetContainers()
	md := &MMCSDownloader{
		AuthID:        authID,
		Signature:     signature,
		DecryptionKey: decryptionKey,
		Containers:    make([]*DownloadContainer, len(containers)),
		Confirmations: make([]*mmcsproto.ConfirmResponse_Request, 0, len(containers)),
	}
	containerChunks := make([][]DownloadChunk, len(containers))
	for i, part := range containers {
		expiry := time.UnixMilli(int64(part.GetRequest().GetExpiryTimeMillis()))
		if md.Expiry.IsZero() || md.Expiry.After(expiry) {
			md.Expiry = expiry
		}
		md.Containers[i] = &DownloadContainer{
			Chunks:   make([]DownloadChunk, 0, len(part.GetChunks())),
			CLAuthP1: part.GetClAuthP1(),
			CLAuthP2: part.GetClAuthP2(),
			Request:  part.GetRequest(),
		}
		containerChunks[i] = make([]DownloadChunk, len(part.GetChunks()))
		for j, chunk := range part.GetChunks() {
			checksum := chunk.GetMeta().GetChecksum()
			if len(checksum) != ChunkChecksumLength {
				return nil, fmt.Errorf("chunk #%d in container #%d has unexpected checksum length %d (expected %d)", j+1, i+1, len(checksum), ChunkChecksumLength)
			}
			wrappedChunk := DownloadChunk{
				Checksum: *(*ChunkChecksum)(checksum),
				Offset:   int(chunk.GetMeta().GetOffset()),
				Size:     int(chunk.GetMeta().GetSize()),
			}
			containerChunks[i][j] = wrappedChunk
		}
	}
	for i, ref := range auth.GetData().GetReferences().GetChunkReferences() {
		if len(containerChunks) < int(ref.GetContainerIndex()) {
			return nil, fmt.Errorf("chunk reference #%d points at chunk #%d in non-existent container #%d", i+1, ref.GetChunkIndex()+1, ref.GetContainerIndex()+1)
		} else if len(containerChunks[ref.GetContainerIndex()]) < int(ref.GetChunkIndex()) {
			return nil, fmt.Errorf("chunk reference #%d points at non-existent chunk #%d in container #%d", i+1, ref.GetChunkIndex()+1, ref.GetContainerIndex()+1)
		}
		wrappedChunk := containerChunks[ref.GetContainerIndex()][ref.GetChunkIndex()]
		wrappedChunk.OffsetInFile = int64(md.TotalSize)
		md.TotalSize += wrappedChunk.Size

		container := md.Containers[ref.GetContainerIndex()]
		container.Chunks = append(container.Chunks, wrappedChunk)
	}
	return md, nil
}

type ReadWriterAt interface {
	io.Reader
	io.WriterAt
}

func (md *MMCSDownloader) DownloadAndDecrypt(ctx context.Context, prog *DownloadProgress, ua Versions, into ReadWriterAt, authURL string) error {
	err := md.Download(ctx, prog, ua, into)
	if err != nil {
		return fmt.Errorf("failed to download file: %w", err)
	}
	err = md.Decrypt(ctx, prog, into)
	if err != nil {
		return fmt.Errorf("failed to decrypt file: %w", err)
	}
	resp, err := md.SendGetComplete(ctx, ua, authURL)
	if err != nil {
		zerolog.Ctx(ctx).Warn().Err(err).Msg("Failed to send getComplete request for attachment download")
	} else if resp.StatusCode >= 400 {
		zerolog.Ctx(ctx).Warn().Int("status", resp.StatusCode).Msg("Got non-OK status for getComplete request")
	} else {
		zerolog.Ctx(ctx).Debug().Int("status", resp.StatusCode).Msg("Sent getComplete request for attachment download")
	}
	prog.GetCompleted = true
	prog.callCallback(false)
	return nil
}

const downloadInChunks = true

func (md *MMCSDownloader) Download(ctx context.Context, prog *DownloadProgress, ua Versions, into io.WriterAt) error {
	for i, container := range md.Containers {
		if container.Downloaded {
			for _, chunk := range container.Chunks {
				prog.DownloadedBytes += chunk.Size
			}
			prog.callCallback(false)
			continue
		}
		if downloadInChunks {
			for j, chunk := range container.Chunks {
				ctx = zerolog.Ctx(ctx).With().
					Int("container_index", i).
					Int("chunk_index", j).
					Int("chunk_count", len(container.Chunks)).
					Int("chunk_size", chunk.Size).
					Logger().WithContext(ctx)
				if chunk.Downloaded {
					prog.DownloadedBytes += chunk.Size
					prog.callCallback(false)
					continue
				}
				confirmation, err := container.DownloadAndWriteChunk(ctx, prog, ua, &chunk, into)
				if err != nil {
					return fmt.Errorf("failed to download chunk #%d in container #%d: %w", i+1, j+1, err)
				}
				md.Confirmations = append(md.Confirmations, confirmation)
				chunk.Downloaded = true
				// The last chunk will get a callback at the end of this function
				if j < len(container.Chunks)-1 {
					prog.callCallback(true)
				}
			}
		} else {
			ctx = zerolog.Ctx(ctx).With().
				Int("container_index", i).
				Int("chunk_count", len(container.Chunks)).
				Logger().WithContext(ctx)
			confirmation, data, err := container.Download(ctx, ua)
			if err != nil {
				return fmt.Errorf("failed to download container #%d: %w", i+1, err)
			}
			err = container.Write(ctx, data, into)
			if err != nil {
				return fmt.Errorf("failed to write container #%d: %w", i+1, err)
			}
			md.Confirmations = append(md.Confirmations, confirmation)
			for _, chunk := range container.Chunks {
				chunk.Downloaded = true
				prog.DownloadedBytes += chunk.Size
			}
		}
		container.Downloaded = true
		prog.callCallback(true)
	}
	return nil
}

func (dc *DownloadContainer) Download(ctx context.Context, ua Versions) (*mmcsproto.ConfirmResponse_Request, []byte, error) {
	chunkURL := getContainerURL(dc.Request)

	req, err := httputil.Prepare(ctx, http.MethodGet, chunkURL, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to prepare get container request: %w", err)
	}
	req.Header.Set(appleRequestUUIDHeader, strings.ToUpper(uuid.New().String()))
	req.Header.Set("User-Agent", ua.IMTransferUserAgent())
	for _, header := range dc.Request.Headers {
		req.Header.Set(header.Name, header.Value)
	}
	req.Host = req.Header.Get("Host")
	zerolog.Ctx(ctx).Trace().Msg("Downloading container")
	resp, respBody, err := httputil.Do(httputil.Media, req)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get container: %w", err)
	} else if resp.StatusCode >= 400 {
		return nil, nil, fmt.Errorf("unexpected HTTP status code %d", resp.StatusCode)
	}
	return &mmcsproto.ConfirmResponse_Request{
		Url:    chunkURL,
		Status: uint32(resp.StatusCode),
		EdgeInfo: []*mmcsproto.ConfirmResponse_Request_Metric{
			{N: "x-apple-edge-info", V: resp.Header.Get("x-apple-edge-info")},
		},
		Token: dc.CLAuthP2,
		F13:   0,
	}, respBody, nil
}

type chunkDownloader struct {
	into       io.WriterAt
	offset     int64
	pointer    int64
	prog       *DownloadProgress
	downloaded int
	hasher     hash.Hash

	bytesUntilCallback int
}

const defaultBytesUntilCallback = 256 * 1024

func (cd *chunkDownloader) Write(data []byte) (int, error) {
	cd.downloaded += len(data)
	cd.prog.DownloadedBytes += len(data)
	cd.bytesUntilCallback -= len(data)
	if cd.bytesUntilCallback <= 0 {
		cd.prog.callCallback(false)
		cd.bytesUntilCallback = defaultBytesUntilCallback
	}
	cd.hasher.Write(data)
	n, err := cd.into.WriteAt(data, cd.offset+cd.pointer)
	cd.pointer += int64(n)
	return n, err
}

func (cd *chunkDownloader) Seek(offset int64, whence int) (int64, error) {
	if whence != io.SeekStart {
		return 0, fmt.Errorf("unsupported whence %d", whence)
	} else if offset != 0 {
		return 0, fmt.Errorf("unsupported offset %d", offset)
	}
	cd.prog.DownloadedBytes -= cd.downloaded
	cd.downloaded = 0
	cd.pointer = 0
	cd.hasher.Reset()
	cd.prog.callCallback(false)
	return 0, nil
}

func (cd *chunkDownloader) AcceptStatus(status int) bool {
	return status == http.StatusOK || status == http.StatusPartialContent
}

func (dc *DownloadContainer) DownloadAndWriteChunk(ctx context.Context, prog *DownloadProgress, ua Versions, chunk *DownloadChunk, into io.WriterAt) (*mmcsproto.ConfirmResponse_Request, error) {
	chunkURL := getContainerURL(dc.Request)

	rangeHeader := fmt.Sprintf("bytes=%d-%d", chunk.Offset, chunk.Offset+chunk.Size-1)
	log := zerolog.Ctx(ctx).With().Str("range_header", rangeHeader).Logger()
	ctx = log.WithContext(ctx)

	req, err := httputil.Prepare(ctx, http.MethodGet, chunkURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to prepare get container request: %w", err)
	}
	req.Header.Set(appleRequestUUIDHeader, strings.ToUpper(uuid.New().String()))
	req.Header.Set("User-Agent", ua.IMTransferUserAgent())
	for _, header := range dc.Request.Headers {
		req.Header.Set(header.Name, header.Value)
	}
	req.Host = req.Header.Get("Host")
	req.Header.Set("Range", rangeHeader)
	writer := &chunkDownloader{
		into:   into,
		offset: chunk.OffsetInFile,
		prog:   prog,
		hasher: sha256.New(),

		bytesUntilCallback: defaultBytesUntilCallback,
	}
	log.Trace().Msg("Downloading chunk")
	resp, errorRespData, err := httputil.DoCustomOutput(httputil.Media, req, writer)
	if err != nil {
		return nil, fmt.Errorf("failed to get container: %w", err)
	} else if resp.StatusCode >= 400 {
		if len(errorRespData) < 16384 {
			log.Debug().
				Int("status_code", resp.StatusCode).
				Str("failed_upload_response_data", base64.StdEncoding.EncodeToString(errorRespData)).
				Msg("DEBUG: Response data of failed upload")
		} else {
			log.Debug().
				Int("status_code", resp.StatusCode).
				Str("failed_upload_response_data", base64.StdEncoding.EncodeToString(errorRespData[:8192])).
				Msg("DEBUG: Response data of failed upload (partial)")
		}
		return nil, fmt.Errorf("unexpected HTTP status code %d", resp.StatusCode)
	} else if chunkMMCSSignatureFromHash(writer.hasher.Sum(nil)) != chunk.Checksum {
		return nil, fmt.Errorf("checksum mismatch")
	}
	return &mmcsproto.ConfirmResponse_Request{
		Url:    chunkURL,
		Status: uint32(resp.StatusCode),
		EdgeInfo: []*mmcsproto.ConfirmResponse_Request_Metric{
			{N: "x-apple-edge-info", V: resp.Header.Get("x-apple-edge-info")},
		},
		Token: dc.CLAuthP2,
		F13:   0,
	}, nil
}

func (dc *DownloadContainer) Write(ctx context.Context, data []byte, into io.WriterAt) error {
	for i, chunk := range dc.Chunks {
		if chunk.Offset+chunk.Size > len(data) {
			return fmt.Errorf("chunk #%d is too large (chunk start: %d, chunk size: %d, container size: %d)", i+1, chunk.Offset, chunk.Size, len(data))
		}
		chunkData := data[chunk.Offset : chunk.Offset+chunk.Size]
		if chunkMMCSSignature(chunkData) != chunk.Checksum {
			return fmt.Errorf("checksum mismatch in chunk #%d", i+1)
		}
		zerolog.Ctx(ctx).Trace().
			Int("chunk_index", i).
			Int("chunk_size", len(chunkData)).
			Int64("file_offset", chunk.OffsetInFile).
			Msg("Writing chunk")
		_, err := into.WriteAt(chunkData, int64(chunk.OffsetInFile))
		if err != nil {
			return fmt.Errorf("failed to write chunk #%d (%d bytes): %w", i+1, len(chunkData), err)
		}
	}
	return nil
}

func (md *MMCSDownloader) Decrypt(ctx context.Context, prog *DownloadProgress, file ReadWriterAt) error {
	if md.DecryptionKey == nil {
		hasher := sha1.New()
		hasher.Write([]byte("com.apple.XattrObjectSalt\x00com.apple.DataObjectSalt\x00"))
		_, err := io.Copy(hasher, file)
		if err != nil {
			return fmt.Errorf("failed to read file: %w", err)
		} else if !bytes.Equal(hasher.Sum(nil), md.Signature[1:]) {
			return fmt.Errorf("signature mismatch")
		}
		return nil
	} else if len(md.DecryptionKey) != 33 {
		return fmt.Errorf("unexpected key length %d (expected 33)", len(md.DecryptionKey))
	} else if md.DecryptionKey[0] != 0x00 {
		return fmt.Errorf("unexpected key prefix 0x%x (expected 0x00)", md.DecryptionKey[0])
	}
	block, err := aes.NewCipher(md.DecryptionKey[1:])
	if err != nil {
		// Key size was already checked above
		panic(fmt.Errorf("impossible error %w", err))
	}
	ctr := cipher.NewCTR(block, zeroIV)
	hasher := sha1.New()
	hasher.Write([]byte("com.apple.XattrObjectSalt\x00com.apple.DataObjectSalt\x00"))
	b := make([]byte, 512)
	var offset int64
	zerolog.Ctx(ctx).Trace().Msg("Decrypting file and checking signature")
	bytesUntilCallback := defaultBytesUntilCallback
	for {
		n, err := file.Read(b)
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return fmt.Errorf("failed to read file: %w", err)
		}
		data := b[:n]
		hasher.Write(data)
		ctr.XORKeyStream(data, data)
		_, err = file.WriteAt(data, offset)
		offset += int64(n)

		prog.DecryptedBytes += n
		bytesUntilCallback -= n
		if bytesUntilCallback <= 0 {
			prog.callCallback(false)
			bytesUntilCallback = defaultBytesUntilCallback
		}
	}
	if !bytes.Equal(hasher.Sum(nil), md.Signature[1:]) {
		return fmt.Errorf("signature mismatch")
	}
	return nil
}

func (md *MMCSDownloader) SendGetComplete(ctx context.Context, ua Versions, attachmentURL string) (*http.Response, error) {
	confirmationBody, err := proto.Marshal(&mmcsproto.ConfirmResponse{
		Inner: md.Confirmations,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to marshal body: %w", err)
	}
	req, err := httputil.Prepare(ctx, http.MethodPost, fmt.Sprintf("%s/getComplete", attachmentURL), confirmationBody)
	if err != nil {
		return nil, fmt.Errorf("failed to prepare request: %w", err)
	}
	addHeaders(req.Header, ua, fmt.Sprintf("%s %s", md.Containers[0].CLAuthP1, md.Containers[0].CLAuthP2), md.AuthID)
	resp, _, err := httputil.Do(httputil.Normal, req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	return resp, nil
}
