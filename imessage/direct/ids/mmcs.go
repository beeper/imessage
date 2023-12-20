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
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha1"
	"crypto/sha256"
	"fmt"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"go.mau.fi/util/random"

	"github.com/beeper/imessage/imessage/direct/ids/mmcsproto"
)

var zeroIV = make([]byte, 16)

func generateMMCSKey() []byte {
	key := random.Bytes(33)
	key[0] = 0x00
	return key
}

func addHeaders(hdr http.Header, ua Versions, auth, authID string) {
	hdr.Set("x-apple-mmcs-dataclass", "com.apple.Dataclass.Messenger")
	hdr.Set("x-apple-mmcs-auth", auth)
	hdr.Set("Accept", appleUbchunkProtobufMime)
	hdr.Set(appleRequestUUIDHeader, strings.ToUpper(uuid.New().String()))
	hdr.Set("x-apple-mme-dsid", authID)
	hdr.Set(mmeClientInfoHeader, ua.MMEClientInfo())
	hdr.Set("Accept-Language", "en-us")
	hdr.Set("Content-Type", appleUbchunkProtobufMime)
	hdr.Set("User-Agent", ua.IMTransferUserAgent())
	hdr.Set(mmcsProtoVersionHeader, mmcsProtoVersion)
	hdr.Set(mmcsPlistVersionHeader, mmcsPlistVersion)
	hdr.Set(mmcsPlistSHA256Header, plistV1SHA256)
}

func aes256CTR(body []byte, key []byte) error {
	if len(key) != 33 {
		return fmt.Errorf("unexpected key length %d (expected 33)", len(key))
	} else if key[0] != 0x00 {
		return fmt.Errorf("unexpected key prefix 0x%x (expected 0x00)", key[0])
	}
	block, err := aes.NewCipher(key[1:])
	if err != nil {
		// Key size was already checked above
		panic(fmt.Errorf("impossible error %w", err))
	}

	cipher.NewCTR(block, zeroIV).XORKeyStream(body, body)
	return nil
}

func encryptedMMCSSignature(body []byte, prefix byte) []byte {
	hasher := sha1.New()
	hasher.Write([]byte("com.apple.XattrObjectSalt\x00com.apple.DataObjectSalt\x00"))
	hasher.Write(body)
	hash := make([]byte, 1, hasher.Size()+1)
	hash[0] = prefix
	return hasher.Sum(hash)
}

func chunkMMCSSignature(body []byte) ChunkChecksum {
	sum := sha256.Sum256(body)
	return chunkMMCSSignatureFromHash(sum[:])
}

func chunkMMCSSignatureFromHash(sha256Hash []byte) ChunkChecksum {
	sum := sha256.Sum256(sha256Hash)
	copy(sum[1:], sum[:20])
	sum[0] = 0x01
	return *(*ChunkChecksum)(sum[:21])
}

const mmcsProtoVersionHeader = "x-apple-mmcs-proto-version"
const mmcsPlistVersionHeader = "x-apple-mmcs-plist-version"
const mmcsPlistSHA256Header = "x-apple-mmcs-plist-sha256"
const mmeClientInfoHeader = "x-mme-client-info"
const appleRequestUUIDHeader = "x-apple-request-uuid"
const putCompleteAtEdgeHeader = "x-apple-put-complete-at-edge-version"

const appleUbchunkProtobufMime = "application/vnd.com.apple.me.ubchunk+protobuf"

const mmcsProtoVersion = "5.0"
const mmcsPlistVersion = "v1.0"
const plistV1SHA256 = "fvj0Y/Ybu1pq0r4NxXw3eP51exujUkEAd7LllbkTdK8="

func makeMMCSHeaders(ua Versions) string {
	return strings.Join([]string{
		mmcsProtoVersionHeader + ":" + mmcsProtoVersion,
		mmcsPlistSHA256Header + ":" + plistV1SHA256,
		mmcsPlistVersionHeader + ":" + mmcsPlistVersion,
		mmeClientInfoHeader + ":" + ua.MMEClientInfo(),
		"",
	}, "\n")
}

func getContainerURL(req *mmcsproto.HTTPRequest) string {
	// Note: req.Path contains the query string as well, so the url package can't be used safely
	return fmt.Sprintf("%s://%s:%d%s", req.Scheme, req.Domain, req.Port, req.Path)
}
