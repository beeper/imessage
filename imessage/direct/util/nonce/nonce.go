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

package nonce

import (
	"crypto/rand"
	"encoding/binary"
	"time"
)

const NonceLength = 17

type Nonce []byte
type NoncedPayload []byte

// Generate generates a nonce in this format:
//
//	01000001876bd0a2c0e571093967fce3d7
//	01                                 # version
//	  000001876d008cc5                 # UNIX time (ms)
//	                  r1r2r3r4r5r6r7r8 # random bytes
func Generate() Nonce {
	nonce := make([]byte, NonceLength)
	nonce[0] = 0x01
	binary.BigEndian.PutUint64(nonce[1:9], uint64(time.Now().UnixMilli()))
	rand.Read(nonce[9:])
	return nonce
}

func (n Nonce) WrapPayload(payload []byte) NoncedPayload {
	wrapped := make([]byte, NonceLength+len(payload))
	copy(wrapped[:NonceLength], n)
	copy(wrapped[NonceLength:], payload)
	return wrapped
}
