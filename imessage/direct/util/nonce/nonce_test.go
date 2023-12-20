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

package nonce_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/beeper/imessage/imessage/direct/util/nonce"
)

func TestGenerate(t *testing.T) {
	assert.Equal(t, 17, nonce.NonceLength)

	n := nonce.Generate()
	assert.Len(t, n, nonce.NonceLength)
}

func TestWrapPayload(t *testing.T) {
	n := nonce.Generate()
	payload := []byte("test")
	wrapped := n.WrapPayload(payload)
	assert.Len(t, wrapped, nonce.NonceLength+len(payload))
	assert.Equal(t, payload, []byte(wrapped[nonce.NonceLength:]))
}
