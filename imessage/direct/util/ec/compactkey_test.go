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

package ec_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/beeper/imessage/imessage/direct/util/ec"
)

func TestCompactKey(t *testing.T) {
	compactPrivateKey, err := ec.NewCompactPrivateKey()
	assert.NoError(t, err)
	assert.NotNil(t, compactPrivateKey)

	marshalled := compactPrivateKey.PublicKey().Bytes()
	assert.Equal(t, 32, len(marshalled))

	roundTripped := ec.CompactPublicKeyFromBytes(marshalled)
	assert.Equal(t, compactPrivateKey.X, roundTripped.X)
	assert.Equal(t, compactPrivateKey.Y, roundTripped.Y)
}
