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

package plistuuid_test

import (
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"howett.net/plist"

	"github.com/beeper/imessage/imessage/direct/util/plistuuid"
)

type container struct {
	UUID plistuuid.UUID `plist:"uuid"`
}

func TestMarshalUnmarshal(t *testing.T) {
	tests := []struct {
		uuid     string
		expected string
	}{
		{"AAAAAAAA-0000-0000-0000-000000000000", "<string>AAAAAAAA-0000-0000-0000-000000000000</string>"},
		{"aaaaaaaa-0000-0000-0000-000000000000", "<string>AAAAAAAA-0000-0000-0000-000000000000</string>"},
		{"00000000-0000-0000-0000-000000000000", "<dict><key>uuid</key></dict>"},
	}

	for _, test := range tests {
		t.Run(test.uuid, func(t *testing.T) {
			container := container{plistuuid.UUID{uuid.MustParse(test.uuid)}}
			data, err := plist.Marshal(container, plist.XMLFormat)
			assert.NoError(t, err)
			assert.Regexp(t, test.expected, string(data))
		})
	}
}
