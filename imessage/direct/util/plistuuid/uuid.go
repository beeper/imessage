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

package plistuuid

import (
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/google/uuid"
)

type UUID struct {
	uuid.UUID
}

func New() UUID {
	return UUID{uuid.New()}
}

func NewPtrFromUUID(id *uuid.UUID) *UUID {
	if id != nil && *id != uuid.Nil {
		return &UUID{UUID: *id}
	}
	return nil
}

func NewFromUUID(id uuid.UUID) UUID {
	return UUID{UUID: id}
}

func (u UUID) Bytes() []byte {
	return u.UUID[:]
}

func (u UUID) MarshalPlist() (any, error) {
	if u.UUID == [16]byte{} {
		return nil, nil
	}
	// TODO is upper necessary?
	return strings.ToUpper(u.String()), nil
}

func (u *UUID) UnmarshalPlist(unmarshal func(any) error) error {
	var str string
	err := unmarshal(&str)
	if err != nil {
		return err
	}

	u.UUID, err = uuid.Parse(str)
	if err != nil {
		return fmt.Errorf("failed to parse %q as a UUID: %w", str, err)
	}
	return nil
}

func (u *UUID) UUIDPtr() *uuid.UUID {
	if u == nil {
		return nil
	}
	return &u.UUID
}

type ByteUUID []byte

func (u ByteUUID) IsValid() bool {
	return len(u) == 16
}

func (u ByteUUID) UUID() (casted uuid.UUID) {
	if u.IsValid() {
		casted = *(*uuid.UUID)(u)
	}
	return
}

func (u ByteUUID) String() string {
	if !u.IsValid() {
		return "INVALID:" + base64.StdEncoding.EncodeToString(u)
	}
	return u.UUID().String()
}

func (u ByteUUID) Bytes() []byte {
	return u
}

func (u ByteUUID) MarshalJSON() ([]byte, error) {
	if u.IsValid() {
		return []byte(`"` + u.String() + `"`), nil
	} else {
		return []byte(`"` + base64.StdEncoding.EncodeToString(u) + `"`), nil
	}
}
