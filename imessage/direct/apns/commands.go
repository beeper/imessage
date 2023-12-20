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

package apns

import (
	"encoding/binary"
)

type CommandID uint8

const (
	CommandConnect         CommandID = 7
	CommandConnectAck      CommandID = 8
	CommandFilterTopics    CommandID = 9
	CommandSendMessage     CommandID = 10
	CommandSendMessageAck  CommandID = 11
	CommandKeepAlive       CommandID = 12
	CommandKeepAliveAck    CommandID = 13
	CommandFilterTopicsAck CommandID = 14 // uncertain
	CommandSetState        CommandID = 20
)

type ConnectionFlag uint32

const (
	BaseConnectionFlags ConnectionFlag = 0b1000001
	RootConnection      ConnectionFlag = 0b100
)

func (c ConnectionFlag) ToBytes() []byte {
	out := make([]byte, 4)
	binary.BigEndian.PutUint32(out, uint32(c))
	return out
}

func (c ConnectionFlag) MarshalBinary() ([]byte, error) {
	return c.ToBytes(), nil
}

type ConnectCommand struct {
	DeviceToken []byte         `apns:"1"`
	State       []byte         `apns:"2"`
	Flags       ConnectionFlag `apns:"5"`

	Cert      []byte `apns:"12"`
	Nonce     []byte `apns:"13"`
	Signature []byte `apns:"14"`
}

type ConnectAckCommand struct {
	Status           []byte `apns:"1"` // 0 for success, 2 for error
	Token            []byte `apns:"3"`
	MaxMessageSize   uint16 `apns:"4"`  // uint16, usually 4 KiB
	Unknown5         []byte `apns:"5"`  // AAI=
	Capabilities     []byte `apns:"6"`  // AAAw==
	LargeMessageSize uint16 `apns:"8"`  // uint16, usually 15 KiB
	ServerTimestamp  uint64 `apns:"10"` // unix milliseconds
}

type IncomingSendMessageCommand struct {
	MessageID  []byte `apns:"4"`
	Token      []byte `apns:"1"`
	Topic      []byte `apns:"2"`
	Payload    []byte `apns:"3"`
	Expiration []byte `apns:"5"` // uint32, seconds, always 2^32-1 (0xffffffff)?
	Timestamp  []byte `apns:"6"` // uint64, unix nanoseconds
	Unknown7   []byte `apns:"7"` // always 0x02?
}

type OutgoingSendMessageCommand struct {
	MessageID []byte `apns:"4"`
	Token     []byte `apns:"2"`
	Topic     []byte `apns:"1"`
	Payload   []byte `apns:"3"`
}

type SetStateCommand struct {
	State    uint8  `apns:"1"`
	FieldTwo uint32 `apns:"2"`
}

type FilterTopicsCommand struct {
	Token  []byte   `apns:"1"`
	Topics [][]byte `apns:"2"`
}

type FilterTopicsAckCommand struct {
	Token []byte `apns:"1"`
}

type SendMessageAckCommand struct {
	Token     []byte `apns:"1"`
	MessageID []byte `apns:"4"`
	NullByte  []byte `apns:"8"`

	MaybeError []byte `apns:"6"`
}

type KeepAliveCommand struct{}
