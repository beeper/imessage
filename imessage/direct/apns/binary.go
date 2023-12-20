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
	"fmt"
	"io"
)

type FieldID uint8

type Field struct {
	ID    FieldID
	Value []byte
}

type Payload struct {
	ID     CommandID
	Fields []Field
}

func (p *Payload) FindField(fieldID uint8) []byte {
	for _, field := range p.Fields {
		if field.ID == FieldID(fieldID) {
			return field.Value
		}
	}
	return nil
}

func (p *Payload) ToBytes() []byte {
	length := 5
	for _, field := range p.Fields {
		length += 3 + len(field.Value)
	}
	payload := make([]byte, length)
	payload[0] = byte(p.ID)
	binary.BigEndian.PutUint32(payload[1:5], uint32(length-5))
	ptr := 5
	for _, field := range p.Fields {
		payload[ptr] = byte(field.ID)
		binary.BigEndian.PutUint16(payload[ptr+1:ptr+3], uint16(len(field.Value)))
		copy(payload[ptr+3:ptr+3+len(field.Value)], field.Value)
		ptr += 3 + len(field.Value)
	}
	return payload
}

func (p *Payload) MarshalBinary() ([]byte, error) {
	return p.ToBytes(), nil
}

func (p *Payload) UnmarshalBinaryStream(reader io.Reader) error {
	// Read the first byte to figure out which command it is
	readBuf := make([]byte, 4)
	_, err := io.ReadFull(reader, readBuf[:1])
	if err != nil {
		return err
	}
	p.ID = CommandID(readBuf[0])
	if p.ID == 0 {
		return nil
	}

	// Read the next 4 bytes to figure out the length of the command
	_, err = io.ReadFull(reader, readBuf)
	if err != nil {
		return err
	}
	length := binary.BigEndian.Uint32(readBuf)

	// Now read the full payload
	data := make([]byte, length)
	_, err = io.ReadFull(reader, data)
	if err != nil {
		return err
	}

	return p.unmarshalFieldsFromBytes(data)
}

func (p *Payload) UnmarshalBinary(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("empty payload")
	}
	p.ID = CommandID(data[0])
	if p.ID == 0 {
		return nil
	}
	if len(data) < 5 {
		return fmt.Errorf("invalid payload length")
	}
	length := binary.BigEndian.Uint32(data[1:5])
	return p.unmarshalFieldsFromBytes(data[5 : 5+length])
}

func (p *Payload) unmarshalFieldsFromBytes(data []byte) error {
	var i int
	for i+3 <= len(data) {
		var field Field
		field.ID = FieldID(data[i])
		fieldLength := int(binary.BigEndian.Uint16(data[i+1 : i+3]))
		if i+3+fieldLength > len(data) {
			return fmt.Errorf("invalid field length")
		}
		field.Value = data[i+3 : i+3+fieldLength]
		i += 3 + fieldLength
		p.Fields = append(p.Fields, field)
	}
	return nil
}
