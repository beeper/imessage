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
	"encoding"
	"encoding/binary"
	"fmt"
	"reflect"
	"strconv"
	"strings"
)

var commandIDToStruct = map[CommandID]reflect.Type{
	CommandConnect:         reflect.TypeOf(ConnectCommand{}),
	CommandConnectAck:      reflect.TypeOf(ConnectAckCommand{}),
	CommandFilterTopics:    reflect.TypeOf(FilterTopicsCommand{}),
	CommandFilterTopicsAck: reflect.TypeOf(FilterTopicsAckCommand{}),
	CommandSendMessage:     reflect.TypeOf(IncomingSendMessageCommand{}),
	CommandSendMessageAck:  reflect.TypeOf(SendMessageAckCommand{}),
	CommandSetState:        reflect.TypeOf(SetStateCommand{}),
	CommandKeepAlive:       reflect.TypeOf(KeepAliveCommand{}),
	CommandKeepAliveAck:    reflect.TypeOf(KeepAliveCommand{}),
}

var structToCommandID = map[reflect.Type]CommandID{
	reflect.TypeOf(ConnectCommand{}):             CommandConnect,
	reflect.TypeOf(ConnectAckCommand{}):          CommandConnectAck,
	reflect.TypeOf(FilterTopicsCommand{}):        CommandFilterTopics,
	reflect.TypeOf(FilterTopicsAckCommand{}):     CommandFilterTopicsAck,
	reflect.TypeOf(OutgoingSendMessageCommand{}): CommandSendMessage,
	reflect.TypeOf(SendMessageAckCommand{}):      CommandSendMessageAck,
	reflect.TypeOf(SetStateCommand{}):            CommandSetState,
	reflect.TypeOf(KeepAliveCommand{}):           CommandKeepAlive,
	reflect.TypeOf(KeepAliveCommand{}):           CommandKeepAliveAck,
}

type reflectField struct {
	name  string
	id    FieldID
	index []int
}

type reflectFields struct {
	fields []reflectField
	byID   map[FieldID]reflectField
}

var reflectFieldMapCache map[reflect.Type]*reflectFields

func init() {
	reflectFieldMapCache = make(map[reflect.Type]*reflectFields)
	for _, structType := range commandIDToStruct {
		var err error
		reflectFieldMapCache[structType], err = makeFieldMap(structType)
		if err != nil {
			panic(err)
		}
	}
	for structType := range structToCommandID {
		if _, ok := reflectFieldMapCache[structType]; ok {
			continue
		}
		var err error
		reflectFieldMapCache[structType], err = makeFieldMap(structType)
		if err != nil {
			panic(err)
		}
	}
}

func makeFieldMap(payloadTypeRef reflect.Type) (*reflectFields, error) {
	fieldMap := make(map[FieldID]reflectField, payloadTypeRef.NumField())
	fields := make([]reflectField, 0, payloadTypeRef.NumField())
	for _, fieldTypeRef := range reflect.VisibleFields(payloadTypeRef) {
		val := fieldTypeRef.Tag.Get("apns")
		if len(val) == 0 {
			continue
		}
		parts := strings.Split(val, ",")
		fieldID, err := strconv.Atoi(parts[0])
		if err != nil {
			return nil, fmt.Errorf("invalid struct tag %q in field %s: %v", val, fieldTypeRef.Name, err)
		}
		fieldMeta := reflectField{
			name:  fieldTypeRef.Name,
			id:    FieldID(fieldID),
			index: fieldTypeRef.Index,
		}
		fieldMap[fieldMeta.id] = fieldMeta
		fields = append(fields, fieldMeta)
	}
	return &reflectFields{byID: fieldMap, fields: fields}, nil
}

func Marshal(payload any) ([]byte, error) {
	p, err := structToPayload(payload)
	if err != nil {
		return nil, err
	}
	return p.MarshalBinary()
}

func Unmarshal(data []byte, into any) error {
	payload := &Payload{}
	err := payload.UnmarshalBinary(data)
	if err != nil {
		return err
	}
	return payload.toStruct(into)
}

func (p *Payload) toStructAuto() (any, error) {
	structType, ok := commandIDToStruct[p.ID]
	if !ok {
		return nil, fmt.Errorf("unknown command ID %d", p.ID)
	}
	output := reflect.New(structType).Interface()
	err := p.toStruct(output)
	if err != nil {
		return nil, err
	}
	return output, nil
}

func deserializeOneField(fieldRef reflect.Value, data []byte) error {
	switch typedField := fieldRef.Interface().(type) {
	case []byte:
		fieldRef.SetBytes(data)
	case bool:
		if len(data) == 0 {
			return fmt.Errorf("expected at least one byte for bool, got none")
		}
		fieldRef.SetBool(data[0] > 0)
	case uint8:
		if len(data) == 0 {
			return fmt.Errorf("expected at least one byte for uint8, got none")
		}
		fieldRef.SetUint(uint64(data[0]))
	case uint16:
		if len(data) < 2 {
			return fmt.Errorf("expected at least 2 bytes for uint16, got %d", len(data))
		}
		fieldRef.SetUint(uint64(binary.BigEndian.Uint16(data)))
	case uint32:
		if len(data) < 4 {
			return fmt.Errorf("expected at least 4 bytes for uint32, got %d", len(data))
		}
		fieldRef.SetUint(uint64(binary.BigEndian.Uint32(data)))
	case uint64:
		if len(data) < 8 {
			return fmt.Errorf("expected at least 8 bytes for uint64, got %d", len(data))
		}
		fieldRef.SetUint(binary.BigEndian.Uint64(data))
	case encoding.BinaryUnmarshaler:
		if fieldRef.IsNil() {
			fieldRef.Set(reflect.New(fieldRef.Type()))
		}
		err := typedField.UnmarshalBinary(data)
		if err != nil {
			return err
		}
	default:
		return fmt.Errorf("unsupported type %T", typedField)
	}
	return nil
}

func (p *Payload) toStruct(into any) error {
	payloadRef := reflect.ValueOf(into).Elem()
	fieldMap, ok := reflectFieldMapCache[payloadRef.Type()]
	if !ok {
		return fmt.Errorf("reflect field map not found for %T", into)
	}
	for _, field := range p.Fields {
		fieldMeta, ok := fieldMap.byID[field.ID]
		if !ok {
			// TODO log/error/something?
			continue
		}
		fieldRef := payloadRef.FieldByIndex(fieldMeta.index)
		if fieldRef.Kind() == reflect.Slice && fieldRef.Type().Elem().Kind() != reflect.Uint8 {
			if fieldRef.IsNil() {
				fieldRef.Set(reflect.New(fieldRef.Type()))
			}
			newVal := reflect.New(fieldRef.Type().Elem())
			err := deserializeOneField(fieldRef, field.Value)
			if err != nil {
				return fmt.Errorf("failed to deserialize field %s[%d]: %w", fieldMeta.name, fieldRef.Len(), err)
			}
			fieldRef.Set(reflect.Append(fieldRef, newVal))
		} else {
			err := deserializeOneField(fieldRef, field.Value)
			if err != nil {
				return fmt.Errorf("failed to deserialize field %s: %w", fieldMeta.name, err)
			}
		}
	}
	return nil
}

func serializeOneField(fieldRef reflect.Value) ([]byte, error) {
	switch typedField := fieldRef.Interface().(type) {
	case string:
		return []byte(typedField), nil
	case []byte:
		return typedField, nil
	case bool:
		if typedField {
			return []byte{1}, nil
		}
		return []byte{0}, nil
	case uint8:
		return []byte{typedField}, nil
	case uint16:
		bytes := make([]byte, 2)
		binary.BigEndian.PutUint16(bytes, typedField)
		return bytes, nil
	case uint32:
		bytes := make([]byte, 4)
		binary.BigEndian.PutUint32(bytes, typedField)
		return bytes, nil
	case uint64:
		bytes := make([]byte, 8)
		binary.BigEndian.PutUint64(bytes, typedField)
		return bytes, nil
	case encoding.BinaryMarshaler:
		data, err := typedField.MarshalBinary()
		if err != nil {
			return nil, err
		}
		return data, nil
	default:
		return nil, fmt.Errorf("unsupported type %T", typedField)
	}
}

func structToPayload(payload any) (*Payload, error) {
	payloadRef := reflect.ValueOf(payload).Elem()
	payloadTypeRef := payloadRef.Type()
	commandID, ok := structToCommandID[payloadTypeRef]
	if !ok {
		return nil, fmt.Errorf("unknown payload type %T", payload)
	}
	fieldMap, ok := reflectFieldMapCache[payloadRef.Type()]
	if !ok {
		return nil, fmt.Errorf("reflect field map not found for %T", payload)
	}
	var output []Field
	for _, fieldMeta := range fieldMap.fields {
		fieldRef := payloadRef.FieldByIndex(fieldMeta.index)
		switch fieldRef.Kind() {
		case reflect.Slice, reflect.Pointer, reflect.Interface:
			if fieldRef.IsNil() {
				continue
			}
		}
		if fieldRef.Kind() == reflect.Slice && fieldRef.Type().Elem().Kind() != reflect.Uint8 {
			for i := 0; i < fieldRef.Len(); i++ {
				serialized, err := serializeOneField(fieldRef.Index(i))
				if err != nil {
					return nil, fmt.Errorf("failed to serialize field %s[%d]: %v", fieldMeta.name, i, err)
				}
				output = append(output, Field{ID: fieldMeta.id, Value: serialized})
			}
		} else {
			serialized, err := serializeOneField(fieldRef)
			if err != nil {
				return nil, fmt.Errorf("failed to serialize field %s: %v", fieldMeta.name, err)
			}
			output = append(output, Field{ID: fieldMeta.id, Value: serialized})
		}
	}

	return &Payload{
		ID:     commandID,
		Fields: output,
	}, nil
}
