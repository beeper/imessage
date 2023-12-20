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

package nskeyedarchive

import (
	"fmt"

	"golang.org/x/exp/maps"
	"golang.org/x/exp/slices"
	"howett.net/plist"
)

type NSKeyedArchiveRoot struct {
	Root plist.UID `plist:"root"`
}

type NSKeyedArchivePayload struct {
	Archiver string             `plist:"$archiver"`
	Objects  []any              `plist:"$objects"`
	Top      NSKeyedArchiveRoot `plist:"$top"`
	Version  int                `plist:"$version"`
}

func (p *NSKeyedArchivePayload) Parse(objIdx int) (any, error) {
	switch obj := p.Objects[objIdx].(type) {
	case string:
		if obj == "$null" {
			return nil, nil
		} else {
			return obj, nil
		}
	case map[string]any:
		var err error
		keys := maps.Keys(obj)
		if slices.Contains(keys, "NS.keys") && slices.Contains(keys, "NS.objects") {
			// This is a serialized dictionary.

			deserialized := map[string]any{}
			values := obj["NS.objects"].([]any)
			for i, k := range obj["NS.keys"].([]any) {
				parsedKey, err := p.Parse(int(k.(plist.UID)))
				if err != nil {
					return nil, err
				}
				deserialized[parsedKey.(string)], err = p.Parse(int(values[i].(plist.UID)))
			}
			return deserialized, nil
		}

		for k, v := range obj {
			if k == "$class" {
				delete(obj, k)
				continue
			}
			switch val := v.(type) {
			case plist.UID:
				if obj[k], err = p.Parse(int(val)); err != nil {
					return nil, err
				}
			}
		}
		return obj, nil
	default:
		return p.Objects[objIdx], nil
	}
}

func Parse(data []byte) (any, error) {
	var payload NSKeyedArchivePayload
	if _, err := plist.Unmarshal(data, &payload); err != nil {
		return nil, err
	}

	if payload.Archiver != "NSKeyedArchiver" {
		return nil, fmt.Errorf("invalid archiver: %s", payload.Archiver)
	}

	return payload.Parse(int(payload.Top.Root))
}
