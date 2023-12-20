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

package plisttime

import "time"

type UnixNano struct {
	time.Time
}

func UN(time time.Time) UnixNano {
	return UnixNano{time}
}

func UnixNanoNow() UnixNano {
	return UN(time.Now())
}

func (u UnixNano) MarshalPlist() (any, error) {
	return u.UnixMicro() * 1000, nil
}

func (u *UnixNano) UnmarshalPlist(unmarshal func(any) error) error {
	var val int64
	if err := unmarshal(&val); err != nil {
		return err
	}
	u.Time = time.Unix(0, val)
	return nil
}
