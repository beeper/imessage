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

package ffi

type ffiStdout struct {
	callback func([]byte)
}

func (s *ffiStdout) Write(p []byte) (n int, err error) {
	s.callback(p)
	return len(p), nil
}

var FFIStdout = ffiStdout{}

func SetStdoutCallback(callback func([]byte)) {
	FFIStdout.callback = callback
}
