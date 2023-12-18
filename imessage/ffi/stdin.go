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

package main

import "C"
import (
	"io"
	"unsafe"
)

var FFIStdinReader, FFIStdinWriter = io.Pipe()

// stdin_write is a function which allows C code to write to the fake "stdin"
// buffer.
//
// This function returns the number of bytes written, or -1 if an error
// occurred.
//
//export stdin_write
func stdin_write(data *C.char, n C.int) C.int {
	buf := C.GoBytes(unsafe.Pointer(data), n)
	written, err := FFIStdinWriter.Write(buf)
	if err != nil {
		return C.int(-1)
	}
	return C.int(written)
}
