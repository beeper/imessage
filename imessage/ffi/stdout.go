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

/*
#include <stdio.h>

// stdout_callback is a function pointer to a function that takes a string and
// returns nothing.
typedef void (*stdout_callback_t)(const char*, int);
void stdout_write(stdout_callback_t callback, const char* data, int n);
*/
import "C"
import "unsafe"

type ffiStdout struct {
	callback C.stdout_callback_t
}

func (s *ffiStdout) Write(p []byte) (n int, err error) {
	C.stdout_write(s.callback, (*C.char)(unsafe.Pointer(&p[0])), C.int(len(p)))
	return len(p), nil
}

var FFIStdout = ffiStdout{}

//export set_stdout_callback
func set_stdout_callback(callback C.stdout_callback_t) {
	FFIStdout.callback = callback
}
