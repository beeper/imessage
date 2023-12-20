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

package appleid

import (
	"crypto/sha1"
	"fmt"
	"time"
)

const hashcashDateFormat = "20060102150405"

func (hp *HashcashParams) Compute() string {
	date := time.Now().Format(hashcashDateFormat)
	var stamp string
	maxCounter := hp.Bits * 100_000_000
	for counter := 0; counter < maxCounter; counter++ {
		stamp = fmt.Sprintf("1:%d:%s:%s::%d", hp.Bits, date, hp.Challenge, counter)
		if enoughZeroes(sha1.Sum([]byte(stamp)), hp.Bits) {
			return stamp
		}
	}
	panic("could not compute hashcash stamp")
}

func enoughZeroes(data [20]byte, number int) bool {
	ptr := 0
	for number > 8 {
		if data[ptr] != 0 {
			return false
		}
		number -= 8
		ptr++
	}
	if number > 0 {
		if data[ptr]>>(8-number) != 0 {
			return false
		}
	}
	return true
}
