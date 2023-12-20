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

package gnuzip

import (
	"bytes"
	"compress/gzip"
	"errors"
	"io"
)

func MaybeGUnzip(body []byte) ([]byte, error) {
	reader, err := gzip.NewReader(bytes.NewReader(body))
	if err != nil {
		if errors.Is(err, gzip.ErrHeader) {
			return body, nil
		} else {
			return nil, err
		}
	}
	defer reader.Close()
	if decompressed, err := io.ReadAll(reader); err != nil {
		return nil, err
	} else {
		return decompressed, nil
	}
}
