// beeper-imessage - A Matrix-iMessage puppeting bridge.
// Copyright (C) 2022 Tulir Asokan
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

//go:build libheif

package msgconv

import (
	"bufio"
	"bytes"
	"fmt"
	"image/jpeg"

	"github.com/strukturag/libheif/go/heif"
)

const CanConvertHEIF = true

func ConvertHEIF(data []byte) ([]byte, error) {
	ctx, err := heif.NewContext()
	if err != nil {
		return nil, fmt.Errorf("can't create context: %s", err)
	}

	if err := ctx.ReadFromMemory(data); err != nil {
		return nil, fmt.Errorf("can't read from memory: %s", err)
	}

	handle, err := ctx.GetPrimaryImageHandle()
	if err != nil {
		return nil, fmt.Errorf("can't read primary image: %s", err)
	}

	heifImg, err := handle.DecodeImage(heif.ColorspaceUndefined, heif.ChromaUndefined, nil)
	if err != nil {
		return nil, fmt.Errorf("can't decode image: %s", err)
	}

	img, err := heifImg.GetImage()
	if err != nil {
		return nil, fmt.Errorf("can't convert image: %s", err)
	}

	var output bytes.Buffer

	err = jpeg.Encode(bufio.NewWriter(&output), img, nil)
	if err != nil {
		return nil, fmt.Errorf("Failed to encode: %v", err)
	}

	return output.Bytes(), nil
}
