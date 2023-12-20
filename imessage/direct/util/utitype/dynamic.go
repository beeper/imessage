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

package utitype

import (
	"encoding/base32"
	"fmt"
	"strings"
)

var appleBase32 = base32.NewEncoding("abcdefghkmnpqrstuvwxyz0123456789").WithPadding(base32.NoPadding)

func Dynamic(mimeType, extension string) string {
	// See https://alastairs-place.net/blog/2012/06/06/utis-are-better-than-you-think-and-heres-why/ for details on dynamic UTIs

	var baseType string
	switch strings.Split(mimeType, "/")[0] {
	case "text":
		baseType = "7" // public.text
	case "image":
		baseType = "B" // public.image
	case "video":
		baseType = "C" // public.video
	case "audio":
		baseType = "D" // public.audio
	default:
		baseType = "6" // public.data
	}
	// 0 = UTTypeConformsTo
	// 1 = public.filename-extension
	// 3 = public.mime-type
	dynamicText := fmt.Sprintf("?0=%s:3=%s", baseType, mimeType)
	extension = strings.TrimPrefix(extension, ".")
	if extension != "" {
		dynamicText = fmt.Sprintf("%s:1=%s", dynamicText, extension)
	}
	return fmt.Sprintf("dyn.a%s", appleBase32.EncodeToString([]byte(dynamicText)))
}
