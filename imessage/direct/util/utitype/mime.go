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
	_ "embed"
	"encoding/json"

	"go.mau.fi/util/exmime"
)

//go:generate sh -c "./generate.py --mime-only > mime-to-uti.json"
//go:embed mime-to-uti.json
var mimeToUTIRaw []byte

// Custom UTIs are hardcoded here, standard ones are saved in the JSON file.
var mimeToUTI = map[string]string{
	"text/x-vlocation": "public.vlocation",
}

func init() {
	err := json.Unmarshal(mimeToUTIRaw, &mimeToUTI)
	if err != nil {
		panic(err)
	}
}

func MIME(mimeType string) string {
	uti, ok := mimeToUTI[mimeType]
	if !ok {
		return Dynamic(mimeType, exmime.ExtensionFromMimetype(mimeType))
	}
	return uti
}
