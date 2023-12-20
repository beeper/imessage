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

package ids

import (
	"encoding/hex"
	"fmt"
	"math/rand"
	"strings"
)

func CreateSMSRegisterRequest(pushToken []byte) string {
	token := strings.ToUpper(hex.EncodeToString(pushToken))
	reqID := fmt.Sprintf("%d", rand.Uint32())
	return fmt.Sprintf("REG-REQ?v=3;t=%s;r=%s;", token, reqID)
}

func ParseSMSRegisterResponse(resp string) (phoneNumber string, sig []byte, err error) {
	if !strings.HasPrefix(resp, "REG-RESP?") {
		return "", nil, fmt.Errorf("invalid register response: %s", resp)
	}
	resp = strings.TrimPrefix(resp, "REG-RESP?")

	for _, param := range strings.Split(resp, ";") {
		kv := strings.SplitN(param, "=", 2)
		if len(kv) != 2 {
			return "", nil, fmt.Errorf("invalid register response parameter: %s", param)
		}

		switch kv[0] {
		case "v":
			if kv[1] != "3" {
				return "", nil, fmt.Errorf("invalid register response version: %s", kv[1])
			}
		case "r": // Request ID - do nothing
		case "n":
			phoneNumber = kv[1]
		case "s":
			sig, err = hex.DecodeString(kv[1])
			if err != nil {
				return "", nil, fmt.Errorf("invalid register response signature: %w", err)
			}
		}
	}
	return
}
