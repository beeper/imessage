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

package apns

import (
	"context"
	"fmt"
	"math/rand"
)

// If these values ever change, fetch them from
// http://init-p01st.push.apple.com/bag

const (
	apnsCourierHostcount = 50
	apnsCourierHostname  = "courier.push.apple.com"
)

func GetCourierHostPort(ctx context.Context) (string, int, error) {
	hostNum := rand.Intn(apnsCourierHostcount) + 1
	return fmt.Sprintf("%d-%s", hostNum, apnsCourierHostname), 5223, nil
}
