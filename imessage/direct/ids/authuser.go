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
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/rs/zerolog"
	"howett.net/plist"

	"github.com/beeper/imessage/imessage/direct/ids/types"
	"github.com/beeper/imessage/imessage/direct/util/httputil"
)

type userAuthenticateRequest struct {
	Username string `plist:"username"`
	Password string `plist:"password"`
}

type AuthResponse struct {
	Status    types.IDSStatus `plist:"status"`
	AuthToken string          `plist:"auth-token"`
	ProfileID string          `plist:"profile-id"`
}

func (u *User) Authenticate(ctx context.Context, username, password, code string) (*AuthResponse, error) {
	log := zerolog.Ctx(ctx)

	data := userAuthenticateRequest{
		Username: strings.TrimSpace(username),
		Password: password,
	}
	code = strings.TrimSpace(code)
	if code != "" {
		data.Password += code
	}

	marshaled, err := plist.Marshal(data, plist.XMLFormat)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	req, err := httputil.Prepare(ctx, http.MethodPost, authenticateUserURL, marshaled)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("User-Agent", u.Versions.CombinedVersion())

	_, body, err := httputil.Do(httputil.Apple, req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}

	var authResp AuthResponse
	_, err = plist.Unmarshal(body, &authResp)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	log.Info().Int("resp_status", int(authResp.Status)).Msg("got auth response")

	if authResp.Status != types.IDSStatusSuccess {
		return nil, types.IDSError{ErrorCode: authResp.Status}
	}

	return &authResp, nil
}
