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

package nacserv

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/rs/zerolog"

	"github.com/beeper/imessage/imessage/direct/ids"
	"github.com/beeper/imessage/imessage/direct/util/httputil"
)

type Client struct {
	URL   string
	Token string

	BeeperToken string

	IsRelay bool
}

var ErrProviderNotReachable = errors.New("invalid registration code or provider not reachable")

type Response struct {
	Name       string        `json:"name"`
	Data       []byte        `json:"data"`
	ValidUntil time.Time     `json:"valid_until"`
	Versions   *ids.Versions `json:"versions"`
	Error      string        `json:"error"`
}

func (c *Client) FetchVersions(ctx context.Context) (*ids.Versions, error) {
	var resp *Response
	var err error
	if !c.IsRelay {
		resp, err = c.fetch(ctx, c.URL, nil, "versions (direct)")
	} else {
		resp, err = c.fetch(ctx, fmt.Sprintf("%s/api/v1/bridge/get-version-info", c.URL), []byte("{}"), "versions (relay)")
	}
	if err != nil {
		return nil, err
	}
	return resp.Versions, nil
}

func (c *Client) FetchValidationData(ctx context.Context) (*Response, error) {
	if !c.IsRelay {
		return c.fetch(ctx, c.URL, nil, "validation data (direct)")
	}
	return c.fetch(ctx, fmt.Sprintf("%s/api/v1/bridge/get-validation-data", c.URL), []byte("{}"), "validation data (relay)")
}

func (c *Client) fetch(ctx context.Context, url string, body []byte, dataType string) (*Response, error) {
	log := zerolog.Ctx(ctx)
	method := http.MethodGet
	if body != nil {
		method = http.MethodPost
	}
	req, err := httputil.Prepare(ctx, method, url, body)
	if err != nil {
		return nil, fmt.Errorf("failed to prepare request: %w", err)
	}
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.Token))
	if c.BeeperToken != "" {
		req.Header.Set("X-Beeper-Access-Token", c.BeeperToken)
	}

	log.Info().Str("url", req.URL.String()).Str("data_type", dataType).Msg("Fetching nacserv data")

	resp, data, err := httputil.Do(httputil.Slow, req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	} else if resp.StatusCode != http.StatusOK {
		if c.IsRelay && resp.StatusCode == http.StatusNotFound {
			return nil, ErrProviderNotReachable
		}
		return nil, fmt.Errorf("unexpected response status %d", resp.StatusCode)
	}
	var respData Response
	err = json.Unmarshal(data, &respData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse response response: %w", err)
	}

	var logEvent = log.Info().
		Str("name", respData.Name).
		Str("data_type", dataType).
		Time("valid_until", respData.ValidUntil).
		Str("error", respData.Error).
		Bool("has_data", respData.Data != nil)
	if respData.Versions != nil {
		logEvent = logEvent.Object("versions", respData.Versions)
	}
	logEvent.Msg("Got nacserv response")

	if respData.Error != "" {
		return nil, errors.New(respData.Error)
	}

	return &respData, nil
}
