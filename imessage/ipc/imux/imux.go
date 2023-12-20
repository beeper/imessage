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

package imux

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/rs/zerolog"

	"github.com/beeper/imessage/imessage/direct/ids"
	"github.com/beeper/imessage/imessage/direct/util/httputil"
)

var (
	ErrImuxUnauthorized       = errors.New("imat unauthorized")
	ErrImuxUnknownDevice      = errors.New("device not registered on imux")
	ErrImuxConflict           = errors.New("registration conflict on imux")
	ErrImuxUnexpectedResponse = errors.New("unexpected error from imux")
)

const imuxMinKeepalive = time.Second * 1

type IMux struct {
	log      *zerolog.Logger
	url      string
	imaToken string
	cfg      DeviceConfig
	cancel   context.CancelFunc
	wg       sync.WaitGroup
}

type FCMConfig struct {
	Token string `json:"token"`
}

// FIXME: share with ids.Config
type ApnsConfig struct {
	Token []byte                `json:"token"`
	Key   ids.JSONRSAPrivateKey `json:"key"`
	Cert  ids.JSONCertificate   `json:"cert"`
}

// FIXME: shared with imux
type DeviceConfig struct {
	FCM          FCMConfig   `json:"fcm"`
	Apns         ApnsConfig  `json:"apns"`
	SecondaryReg *ApnsConfig `json:"secondary_reg,omitempty"`
}

// FIXME: shared with imux
type JSONDurationMs time.Duration

func (t *JSONDurationMs) UnmarshalJSON(data []byte) error {
	var value int64

	if err := json.Unmarshal(data, &value); err != nil {
		return err
	}

	*t = JSONDurationMs(value * int64(time.Millisecond))
	return nil
}

type KeepaliveResponse struct {
	Rate JSONDurationMs `json:"rate_ms"`
}

func NewIMux(log *zerolog.Logger, url, imaToken, pushToken string, primaryIDSConfig, secondaryIDSConfig *ids.Config) *IMux {
	primaryPush := primaryIDSConfig.ToJSONConfig().Push

	deviceConfig := DeviceConfig{
		FCM: FCMConfig{
			Token: pushToken,
		},
		Apns: ApnsConfig{
			Token: primaryPush.Token,
			Key:   primaryPush.Key,
			Cert:  primaryPush.Cert,
		},
	}

	if secondaryIDSConfig != nil {
		secondaryPush := secondaryIDSConfig.ToJSONConfig().Push
		deviceConfig.SecondaryReg = &ApnsConfig{
			Token: secondaryPush.Token,
			Key:   secondaryPush.Key,
			Cert:  secondaryPush.Cert,
		}
	}

	return &IMux{
		log:      log,
		url:      url,
		imaToken: imaToken,
		cfg:      deviceConfig,
	}
}

func (imux *IMux) request(ctx context.Context, method, endpoint string, body any) (*http.Response, error) {
	var bodyReader io.Reader

	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}

		bodyReader = bytes.NewReader(data)
	}

	req, err := http.NewRequestWithContext(ctx, method, fmt.Sprintf("%s/v1/apns/%s", imux.url, endpoint), bodyReader)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+imux.imaToken)
	req.Header.Set("User-Agent", "imessagego")

	resp, err := httputil.Normal.Do(req)
	if err != nil {
		imux.log.Trace().Err(err).Str("url", req.URL.String()).Str("method", method).Msg("Request")
	} else {
		imux.log.Trace().Str("url", req.URL.String()).Str("method", method).Str("status", resp.Status).Msg("Request")
	}

	return resp, err
}

func (imux *IMux) register(ctx context.Context) (time.Duration, error) {
	resp, err := imux.request(ctx, http.MethodPut, "device", &imux.cfg)
	if err != nil {
		return 0, err
	}

	switch resp.StatusCode {
	case http.StatusCreated:
		return decodeKeepaliveRate(resp)
	case http.StatusConflict:
		return 0, ErrImuxConflict
	case http.StatusUnauthorized:
		return 0, ErrImuxUnauthorized
	default:
		return 0, fmt.Errorf("%w: register returned unexpected status %d", ErrImuxUnexpectedResponse, resp.StatusCode)
	}
}

func decodeKeepaliveRate(resp *http.Response) (rate time.Duration, err error) {
	if resp.Body == nil {
		return
	}

	var keepaliveResp KeepaliveResponse
	if err = json.NewDecoder(resp.Body).Decode(&keepaliveResp); err != nil {
		return
	}

	rate = time.Duration(keepaliveResp.Rate)
	return
}

func (imux *IMux) keepalive(ctx context.Context) (time.Duration, error) {
	resp, err := imux.request(ctx, http.MethodPost, "keepalive", nil)
	if err != nil {
		return 0, err
	}

	switch resp.StatusCode {
	case http.StatusOK:
		return decodeKeepaliveRate(resp)
	case http.StatusNoContent:
		return 0, nil
	case http.StatusUnauthorized:
		return 0, ErrImuxUnauthorized
	case http.StatusNotFound:
		return 0, ErrImuxUnknownDevice
	default:
		return 0, fmt.Errorf("%w: keepalive returned unexpected status %d", ErrImuxUnexpectedResponse, resp.StatusCode)
	}
}

func (imux *IMux) yield(ctx context.Context) error {
	resp, err := imux.request(ctx, http.MethodPost, "yield", nil)
	if err != nil {
		return err
	}

	switch resp.StatusCode {
	case http.StatusNoContent:
		return nil
	case http.StatusUnauthorized:
		return ErrImuxUnauthorized
	case http.StatusNotFound:
		return ErrImuxUnknownDevice
	default:
		return fmt.Errorf("%w: yield returned unexpected status %d", ErrImuxUnexpectedResponse, resp.StatusCode)
	}
}

func (imux *IMux) keepaliveOrRegister(ctx context.Context) (time.Duration, error) {
	rate, err := imux.keepalive(ctx)

	if err == ErrImuxUnknownDevice {
		rate, err = imux.register(ctx)
	}

	return rate, err
}

func (imux *IMux) Start(ctx context.Context) {
	if imux.cancel != nil {
		imux.log.Debug().Msg("Start() called when already running")
		return
	}

	if imux.url == "" {
		imux.log.Warn().Msg("No URL set, imux disabled")
		return
	}

	// we need to run once with start context to make imux disconnect from apns immediately
	rate, err := imux.keepaliveOrRegister(ctx)
	if err != nil {
		imux.log.Warn().Err(err).Msg("Unexpected imux error during start")
		// first successful keepalive will reset the ticker
		rate = time.Second * 30
	} else if rate == 0 {
		imux.log.Warn().Msg("Server requested we don't do keepalives, not starting loop")
		return
	} else if rate < imuxMinKeepalive {
		imux.log.Warn().Dur("rate_req", rate).Dur("rate_min", imuxMinKeepalive).Msg("Server requested keepalive time less than allowed, using ours")
		rate = imuxMinKeepalive
	}

	imux.log.Info().Str("url", imux.url).Dur("rate", rate).Msg("Starting imux loop")

	ctx, imux.cancel = context.WithCancel(context.Background())

	imux.wg.Add(1)
	go func() {
		defer func() {
			imux.wg.Done()
			imux.log.Trace().Msg("Leaving imux loop")
		}()

		ticker := time.NewTicker(rate)
		for {
			select {
			case <-ticker.C:
				newRate, err := imux.keepaliveOrRegister(ctx)
				if errors.Is(err, context.Canceled) {
					return
				} else if err != nil {
					imux.log.Warn().Err(err).Msg("Unexpected imux error")
				} else if newRate == 0 {
					imux.log.Warn().Msg("Keepalive returned zero rate, stopping loop")
					return
				} else if newRate > imuxMinKeepalive && newRate != rate {
					imux.log.Info().Dur("rate_new", newRate).Dur("rate_old", rate).Msg("Keepalive rate changed by imux")
					rate = newRate
					ticker.Reset(rate)
				}
			case <-ctx.Done():
				return
			}
		}
	}()
}

func (imux *IMux) Stop(ctx context.Context) {
	if imux.cancel == nil {
		return
	}

	imux.log.Info().Msg("Stopping imux loop")

	imux.Close()

	// send yield before returning
	imux.log.Debug().Msg("Sending final yield")
	err := imux.yield(ctx)
	if err != nil {
		imux.log.Err(err).Msg("Final yield failed")
	} else {
		imux.log.Info().Msg("Yielded imux connection")
	}
}

func (imux *IMux) Close() {
	if imux.cancel == nil {
		return
	}

	imux.cancel()
	imux.cancel = nil
	imux.wg.Wait()
}

func (imux *IMux) Deregister(ctx context.Context) error {
	_, err := imux.request(ctx, http.MethodDelete, "device", &imux.cfg)
	return err
}

func (imux *IMux) IsUsingApnsPushToken(token []byte) bool {
	return bytes.Equal(token, imux.cfg.Apns.Token)
}

func (imux *IMux) IsUsingFCMPushToken(token string) bool {
	return imux.cfg.FCM.Token == token
}
