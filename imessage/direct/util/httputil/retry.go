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

package httputil

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/rs/zerolog"
)

var reqIDCounter atomic.Uint64

func Prepare(ctx context.Context, method, url string, body []byte) (*http.Request, error) {
	if url == "" {
		return nil, fmt.Errorf("missing url")
	}
	var bodyReader io.Reader
	if body != nil {
		bodyReader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, url, bodyReader)
	if err != nil {
		return nil, err
	}
	return req, nil
}

func PrepareCustom(ctx context.Context, method, url string, getBody func() (io.ReadCloser, error)) (*http.Request, error) {
	if url == "" {
		return nil, fmt.Errorf("missing url")
	}
	body, err := getBody()
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return nil, err
	}
	req.GetBody = getBody
	return req, nil
}

var MaxRetries = 50

func Do(client *http.Client, req *http.Request) (*http.Response, []byte, error) {
	return DoCustomOutput(client, req, nil)
}

func DoCustomOutput(client *http.Client, req *http.Request, out io.WriteSeeker) (*http.Response, []byte, error) {
	reqID := reqIDCounter.Add(1)
	log := zerolog.Ctx(req.Context()).With().
		Str("url", req.URL.String()).
		Str("method", "http request").
		Uint64("req_id", reqID).
		Logger()
	ctx := req.Context()
	retries := 0
	for {
		start := time.Now()
		resp, data, err := doOnce(client, req, out)
		duration := time.Since(start)
		backoff := time.Duration(retries) * 3 * time.Second
		if err != nil {
			if errors.Is(err, context.Canceled) {
				return nil, nil, err
			} else if ctx.Err() != nil {
				return nil, nil, ctx.Err()
			}
			if retries > 0 && strings.Contains(err.Error(), "net/http: timeout awaiting response headers") {
				IncreaseTimeout(log.WithContext(ctx), client)
			}
			//if timeoutErr := net.Error(nil); errors.As(err, &timeoutErr) && timeoutErr.Timeout() {
			//	TODO handle other types of timeouts?
			//}
			log.Warn().Err(err).
				Dur("request_duration", duration).
				Int("retry_count", retries).
				Int("retry_in_seconds", int(backoff.Seconds())).
				Msg("Failed to complete request, retrying")
		} else if resp.StatusCode == http.StatusBadGateway || resp.StatusCode == http.StatusServiceUnavailable || resp.StatusCode == http.StatusGatewayTimeout {
			log.Warn().
				Dur("request_duration", duration).
				Int("status_code", resp.StatusCode).
				Int("retry_count", retries).
				Int("retry_in_seconds", int(backoff.Seconds())).
				Msg("Bad gateway error in request, retrying")
			err = fmt.Errorf("HTTP %d", resp.StatusCode)
		} else if resp.StatusCode == http.StatusInternalServerError {
			log.Error().
				Dur("request_duration", duration).
				Int("status_code", resp.StatusCode).
				Msg("Internal server error in request")
			return resp, data, fmt.Errorf("server returned HTTP 500")
		} else {
			log.Debug().
				Dur("request_duration", duration).
				Int("status_code", resp.StatusCode).
				Int("retry_count", retries).
				Msg("Request successful")
			return resp, data, err
		}
		retries++
		if retries > MaxRetries {
			log.Error().Msg("Exceeded max retries")
			return nil, nil, err
		}
		if req.Body != nil {
			if req.GetBody == nil {
				log.Error().Msg("GetBody is nil, can't retry request")
				return resp, data, err
			}
			req.Body, err = req.GetBody()
			if err != nil {
				log.Err(err).Msg("Failed to get new body to retry request")
				return resp, data, err
			}
		}
		select {
		case <-ctx.Done():
			return nil, nil, ctx.Err()
		case <-time.After(backoff):
		}
	}
}

type StatusAccepter interface {
	AcceptStatus(status int) bool
}

func acceptStatus(out io.WriteSeeker, status int) bool {
	accepter, ok := out.(StatusAccepter)
	if !ok {
		return true
	}
	return accepter.AcceptStatus(status)
}

func doOnce(client *http.Client, req *http.Request, out io.WriteSeeker) (resp *http.Response, respData []byte, err error) {
	resp, err = client.Do(req)
	if err != nil {
		err = fmt.Errorf("error sending request: %w", err)
		return
	}
	if out != nil && acceptStatus(out, resp.StatusCode) {
		_, err = out.Seek(0, io.SeekStart)
		if err == nil {
			_, err = io.Copy(out, resp.Body)
		}
	} else if resp.ContentLength > 0 {
		respData = make([]byte, resp.ContentLength)
		_, err = io.ReadFull(resp.Body, respData)
	} else {
		respData, err = io.ReadAll(resp.Body)
	}
	if err != nil {
		err = fmt.Errorf("error reading response: %w", err)
	}
	_ = resp.Body.Close()
	return
}
