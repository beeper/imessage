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
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"time"

	"github.com/rs/zerolog"

	"github.com/beeper/imessage/imessage/direct/util/appletls"
)

var normalTransport = &http.Transport{
	DialContext:           (&net.Dialer{Timeout: 10 * time.Second}).DialContext,
	ForceAttemptHTTP2:     true,
	TLSHandshakeTimeout:   10 * time.Second,
	ResponseHeaderTimeout: 5 * time.Second,
}
var slowTransport = &http.Transport{
	DialContext:           (&net.Dialer{Timeout: 20 * time.Second}).DialContext,
	ForceAttemptHTTP2:     true,
	TLSHandshakeTimeout:   20 * time.Second,
	ResponseHeaderTimeout: 60 * time.Second,
}
var appleTLSTransport = &http.Transport{
	TLSClientConfig: &tls.Config{
		RootCAs: appletls.CertPool,
	},

	DialContext:           (&net.Dialer{Timeout: 10 * time.Second}).DialContext,
	ForceAttemptHTTP2:     true,
	TLSHandshakeTimeout:   10 * time.Second,
	ResponseHeaderTimeout: 5 * time.Second,
}
var Normal = &http.Client{
	Timeout:   1 * time.Minute,
	Transport: normalTransport,
}
var Slow = &http.Client{
	Timeout:   2 * time.Minute,
	Transport: slowTransport,
}
var Media = &http.Client{
	// Long total timeout to allow body to be read or written
	Timeout:   5 * time.Minute,
	Transport: normalTransport,
}
var Apple = &http.Client{
	Transport: appleTLSTransport,
	Timeout:   1 * time.Minute,
}

func IncreaseTimeout(ctx context.Context, client *http.Client) {
	switch client {
	case Apple:
		increaseTimeout(ctx, "apple", appleTLSTransport)
	case Media, Normal:
		increaseTimeout(ctx, "normal", normalTransport)
	}
}

func increaseTimeout(ctx context.Context, transportName string, transport *http.Transport) {
	switch transport.ResponseHeaderTimeout {
	case 5 * time.Second:
		zerolog.Ctx(ctx).Info().
			Str("transport_name", transportName).
			Msg("Increasing response header timeout to 10 seconds")
		transport.ResponseHeaderTimeout = 10 * time.Second
	case 10 * time.Second:
		zerolog.Ctx(ctx).Info().
			Str("transport_name", transportName).
			Msg("Increasing response header timeout to 2.5 minutes")
		transport.ResponseHeaderTimeout = 150 * time.Second
	}
}
