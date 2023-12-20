// Copyright (C) 2023 Tulir Asokan, Sumner Evans
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

package analytics

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"

	"github.com/rs/zerolog"

	"github.com/beeper/imessage/config"
)

type BridgeType string

const (
	BridgeTypeCloud BridgeType = "imessagego bridge"
	BridgeTypeIMA   BridgeType = "imessagego ima"
)

var glog zerolog.Logger
var bridgeType BridgeType
var trackingURL, trackingToken, userID string
var client http.Client

var Version string

type TrackImplementationFunc func(event string, properties map[string]any) error

var trackImplmentationFunc TrackImplementationFunc = trackSyncOverHttp

func trackSyncOverHttp(event string, properties map[string]any) error {
	var buf bytes.Buffer
	err := json.NewEncoder(&buf).Encode(map[string]interface{}{
		"userId":     userID,
		"event":      event,
		"properties": properties,
	})
	if err != nil {
		return err
	}

	req, err := http.NewRequest(http.MethodPost, trackingURL, &buf)
	if err != nil {
		return err
	}
	req.SetBasicAuth(trackingToken, "")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	_ = resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("unexpected status code %d", resp.StatusCode)
	}
	return nil
}

func IsEnabled() bool {
	return len(trackingToken) > 0 && len(userID) > 0
}

func Track(event string, properties ...map[string]any) {
	if !IsEnabled() {
		return
	} else if len(properties) > 1 {
		panic("Track should be called with at most one property map")
	}

	go func() {
		props := map[string]interface{}{}
		if len(properties) > 0 {
			props = properties[0]
		}
		props["bridge"] = "imessagego"
		props["bridge_version"] = Version
		// Identify to mixpanel who we are
		props["mp_lib"] = bridgeType
		err := trackImplmentationFunc(event, props)
		if err != nil {
			glog.Err(err).Str("event", event).Msg("Error tracking event")
		} else {
			glog.Debug().Str("event", event).Msg("Tracked event")
		}
	}()
}

func Init(cfg config.AnalyticsConfig, log zerolog.Logger, briType BridgeType, trackFunc TrackImplementationFunc) {
	glog = log
	trackingToken = cfg.Token
	userID = cfg.UserID
	bridgeType = briType
	trackingURL = (&url.URL{
		Scheme: "https",
		Host:   cfg.Host,
		Path:   "/v1/track",
	}).String()

	if trackFunc != nil {
		trackImplmentationFunc = trackFunc
	}

	if IsEnabled() {
		log.Info().Msg("Analytics are enabled")
	}
}
