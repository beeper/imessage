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

package main

import (
	"strings"
	"time"

	"github.com/beeper/imessage/imessage/direct/util/uri"
)

type BridgeInfoProfile struct {
	ID            string `json:"id"`
	Secondary     bool   `json:"secondary"`
	RefreshNeeded bool   `json:"refresh_needed"`
	IsPhoneNumber bool   `json:"is_phone_number"`
}

type BridgeInfo struct {
	CanPhoneRegister bool `json:"can_phone_register"`

	RegistrationProviderError string `json:"registration_provider_error,omitempty"`

	ApnsConnected   bool                `json:"apns_connected"`
	Handles         []uri.ParsedURI     `json:"handles"`
	DefaultHandle   uri.ParsedURI       `json:"default_handle"`
	PreferredHandle uri.ParsedURI       `json:"preferred_handle"`
	Profiles        []BridgeInfoProfile `json:"profiles,omitempty"`

	NeedsAuthRefresh    bool      `json:"needs_auth_refresh"`
	NextReregisterCheck time.Time `json:"next_reregister_check,omitempty"`
}

func GetBridgeInfo() *BridgeInfo {
	var resp BridgeInfo

	resp.ApnsConnected = global.IM.User != nil && global.IM.User.Conn != nil
	resp.CanPhoneRegister = global.IM.User != nil && global.IM.User.Versions.SoftwareName == "iPhone OS"

	nextReregisterCheck := time.Now().Add(24 * time.Hour)
	if global.IM.User != nil {
		resp.Handles = global.IM.User.Handles
		resp.DefaultHandle = global.IM.User.DefaultHandle
		resp.PreferredHandle = global.IM.User.PreferredHandle
		for profileID, certs := range global.IM.User.AuthIDCertPairs {
			resp.Profiles = append(resp.Profiles, BridgeInfoProfile{
				ID:            profileID,
				Secondary:     false,
				RefreshNeeded: certs.RefreshNeeded,
				IsPhoneNumber: strings.HasPrefix(profileID, "P:"),
			})
			resp.NeedsAuthRefresh = resp.NeedsAuthRefresh || certs.RefreshNeeded
		}
		nextReregisterCheck = global.IM.NextReregisterCheck()
	}
	if global.SecondaryIM.User != nil {
		for profileID, certs := range global.SecondaryIM.User.AuthIDCertPairs {
			resp.Profiles = append(resp.Profiles, BridgeInfoProfile{
				ID:            profileID,
				Secondary:     true,
				RefreshNeeded: certs.RefreshNeeded,
				IsPhoneNumber: strings.HasPrefix(profileID, "P:"),
			})
			resp.NeedsAuthRefresh = resp.NeedsAuthRefresh || certs.RefreshNeeded
		}
		nextReregisterCheckInSecondary := global.IM.NextReregisterCheck()
		if nextReregisterCheckInSecondary.Before(nextReregisterCheck) {
			nextReregisterCheck = nextReregisterCheckInSecondary
		}
	}
	resp.NextReregisterCheck = nextReregisterCheck.UTC()

	return &resp
}
