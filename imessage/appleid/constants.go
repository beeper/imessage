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

package appleid

import (
	"net/url"
)

// Constants that depend on the browser and device
const (
	UserAgent      = "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0"
	Language       = "en-GB"
	AcceptLanguage = Language + ",en-US;q=0.7,en;q=0.3"
	TimeZone       = "GMT+00:00"
	TimeZoneName   = "Europe/London"
)

// Static constants
const (
	AppleIDBaseURL = "https://appleid.apple.com"
	APIKey         = "cbf64fd6843ee630b463f358ea0b707b"

	OAuthClientID     = "af1139274f266b22b68c2a3e7ad932cb3c0bbe854e13a79af78dcc73136882c3"
	OAuthRedirectURI  = AppleIDBaseURL
	OAuthResponseType = "code"
	OAuthResponseMode = "web_message"

	HdrValFDClientInfoVersion = "1.1"
	HdrValRequestContext      = "ca"
	HdrValDocumentAccept      = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8"
)

// Custom header names that are used in multiple places
const (
	HdrAuthAttributes = "X-Apple-Auth-Attributes"
	HdrAuthSessionID  = "X-Apple-ID-Session-Id"
	HdrScnt           = "scnt"
)

var idmsaBaseURL = url.URL{
	Scheme: "https",
	Host:   "idmsa.apple.com",
	Path:   authBasePath,
}
var appleIDBaseURL = url.URL{
	Scheme: "https",
	Host:   "appleid.apple.com",
	Path:   accountManageBasePath,
}

// OAuth paths (under idmsa.apple.com)
const (
	authBasePath                  = "/appleauth/auth"
	federatePath                  = authBasePath + "/federate"
	initPath                      = authBasePath + "/signin/init"
	completePath                  = authBasePath + "/signin/complete"
	trustedDeviceSecurityCodePath = authBasePath + "/verify/trusteddevice/securitycode"
	requestPhoneCodePath          = authBasePath + "/verify/phone"
	submitPhoneCodePath           = authBasePath + "/verify/phone/securitycode"
	loginIframePath               = authBasePath + "/authorize/signin"
)

// Apple ID paths (under appleid.apple.com)
const (
	additionalAuthenticatePath = "/authenticate/password"

	accountManageBasePath   = "/account/manage"
	appSpecificPasswordPath = accountManageBasePath + "/security/secondary-password"
	gsTokenPath             = accountManageBasePath + "/gs/ws/token"
)
