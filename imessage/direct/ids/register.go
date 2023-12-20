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
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"howett.net/plist"

	"github.com/beeper/imessage/imessage/direct/apns"
	"github.com/beeper/imessage/imessage/direct/ids/idsproto"
	"github.com/beeper/imessage/imessage/direct/ids/types"
	"github.com/beeper/imessage/imessage/direct/util/ec"
	"github.com/beeper/imessage/imessage/direct/util/httputil"
	"github.com/beeper/imessage/imessage/direct/util/plistuuid"
	"github.com/beeper/imessage/imessage/direct/util/uri"
)

type RegisterReq struct {
	DeviceName        string            `plist:"device-name"`
	HardwareVersion   string            `plist:"hardware-version"`
	Language          string            `plist:"language"`
	OSVersion         string            `plist:"os-version"`
	SoftwareVersion   string            `plist:"software-version"`
	PrivateDeviceData PrivateDeviceData `plist:"private-device-data"`
	Services          []RegisterService `plist:"services"`
	ValidationData    []byte            `plist:"validation-data"`
}

type PrivateDeviceData struct {
	AP string `plist:"ap,omitempty"` // "0" on mac, "1" on iphone/ipad

	C string `plist:"c,omitempty"` // "1", not on Macs, only iPhones/iPads?

	D  string `plist:"d,omitempty"`  // Seconds (with floating point microseconds) since Apple epoch (2001-01-01 00:00 UTC)
	DT int    `plist:"dt,omitempty"` // 1 on macs, 2 on iphones, 4 on ipads? perhaps device type?
	EC string `plist:"ec,omitempty"` // "1", not on Macs, only iPhones/iPads?
	GT string `plist:"gt,omitempty"` // "0"
	H  string `plist:"h,omitempty"`  // "1"

	KTF string `plist:"ktf,omitempty"` // "0" or "1"
	KTV int    `plist:"ktv,omitempty"` // observed values: "70", 75, 81, 87

	M string `plist:"m,omitempty"` // "0" on mac/ipad, "1" on iphone
	P string `plist:"p,omitempty"` // "0" on mac/ipad, "1" on iphone

	SoftwareBuild   string `plist:"pb,omitempty"` // 22F82
	SoftwareName    string `plist:"pn,omitempty"` // "macOS" (or "iPhone OS" for ios)
	SoftwareVersion string `plist:"pv,omitempty"` // 13.4.1

	S    string         `plist:"s,omitempty"` // "0"
	T    string         `plist:"t,omitempty"` // "0"
	UUID plistuuid.UUID `plist:"u,omitempty"`
	V    string         `plist:"v,omitempty"` // "1", version?
}

type RegisterService struct {
	Capabilities []RegisterServiceCapabilities `plist:"capabilities"`
	Service      apns.Topic                    `plist:"service"`
	SubServices  []apns.Topic                  `plist:"sub-services"`
	Users        []RegisterServiceUser         `plist:"users"`
}

type RegisterServiceUser struct {
	ClientData     map[string]any                        `plist:"client-data"`
	Tag            string                                `plist:"tag,omitempty"`
	URIs           []Handle                              `plist:"uris"`
	UserID         string                                `plist:"user-id"`
	KTLoggableData *idsproto.KeyTransparencyLoggableData `plist:"kt-loggable-data"`
}

type RegisterServiceCapabilities struct {
	Flags   int    `plist:"flags"`
	Name    string `plist:"name"`
	Version int    `plist:"version"`
}

type RespHandle struct {
	URI    string          `plist:"uri"`
	Status types.IDSStatus `plist:"status"`
}

type RegisterRespAlertAction struct {
	Button string `plist:"button"`
	Type   int    `plist:"type"`
	URL    string `plist:"url"`
}

type RegisterRespAlert struct {
	Body   string `plist:"body"`
	Button string `plist:"button"`
	Title  string `plist:"title"`

	Action RegisterRespAlertAction `plist:"action"`
}

type RegisterRespServiceUser struct {
	URIs   []RespHandle       `plist:"uris"`
	UserID string             `plist:"user-id"`
	Cert   []byte             `plist:"cert"`
	Status types.IDSStatus    `plist:"status"`
	Alert  *RegisterRespAlert `plist:"alert"`
}

type RegisterRespService struct {
	Service string                    `plist:"service"`
	Users   []RegisterRespServiceUser `plist:"users"`
	Status  types.IDSStatus           `plist:"status"`
}

type RegisterResp struct {
	Message  string                `plist:"message"`
	Status   types.IDSStatus       `plist:"status"`
	Services []RegisterRespService `plist:"services"`

	RetryInterval int `plist:"retry-interval"`
}

type DependentRegistration struct {
	ClientData         LookupIdentityClientData `plist:"client-data"`
	DeviceName         string                   `plist:"device-name"`
	HardwareVersion    string                   `plist:"hardware-version"`
	Identities         []Handle                 `plist:"identities"`
	IsHSATrustedDevice bool                     `plist:"is-hsa-trusted-device"`
	PrivateDeviceData  PrivateDeviceData        `plist:"private-device-data"`
	PushToken          []byte                   `plist:"push-token"`
	SelfHandle         string                   `plist:"self-handle"`
	Service            apns.Topic               `plist:"service"`
	SubServices        []apns.Topic             `plist:"sub-services"`
	// This contains phone number URIs for iPhones that have registered a phone number
	LinkedUserURI []uri.ParsedURI `plist:"linked-user-uri"`
}

type RespDependentRegistrations struct {
	ExpiryEpochMillis int64                   `plist:"expiry-epoch-milli-sec"`
	Status            types.IDSStatus         `plist:"status"`
	Registrations     []DependentRegistration `plist:"registrations"`
}

func (u *User) HasIDSKeys() bool {
	return u.IDSSigningKey != nil && u.IDSEncryptionKey != nil
}

var AppleEpoch = time.Date(2001, 1, 1, 0, 0, 0, 0, time.UTC)
var DeviceName = "beeper-imessage"

func (u *User) TriggerReroute(ctx context.Context, url, token string) error {
	log := zerolog.Ctx(ctx)
	log.Info().Str("url", url).Msg("Rerouting user")
	req, err := httputil.Prepare(ctx, http.MethodPost, url, nil)
	if err != nil {
		return fmt.Errorf("failed to prepare request: %w", err)
	}
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

	resp, _, err := httputil.Do(httputil.Normal, req)
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	} else if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected response status %d", resp.StatusCode)
	}

	return nil
}

func (u *User) Register(ctx context.Context, handles map[string][]Handle, validationData []byte) error {
	return u.RegisterSpecificAuthCerts(ctx, handles, validationData, u.AuthIDCertPairs)
}

func (u *User) RegisterSpecificAuthCerts(ctx context.Context, handles map[string][]Handle, validationData []byte, certPairs map[string]*AuthIDCertPair) error {
	log := zerolog.Ctx(ctx)

	var err error
	if u.IDSSigningKey == nil {
		u.IDSSigningKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return fmt.Errorf("failed to generate IDS signing key: %w", err)
		}
	}
	if u.IDSEncryptionKey == nil {
		u.IDSEncryptionKey, err = rsa.GenerateKey(rand.Reader, 1280)
		if err != nil {
			return fmt.Errorf("failed to generate IDS encryption key: %w", err)
		}
	}
	if u.NGMDeviceKey == nil {
		u.NGMDeviceKey, err = ec.NewCompactPrivateKey()
		if err != nil {
			return fmt.Errorf("failed to generate NGM device key: %w", err)
		}
	}
	if u.NGMPreKey == nil {
		u.NGMPreKey, err = ec.NewCompactPrivateKey()
		if err != nil {
			return fmt.Errorf("failed to generate NGM pre key: %w", err)
		}
	}

	if u.DeviceUUID == uuid.Nil {
		u.DeviceUUID = uuid.New()
	}

	var users []RegisterServiceUser
	hasCerts := len(certPairs) > 0
	for profileID := range certPairs {
		var tag string
		if strings.HasPrefix(profileID, "P:") {
			tag = "SIM"
		}

		rsu := RegisterServiceUser{
			Tag: tag,
			ClientData: map[string]any{
				"nicknames-version":                    1,
				"optionally-receive-typing-indicators": true,
				"prefers-sdr":                          false,
				"show-peer-errors":                     true,
				"supports-ack-v1":                      true,
				"supports-animoji-v2":                  true,
				"supports-askto":                       true, // ios 17
				"supports-audio-messaging-v2":          true,
				"supports-autoloopvideo-v1":            true,
				"supports-be-v1":                       true,
				"supports-ca-v1":                       true,
				"supports-cross-platform-sharing":      true,
				"supports-dq-nr":                       true,
				"supports-emoji-stickers":              true, // ios 17?
				"supports-findmy-plugin-messages":      true, // ios 17/macos 14
				"supports-fsm-v1":                      true,
				"supports-fsm-v2":                      true,
				"supports-fsm-v3":                      true,
				"supports-hdr":                         true,
				"supports-heif":                        true,
				"supports-ii-v1":                       true,
				"supports-impact-v1":                   true,
				"supports-inline-attachments":          true,
				"supports-keep-receipts":               true,
				"supports-location-sharing":            true,
				"supports-media-v2":                    true,
				"supports-original-timestamp-v1":       true,
				"supports-people-request-messages":     true,
				"supports-people-request-messages-v2":  true,
				"supports-people-request-messages-v3":  true,
				"supports-photos-extension-v1":         true,
				"supports-photos-extension-v2":         true,
				"supports-protobuf-payload-data-v2":    true,
				"supports-recurring-payment-bubbles":   true, // macos only?
				"supports-rem":                         true,
				"supports-sa-v1":                       true,
				"supports-st-v1":                       true,
				"supports-sticker-editing":             true, // ios 17/macos 14
				"supports-update-attachments-v1":       true,

				//"supports-activity-sharing-v1":          true, // iphone only? (not even ipad)
				//"supports-family-invite-message-bubble": true, // iphone only?
				//"supports-live-delivery":                true, // iphone only?
				//"supports-sos-alerting":                 true, // iphone only?
				//"supports-uwb":                          true, // ios 17, iphone only?
				//"supports-zelkova":                      true, // ios 17, iphone only?

				// TODO implement certified delivery
				//"supports-certified-delivery-v1":        true,

				// ios 17/macos 14, likely hybrid SMS/iMessage groups. TODO: test and enable
				//"supports-hybrid-groups-v1": true,

				// removed in ios 17?
				//"supports-shared-exp":                   true,

				// what was this? it's not on ios 16 either, removed long ago?
				//"is-c2k-equipment":                      true,
			},
			URIs:   handles[profileID],
			UserID: profileID,
		}
		if !u.DontPublishKeys {
			// legacy pair encryption
			rsu.ClientData["public-message-identity-key"] = u.PublicIdentity().ToBytes()
			rsu.ClientData["public-message-identity-version"] = 2

			// pair-ec encryption
			rsu.ClientData["ec-version"] = 1
			rsu.ClientData["public-message-identity-ngm-version"] = 13
			rsu.ClientData["public-message-ngm-device-prekey-data-key"] = u.GeneratePreKeyData()
			rsu.ClientData["kt-version"] = 5
			rsu.KTLoggableData = u.GenerateLoggableData()
		}
		users = append(users, rsu)
	}

	const registerService = "com.apple.madrid"
	registerReq := RegisterReq{
		DeviceName:      DeviceName,
		HardwareVersion: u.HardwareVersion,
		Language:        "en-US",
		OSVersion:       u.IDSOSVersion(),
		SoftwareVersion: u.SoftwareBuildID,
		PrivateDeviceData: PrivateDeviceData{
			AP: "0",
			D:  fmt.Sprintf("%.6f", time.Now().Sub(AppleEpoch).Seconds()),
			DT: 1,
			GT: "0",
			H:  "1",
			//KTF: "0",
			//KTV: 87,
			M: "0",
			P: "0",

			SoftwareBuild:   u.SoftwareBuildID,
			SoftwareName:    u.SoftwareName,
			SoftwareVersion: u.SoftwareVersion,

			S:    "0",
			T:    "0",
			UUID: plistuuid.NewFromUUID(u.DeviceUUID),
			V:    "1",
		},
		Services: []RegisterService{{
			Capabilities: []RegisterServiceCapabilities{{
				Flags:   1,
				Name:    "Messenger",
				Version: 1,
			}},
			Service: apns.TopicMadrid,
			SubServices: []apns.Topic{
				apns.TopicAlloyGamecenteriMessage,
				apns.TopicAlloySafetyMonitor,
				apns.TopicAlloyBiz,
				apns.TopicAlloySMS,
				apns.TopicAlloySafetyMonitorOwnAccount,
				apns.TopicAlloyGelato,
				apns.TopicAlloyAskTo,
			},
			Users: users,
		}},
		ValidationData: validationData,
	}

	body, err := plist.Marshal(&registerReq, plist.XMLFormat)
	if err != nil {
		return fmt.Errorf("failed to marshal register request payload: %w", err)
	}
	req, err := httputil.Prepare(ctx, http.MethodPost, idsRegisterURL, body)
	if err != nil {
		return fmt.Errorf("failed to prepare register request: %w", err)
	}
	req.Header.Set("X-Protocol-Version", ProtocolVersion)
	req.Header.Set("User-Agent", fmt.Sprintf("com.apple.invitation-registration %s", u.CombinedVersion()))

	signingPayload := u.createSigningPayload("id-register", "", body)

	// Always sign with the push token.
	if err := u.addPushHeaders(req, signingPayload); err != nil {
		return fmt.Errorf("failed to add push headers: %w", err)
	}

	// Sign separately with each auth cert.
	var i int
	for profileID, certs := range certPairs {
		suffix := fmt.Sprintf("-%d", i)
		req.Header.Set(fmt.Sprintf("X-Auth-User-ID%s", suffix), profileID)

		if err := u.addAuthHeaders(req, signingPayload, suffix, certs.AuthCert); err != nil {
			return fmt.Errorf("failed to sign register request: %w", err)
		}
		i++
	}

	_, data, err := httputil.Do(httputil.Apple, req)
	if err != nil {
		return fmt.Errorf("failed to send register request: %w", err)
	}
	var respData RegisterResp
	err = plist.NewDecoder(bytes.NewReader(data)).Decode(&respData)
	if err != nil {
		return fmt.Errorf("failed to parse register response plist: %w", err)
	}

	if log.Trace().Enabled() {
		log.Trace().Any("resp", respData).Msg("DEBUG: Parsed register response")
		var respDataRaw map[string]any
		err = plist.NewDecoder(bytes.NewReader(data)).Decode(&respDataRaw)
		if err != nil {
			return fmt.Errorf("failed to decode response data to raw map: %w", err)
		}
		log.Trace().Any("resp_raw", respDataRaw).Msg("DEBUG: Raw register response")
	}

	if !hasCerts {
		log.Debug().Msg("Re-registered without auth certs, not trying to parse response")
		return nil
	} else if respData.Status != 0 {
		return fmt.Errorf("unexpected status in register response (top-level): %s", respData.Status.String())
	} else if len(respData.Services) == 0 {
		return fmt.Errorf("no services received in register response")
	} else if respData.Services[0].Service != registerService {
		return fmt.Errorf("unexpected service in register response: %s (status %s)", respData.Services[0].Service, respData.Services[0].Status.String())
	} else if respData.Services[0].Status != 0 {
		return fmt.Errorf("unexpected status in register response: %s", respData.Services[0].Status.String())
	}

	for _, user := range respData.Services[0].Users {
		if user.Status != 0 {
			if user.Status == types.IDSStatusActionRefreshCredentials {
				existingPair, ok := u.AuthIDCertPairs[user.UserID]
				if ok {
					existingPair.RefreshNeeded = true
				}
			}
			return RegisterError{
				Alert:  user.Alert,
				Status: user.Status,
				UserID: user.UserID,
			}
		} else if user.Cert == nil {
			return fmt.Errorf("no cert for user %s in register response", user.UserID)
		} else if idCert, err := x509.ParseCertificate(user.Cert); err != nil {
			return fmt.Errorf("failed to parse cert for user %s in register response: %w", user.UserID, err)
		} else {
			u.AuthIDCertPairs[user.UserID].IDCert = idCert
			u.AuthIDCertPairs[user.UserID].RefreshNeeded = false
		}
	}
	u.IDRegisteredAt = time.Now()
	return nil
}

type RegisterError struct {
	Alert  *RegisterRespAlert
	Status types.IDSStatus
	UserID string
}

func (re RegisterError) Is(other error) bool {
	var idsErr types.IDSError
	return errors.As(other, &idsErr) && idsErr.ErrorCode == re.Status
}

func (re RegisterError) Unwrap() error {
	return types.IDSError{ErrorCode: re.Status}
}

func (re RegisterError) Error() string {
	if re.Alert != nil {
		return fmt.Sprintf("got error alert for user %s (status %s): %s", re.UserID, re.Status.String(), re.Alert.Body)
	}
	return fmt.Sprintf("unexpected status %s for user %s in register response", re.Status.String(), re.UserID)
}

type reqGetDependentRegistration struct {
	RetryCount int `plist:"retry-count"`
}

func (u *User) GetDependentRegistrations(ctx context.Context, profileID string) (map[string]any, error) {
	reqData, err := plist.Marshal(&reqGetDependentRegistration{
		RetryCount: 0,
	}, plist.XMLFormat)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}
	req, err := httputil.Prepare(ctx, http.MethodPost, idGetDependentRegistrationsURL, reqData)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-apple-plist")
	req.Header.Set("X-Protocol-Version", ProtocolVersion)
	req.Header.Set("X-Auth-User-ID", profileID)
	req.Header.Set("User-Agent", fmt.Sprintf("com.apple.invitation-registration %s", u.CombinedVersion()))

	if certs, ok := u.AuthIDCertPairs[profileID]; !ok {
		return nil, fmt.Errorf("no auth id cert pair for %s", profileID)
	} else {
		signingPayload := u.createSigningPayload("id-get-dependent-registrations", "", reqData)
		if err = u.addPushHeaders(req, signingPayload); err != nil {
			return nil, err
		} else if err = u.addAuthHeaders(req, signingPayload, "", certs.AuthCert); err != nil {
			return nil, err
		}
	}

	_, body, err := httputil.Do(httputil.Apple, req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}

	var resp map[string]any
	_, err = plist.Unmarshal(body, &resp)
	if err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}
	return resp, nil
}
