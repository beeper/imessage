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
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"fmt"
	"net/http"

	"github.com/rs/zerolog"
	"howett.net/plist"

	"github.com/beeper/imessage/imessage/direct/util/httputil"
)

type deviceAuthenticationData struct {
	// For Apple ID login
	AuthToken string `plist:"auth-token,omitempty" json:"auth-token,omitempty"`

	// For SMS login
	PushToken  []byte   `plist:"push-token,omitempty" json:"push-token,omitempty"`
	Signatures [][]byte `plist:"sigs,omitempty" json:"sigs,omitempty"`
}

type deviceAuthenticationReq struct {
	AuthenticationData deviceAuthenticationData `plist:"authentication-data" json:"authentication-data"`
	CSR                []byte                   `plist:"csr" json:"csr"`
	RealmUserID        string                   `plist:"realm-user-id" json:"realm-user-id"`
}

type deviceAuthenticationResp struct {
	Status int    `plist:"status"`
	Cert   []byte `plist:"cert"`
}

func (u *User) getAuthCertFromReq(ctx context.Context, endpoint string, deviceAuthReq deviceAuthenticationReq) (*x509.Certificate, error) {
	log := zerolog.Ctx(ctx)
	var err error
	if u.AuthPrivateKey == nil {
		if u.AuthPrivateKey, err = rsa.GenerateKey(rand.Reader, 2048); err != nil {
			return nil, err
		}
	}

	commonName := sha1.Sum([]byte(deviceAuthReq.RealmUserID))
	template := x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: hex.EncodeToString(commonName[:]),
		},
		SignatureAlgorithm: x509.SHA256WithRSA,
	}
	deviceAuthReq.CSR, err = x509.CreateCertificateRequest(rand.Reader, &template, u.AuthPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate request: %w", err)
	}

	log.Debug().
		Str("endpoint", endpoint).
		Any("req", deviceAuthReq).
		Msg("getting auth cert from request")

	reqBody, err := plist.Marshal(deviceAuthReq, plist.XMLFormat)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	req, err := httputil.Prepare(ctx, http.MethodPost, endpoint, reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("x-protocol-version", ProtocolVersion)
	// TODO should this have a prefix string like register?
	req.Header.Set("User-Agent", u.CombinedVersion())

	_, body, err := httputil.Do(httputil.Apple, req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}

	var authResp deviceAuthenticationResp
	_, err = plist.Unmarshal(body, &authResp)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	if authResp.Status != 0 {
		return nil, fmt.Errorf("authenticating returned status %d", authResp.Status)
	}

	authCert, err := x509.ParseCertificate(authResp.Cert)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	return authCert, nil
}

func (u *User) GetAuthCert(ctx context.Context, authToken, profileID string) (*x509.Certificate, error) {
	return u.getAuthCertFromReq(ctx, idAuthenticateDSIDURL, deviceAuthenticationReq{
		AuthenticationData: deviceAuthenticationData{AuthToken: authToken},
		RealmUserID:        profileID,
	})
}

func (u *User) GetAuthCertSMS(ctx context.Context, pushToken, signature []byte, phoneNumber string) (*x509.Certificate, error) {
	return u.getAuthCertFromReq(ctx, idAuthenticatePhoneNumberURL, deviceAuthenticationReq{
		AuthenticationData: deviceAuthenticationData{
			PushToken:  pushToken,
			Signatures: [][]byte{signature},
		},
		RealmUserID: "P:" + phoneNumber,
	})
}
