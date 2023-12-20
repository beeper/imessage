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
	"crypto"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"net/http"

	"github.com/beeper/imessage/imessage/direct/util/nonce"
)

type SigningPayload []byte

func (u *User) createSigningPayload(bagKey, queryString string, body []byte) SigningPayload {
	payloadBuf := new(bytes.Buffer)
	_ = binary.Write(payloadBuf, binary.BigEndian, uint32(len(bagKey)))
	payloadBuf.WriteString(bagKey)
	_ = binary.Write(payloadBuf, binary.BigEndian, uint32(len(queryString)))
	payloadBuf.WriteString(queryString)
	_ = binary.Write(payloadBuf, binary.BigEndian, uint32(len(body)))
	payloadBuf.Write(body)
	_ = binary.Write(payloadBuf, binary.BigEndian, uint32(len(u.PushToken)))
	payloadBuf.Write(u.PushToken)
	return payloadBuf.Bytes()
}

func (u *User) addPushHeaders(req *http.Request, payload SigningPayload) error {
	n := nonce.Generate()
	req.Header.Add("X-Push-Nonce", base64.StdEncoding.EncodeToString(n))
	req.Header.Add("X-Push-Cert", base64.StdEncoding.EncodeToString(u.PushCert.Raw))
	req.Header.Add("X-Push-Token", base64.StdEncoding.EncodeToString(u.PushToken))

	sum := sha1.Sum(n.WrapPayload(payload))
	signature, err := rsa.SignPKCS1v15(nil, u.PushKey, crypto.SHA1, sum[:])
	if err != nil {
		return err
	}
	req.Header.Add("X-Push-Sig", base64.StdEncoding.EncodeToString(append([]byte{0x01, 0x01}, signature...)))
	return nil
}

func (u *User) signWithIdentity(headers map[string]string, payload SigningPayload, idCert *x509.Certificate) error {
	if idCert == nil {
		return fmt.Errorf("missing identity certificate")
	}
	n := nonce.Generate()
	headers["X-ID-Nonce"] = base64.StdEncoding.EncodeToString(n)
	headers["X-ID-Cert"] = base64.StdEncoding.EncodeToString(idCert.Raw)
	headers["X-Push-Token"] = base64.StdEncoding.EncodeToString(u.PushToken)

	sum := sha1.Sum(n.WrapPayload(payload))
	signature, err := rsa.SignPKCS1v15(nil, u.AuthPrivateKey, crypto.SHA1, sum[:])
	if err != nil {
		return err
	}
	headers["X-ID-Sig"] = base64.StdEncoding.EncodeToString(append([]byte{0x01, 0x01}, signature...))
	return nil
}

func (u *User) addAuthHeaders(req *http.Request, signingPayload SigningPayload, authSuffix string, authCert *x509.Certificate) error {
	if authCert == nil {
		return fmt.Errorf("missing auth certificate")
	}
	n := nonce.Generate()
	req.Header.Add("X-Auth-Nonce"+authSuffix, base64.StdEncoding.EncodeToString(n))
	req.Header.Add("X-Auth-Cert"+authSuffix, base64.StdEncoding.EncodeToString(authCert.Raw))

	sum := sha1.Sum(n.WrapPayload(signingPayload))
	signature, err := rsa.SignPKCS1v15(nil, u.AuthPrivateKey, crypto.SHA1, sum[:])
	if err != nil {
		return err
	}
	req.Header.Add("X-Auth-Sig"+authSuffix, base64.StdEncoding.EncodeToString(append([]byte{0x01, 0x01}, signature...)))
	return nil
}
