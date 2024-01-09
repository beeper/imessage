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

package albert

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"net/http"
	"net/url"
	"strings"

	"github.com/google/uuid"
	"go.mau.fi/util/random"
	"howett.net/plist"

	"github.com/beeper/imessage/imessage/direct/ids"
	"github.com/beeper/imessage/imessage/direct/util/httputil"
)

const AlbertDeviceRegistrationURL = "https://albert.apple.com/deviceservices/deviceActivation?device=MacOS"

type ActivationInfo struct {
	ActivationRandomness string `plist:"ActivationRandomness"`
	ActivationState      string `plist:"ActivationState"`
	BuildVersion         string `plist:"BuildVersion"`
	DeviceCertRequest    []byte `plist:"DeviceCertRequest"`
	DeviceClass          string `plist:"DeviceClass"`
	ProductType          string `plist:"ProductType"`
	ProductVersion       string `plist:"ProductVersion"`
	SerialNumber         string `plist:"SerialNumber"`
	UniqueDeviceID       string `plist:"UniqueDeviceID"`
}

func NewActivationInfo(privateKey *rsa.PrivateKey, versions ids.Versions) (*ActivationInfo, error) {
	template := x509.CertificateRequest{
		Subject: pkix.Name{
			Country:            []string{"US"},
			Province:           []string{"CA"},
			Locality:           []string{"Cupertino"},
			Organization:       []string{"Apple Inc."},
			OrganizationalUnit: []string{"iPhone"},
			CommonName:         "Client Push Certificate",
		},
		SignatureAlgorithm: x509.SHA1WithRSA, // Macs use SHA-1. SHA-256 may work (or the server may ignore it)
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &template, privateKey)
	if err != nil {
		return nil, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr})

	deviceClass := versions.SoftwareName
	if deviceClass == "macOS" || deviceClass == "Mac OS X" {
		deviceClass = "MacOS"
	}
	udid := versions.UniqueDeviceID
	if udid == "" {
		udid = strings.ToUpper(uuid.New().String())
	}
	serialNumber := versions.SerialNumber
	if serialNumber == "" {
		serialNumber = strings.ToUpper(random.String(12))
	}
	return &ActivationInfo{
		ActivationRandomness: strings.ToUpper(uuid.New().String()),
		ActivationState:      "Unactivated",
		DeviceCertRequest:    certPEM,
		DeviceClass:          deviceClass,
		ProductType:          versions.HardwareVersion,
		ProductVersion:       versions.SoftwareVersion,
		BuildVersion:         versions.SoftwareBuildID,
		SerialNumber:         serialNumber,
		UniqueDeviceID:       udid,
	}, nil
}

type ActivationBody struct {
	ActivationInfoComplete bool   `plist:"ActivationInfoComplete"`
	ActivationInfoXML      []byte `plist:"ActivationInfoXML"`
	FairPlayCertChain      []byte `plist:"FairPlayCertChain"`
	FairPlaySignature      []byte `plist:"FairPlaySignature"`
}

func NewActivationBody(privateKey *rsa.PrivateKey, versions ids.Versions) (*ActivationBody, error) {
	activationInfo, err := NewActivationInfo(privateKey, versions)
	if err != nil {
		return nil, err
	}

	activationInfoXML, err := plist.Marshal(activationInfo, plist.XMLFormat)
	if err != nil {
		return nil, err
	}

	sum := sha1.Sum(activationInfoXML)
	signature, err := rsa.SignPKCS1v15(nil, FairplayPrivateKey, crypto.SHA1, sum[:])
	if err != nil {
		return nil, err
	}

	return &ActivationBody{
		ActivationInfoComplete: true,
		ActivationInfoXML:      activationInfoXML,
		FairPlayCertChain:      FairplayCertChain,
		FairPlaySignature:      signature,
	}, nil
}

func (r *ActivationBody) ToActivationRequest(ctx context.Context) (*http.Request, error) {
	activationInfoPlistBytes, err := plist.Marshal(r, plist.XMLFormat)
	if err != nil {
		return nil, err
	}

	formData := url.Values{}
	formData.Set("activation-info", string(activationInfoPlistBytes))

	req, err := httputil.Prepare(ctx, http.MethodPost, AlbertDeviceRegistrationURL, []byte(formData.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	return req, err
}

type ProtocolResp struct {
	DeviceActivation struct {
		AckReceived      bool `plist:"ack-received"`
		ActivationRecord struct {
			DeviceCertificate []byte `plist:"DeviceCertificate"`
		} `plist:"activation-record"`
		ShowSettings bool `plist:"show-settings"`
	} `plist:"device-activation"`
}
