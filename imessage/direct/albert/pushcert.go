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
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"regexp"

	"howett.net/plist"

	"github.com/beeper/imessage/imessage/direct/ids"
	"github.com/beeper/imessage/imessage/direct/util/httputil"
)

const GeneratorVersion = 2

func GeneratePushCert(ctx context.Context, versions ids.Versions) (*rsa.PrivateKey, *x509.Certificate, error) {
	// 2048-bit also works, but use 1024-bit to match what macOS does (Apple doesn't make secure software)
	priv, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		return nil, nil, err
	}

	activationBody, err := NewActivationBody(priv, versions)
	if err != nil {
		return nil, nil, err
	}

	req, err := activationBody.ToActivationRequest(ctx)
	if err != nil {
		return nil, nil, err
	}

	_, respData, err := httputil.Do(httputil.Normal, req)
	if err != nil {
		return nil, nil, err
	}

	protocolStr := regexp.MustCompile(`(?s)<Protocol>(.*)</Protocol>`).FindSubmatch(respData)[1]

	var protocolResp ProtocolResp
	_, err = plist.Unmarshal(protocolStr, &protocolResp)
	if err != nil {
		return nil, nil, err
	}

	block, rest := pem.Decode(protocolResp.DeviceActivation.ActivationRecord.DeviceCertificate)
	if block == nil {
		return nil, nil, fmt.Errorf("failed to decode device cert")
	} else if len(rest) > 0 {
		return nil, nil, fmt.Errorf("extra data after device cert")
	}

	deviceCert, err := x509.ParseCertificate(block.Bytes)
	return priv, deviceCert, err
}
