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
	"crypto/rsa"
	"crypto/x509"
	_ "embed"
	"encoding/pem"
)

// These keys are from
// https://github.com/MiUnlockCode/albertsimlockapple/blob/main/ALBERTBUGBYMIUNLOCK.php,
// which is licensed under the MIT license

//go:embed fairplay_id_rsa
var fairplayPrivateKeyPEM []byte

//go:embed fairplay_cert_chain
var FairplayCertChain []byte

var FairplayPrivateKey *rsa.PrivateKey

func init() {
	block, _ := pem.Decode([]byte(fairplayPrivateKeyPEM))
	if block == nil {
		panic("failed to decode fairplay private key")
	}

	var err error
	FairplayPrivateKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		panic(err)
	}
}
