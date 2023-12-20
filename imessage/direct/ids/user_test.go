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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"testing"

	"github.com/stretchr/testify/assert"
)

func (i *UserIdentity) ToBytesLegacy() []byte {
	var out bytes.Buffer

	out.Write([]byte{0x30, 0x81, 0xF6, 0x81, 0x43}) // DER header

	out.Write([]byte{0x00, 0x41}) // ECDSA header
	// elliptic.Marshal
	out.WriteByte(0x04)
	out.Write(i.SigningKey.X.FillBytes(make([]byte, 32)))
	out.Write(i.SigningKey.Y.FillBytes(make([]byte, 32)))
	// End elliptic.Marshal

	out.Write([]byte{0x82, 0x81, 0xAE}) // another DER header

	out.Write([]byte{0x00, 0xAC}) // RSA header
	// x509.MarshalPKCS1PublicKey
	out.Write([]byte{0x30, 0x81, 0xA9}) // Inner DER header
	out.Write([]byte{0x02, 0x81, 0xA1})
	out.Write(i.EncryptionKey.N.FillBytes(make([]byte, 161)))
	// The last three bytes are the exponent (65537), same as i.EncryptionKey.E
	out.Write([]byte{0x02, 0x03, 0x01, 0x00, 0x01})
	// End MarshalPKCS1PublicKey

	return out.Bytes()
}

func (i *UserIdentity) HashLegacy() []byte {
	var out bytes.Buffer

	out.Write([]byte{0x00, 0x41, 0x04})
	out.Write(i.SigningKey.X.FillBytes(make([]byte, 32)))
	out.Write(i.SigningKey.Y.FillBytes(make([]byte, 32)))
	out.Write([]byte{0x00, 0xAC})
	out.Write([]byte{0x30, 0x81, 0xA9})
	out.Write([]byte{0x02, 0x81, 0xA1})
	out.Write(i.EncryptionKey.N.FillBytes(make([]byte, 161)))
	out.Write([]byte{0x02, 0x03, 0x01, 0x00, 0x01})

	sum := sha256.Sum256(out.Bytes())
	return sum[:]
}

func TestIdentity_ToBytes(t *testing.T) {
	x, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	y, _ := rsa.GenerateKey(rand.Reader, 1280)
	ident := &UserIdentity{
		SigningKey:    &x.PublicKey,
		EncryptionKey: &y.PublicKey,
	}
	assert.Equal(t, ident.ToBytesLegacy(), ident.ToBytes())
}

func TestIdentity_Hash(t *testing.T) {
	x, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	y, _ := rsa.GenerateKey(rand.Reader, 1280)
	ident := &UserIdentity{
		SigningKey:    &x.PublicKey,
		EncryptionKey: &y.PublicKey,
	}
	assert.Equal(t, ident.HashLegacy(), ident.Hash())
}
