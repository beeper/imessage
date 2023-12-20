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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/json"
	"fmt"
)

type UserIdentity struct {
	SigningKey    *ecdsa.PublicKey
	EncryptionKey *rsa.PublicKey
}

func (i *UserIdentity) MarshalJSON() ([]byte, error) {
	return json.Marshal(i.ToBytes())
}

func (i *UserIdentity) UnmarshalJSON(data []byte) error {
	var decodedData []byte
	err := json.Unmarshal(data, &decodedData)
	if err != nil {
		return err
	}
	return i.UnmarshalBinary(decodedData)
}

func (i *UserIdentity) UnmarshalBinary(data []byte) error {
	ident, err := deserializeUserIdentity(data)
	if err != nil {
		return err
	}
	*i = *ident
	return nil
}

func (i *UserIdentity) MarshalBinary() ([]byte, error) {
	return i.ToBytes(), nil
}

type asnIdentity struct {
	SigningKey    []byte `asn1:"tag:1"`
	EncryptionKey []byte `asn1:"tag:2"`
}

func deserializeUserIdentity(dat []byte) (*UserIdentity, error) {
	var ident asnIdentity
	rest, err := asn1.Unmarshal(dat, &ident)
	if err != nil {
		return nil, err
	} else if len(rest) > 0 {
		return nil, fmt.Errorf("trailing data found while deserializing ASN identity")
	}
	if ident.SigningKey[0] != 0x00 || ident.SigningKey[1] != 0x41 {
		return nil, fmt.Errorf("invalid signing key tag")
	} else if ident.EncryptionKey[0] != 0x00 || ident.EncryptionKey[1] != 0xAC {
		return nil, fmt.Errorf("invalid encryption key tag")
	}
	x, y := elliptic.Unmarshal(elliptic.P256(), ident.SigningKey[2:])
	encryptionKey, err := x509.ParsePKCS1PublicKey(ident.EncryptionKey[2:])
	if err != nil {
		return nil, err
	}
	return &UserIdentity{
		SigningKey:    &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y},
		EncryptionKey: encryptionKey,
	}, nil
}

func (i *UserIdentity) marshalSigningKey() []byte {
	return append([]byte{0x00, 0x41}, elliptic.Marshal(elliptic.P256(), i.SigningKey.X, i.SigningKey.Y)...)
}

func (i *UserIdentity) marshalEncryptionKey() []byte {
	return append([]byte{0x00, 0xAC}, x509.MarshalPKCS1PublicKey(i.EncryptionKey)...)
}

func (i *UserIdentity) ToBytes() []byte {
	out, err := asn1.Marshal(asnIdentity{
		SigningKey:    i.marshalSigningKey(),
		EncryptionKey: i.marshalEncryptionKey(),
	})
	if err != nil {
		panic(err)
	}
	return out
}

func (i *UserIdentity) Hash() []byte {
	hasher := sha256.New()
	hasher.Write(i.marshalSigningKey())
	hasher.Write(i.marshalEncryptionKey())
	return hasher.Sum(nil)
}
