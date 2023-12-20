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

package ec

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"math/big"
)

type CompactPrivateKey struct {
	*ecdsa.PrivateKey
}

func (k *CompactPrivateKey) PublicKey() *CompactPublicKey {
	return &CompactPublicKey{&k.PrivateKey.PublicKey}
}

func NewCompactPrivateKey() (*CompactPrivateKey, error) {
	curve := elliptic.P256()
	for {
		key, err := ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			return nil, err
		}
		if key.Y.Cmp(new(big.Int).Sub(curve.Params().P, key.PublicKey.Y)) <= 0 {
			return &CompactPrivateKey{PrivateKey: key}, nil
		}
	}
}

type CompactPublicKey struct {
	*ecdsa.PublicKey
}

func (c *CompactPublicKey) Bytes() []byte {
	key := make([]byte, 32)
	c.X.FillBytes(key)
	return key
}

func CompactPublicKeyFromBytes(compact []byte) *CompactPublicKey {
	if len(compact) > 32 {
		panic(fmt.Errorf("invalid compact public key (too long, %x)", compact))
	}
	curve := elliptic.P256()
	paddedCompact := make([]byte, 33)
	paddedCompact[0] = 0x03
	copy(paddedCompact[33-len(compact):], compact)
	x, y := elliptic.UnmarshalCompressed(curve, paddedCompact)
	if x == nil {
		panic(fmt.Errorf("invalid compact public key (%x)", compact))
	}
	pSubY := new(big.Int).Sub(curve.Params().P, y)
	if y.Cmp(pSubY) >= 0 {
		y = pSubY
	}
	return &CompactPublicKey{
		PublicKey: &ecdsa.PublicKey{
			Curve: curve,
			X:     x,
			Y:     y,
		},
	}
}
