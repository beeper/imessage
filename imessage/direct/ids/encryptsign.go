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

	"github.com/rs/zerolog"
	"google.golang.org/protobuf/proto"

	"github.com/beeper/imessage/imessage/direct/apns"
	"github.com/beeper/imessage/imessage/direct/ids/idsproto"
	"github.com/beeper/imessage/imessage/direct/util/ec"
	"github.com/beeper/imessage/imessage/direct/util/uri"
)

func (u *User) EncryptSignPayload(ctx context.Context, theirURI uri.ParsedURI, ident *LookupIdentity, payload []byte) ([]byte, apns.EncryptionType, error) {
	if len(payload) == 0 {
		return nil, apns.EncryptionTypePair, nil
	}
	log := zerolog.Ctx(ctx)

	if !u.enablePairECSending {
		log.Trace().Msg("pair-ec sending disabled, falling back to pair encryption")
	} else if u.NGMDeviceKey == nil || u.NGMPreKey == nil {
		log.Trace().Msg("We don't have NGM device key or prekey, falling back to pair encryption")
	} else if ident.ClientData.PublicDevicePrekey == nil || (ident.ClientData.NGMPublicIdentity == nil && (ident.KTLoggableData == nil || ident.KTLoggableData.NgmPublicIdentity == nil)) {
		log.Trace().Msg("Destination doesn't have NGM device key or prekey, falling back to pair encryption")
	} else {
		theirPreKey := ec.CompactPublicKeyFromBytes(ident.ClientData.PublicDevicePrekey.Prekey)

		var theirDeviceKey *ec.CompactPublicKey
		if ident.ClientData.NGMPublicIdentity != nil {
			theirDeviceKey = ec.CompactPublicKeyFromBytes(ident.ClientData.NGMPublicIdentity.PublicKey)
		} else {
			ngmPublicIdentity := &idsproto.NgmPublicIdentity{}
			err := proto.Unmarshal(ident.KTLoggableData.NgmPublicIdentity, ngmPublicIdentity)
			if err != nil {
				return nil, apns.EncryptionTypePairEC, err
			}
			theirDeviceKey = ec.CompactPublicKeyFromBytes(ngmPublicIdentity.PublicKey)
		}
		if !ValidatePreKey(ident.ClientData.PublicDevicePrekey, theirDeviceKey.PublicKey) {
			log.Warn().Msg("Prekey signature validation failed")
		}

		ciphertext, err := u.EncryptSignPairECPayload(ctx, theirURI, theirPreKey, theirDeviceKey, payload)
		return ciphertext, apns.EncryptionTypePairEC, err
	}

	ciphertext, err := u.EncryptSignPairPayload(ctx, ident.ClientData.PublicMessageIdentityKey, payload)
	return ciphertext, apns.EncryptionTypePair, err
}
