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
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"math/big"

	"github.com/rs/zerolog"
	"golang.org/x/crypto/hkdf"
	"google.golang.org/protobuf/proto"

	"github.com/beeper/imessage/imessage/direct/ids/idsproto"
	"github.com/beeper/imessage/imessage/direct/util/ec"
	"github.com/beeper/imessage/imessage/direct/util/gnuzip"
	"github.com/beeper/imessage/imessage/direct/util/uri"
)

type OutgoingCounter interface {
	GetNext(ctx context.Context) (uint32, error)
}

type InMemoryOutgoingCounter struct {
	Counter uint32
}

func (c *InMemoryOutgoingCounter) GetNext(ctx context.Context) (uint32, error) {
	c.Counter++
	return c.Counter, nil
}

type OutgoingCounterStore interface {
	Get(ctx context.Context, theirURI uri.ParsedURI) (OutgoingCounter, error)
}

type InMemoryOutgoingCounterStore map[uri.ParsedURI]OutgoingCounter

func (s InMemoryOutgoingCounterStore) Get(ctx context.Context, theirURI uri.ParsedURI) (OutgoingCounter, error) {
	if s[theirURI] == nil {
		s[theirURI] = &InMemoryOutgoingCounter{}
	}
	return s[theirURI], nil
}

func createSignatureData(sharedSecret []byte, recipientPreKey, recipientSigningKey, senderEphemeralKey *ec.CompactPublicKey, inner []byte) []byte {
	signatureData := sharedSecret
	signatureData = append(signatureData, recipientPreKey.Bytes()...)
	signatureData = append(signatureData, senderEphemeralKey.Bytes()...)
	signatureData = append(signatureData, recipientSigningKey.Bytes()...)
	signatureData = append(signatureData, inner...)
	return signatureData
}

// performHKDFDerivation takes the shared secret and performs an HKDF
// derivation and returns the key and the iv.
func performHKDFDerivation(sharedSecret []byte) ([]byte, []byte, error) {
	reader := hkdf.New(sha256.New, sharedSecret, []byte("LastPawn-MessageKeys"), nil)
	key := make([]byte, 32)
	_, err := io.ReadFull(reader, key)
	if err != nil {
		return nil, nil, err
	}
	iv := make([]byte, 16)
	_, err = io.ReadFull(reader, iv)
	if err != nil {
		return nil, nil, err
	}
	return key, iv, nil
}

func createKeyValidator(senderDeviceKey, receiverSigningKey, receiverPreKey *ec.CompactPublicKey) []byte {
	keyValidator := make([]byte, 7)
	copy(keyValidator[0:2], senderDeviceKey.Bytes()[0:2])
	copy(keyValidator[2:4], receiverSigningKey.Bytes()[0:2])
	copy(keyValidator[4:6], receiverPreKey.Bytes()[0:2])
	keyValidator[6] = 0xc
	return keyValidator
}

func (u *User) EncryptSignPairECPayload(ctx context.Context, theirURI uri.ParsedURI, theirPreKey, theirDeviceKey *ec.CompactPublicKey, payload []byte) ([]byte, error) {
	counter, err := u.OutgoingCounterStore.Get(ctx, theirURI)
	if err != nil {
		return nil, err
	}
	counterValue, err := counter.GetNext(ctx)
	if err != nil {
		return nil, err
	}
	inner, err := proto.Marshal(&idsproto.InnerMessage{
		Message: payload,
		Counter: counterValue,
	})
	if err != nil {
		return nil, err
	}

	// New ephemeral public key
	ephemeralPrivKey, err := ec.NewCompactPrivateKey()
	if err != nil {
		return nil, err
	}

	ephemeralECDHKey, err := ephemeralPrivKey.ECDH()
	if err != nil {
		return nil, err
	}

	ngmPreKeyECDH, err := theirPreKey.ECDH()
	if err != nil {
		return nil, err
	}

	sharedSecret, err := ephemeralECDHKey.ECDH(ngmPreKeyECDH)
	if err != nil {
		return nil, err
	}

	key, iv, err := performHKDFDerivation(sharedSecret)
	if err != nil {
		return nil, err
	}

	paddedLength := int(math.Ceil(float64(len(inner))/16.0) * 16)
	padding := make([]byte, paddedLength-len(inner))
	_, err = rand.Read(padding)
	if err != nil {
		return nil, err
	}

	inner = append(inner, padding...)
	inner = binary.LittleEndian.AppendUint32(inner, uint32(len(padding)))

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	cipher.NewCTR(block, iv).XORKeyStream(inner, inner)

	signatureData := createSignatureData(sharedSecret, theirPreKey, theirDeviceKey, ephemeralPrivKey.PublicKey(), inner)

	hash := sha256.Sum256(signatureData)
	r, s, err := ecdsa.Sign(rand.Reader, u.NGMDeviceKey.PrivateKey, hash[:])
	if err != nil {
		return nil, err
	}
	signature := make([]byte, 64)
	r.FillBytes(signature[:32])
	s.FillBytes(signature[32:])

	return proto.Marshal(&idsproto.OuterMessage{
		EncryptedPayload: inner,
		EphemeralPubKey:  ephemeralPrivKey.PublicKey().Bytes(),
		Signature:        signature,
		KeyValidator:     createKeyValidator(u.NGMDeviceKey.PublicKey(), theirDeviceKey, theirPreKey),
	})
}

func (u *User) DeriveExistingPairECSharedSecret(ephemeralPubKeyRaw []byte) ([]byte, error) {
	ephemeralPubKey := ec.CompactPublicKeyFromBytes(ephemeralPubKeyRaw)
	ephemeralECDHKey, err := ephemeralPubKey.ECDH()
	if err != nil {
		return nil, err
	}

	ngmPreKeyECDH, err := u.NGMPreKey.ECDH()
	if err != nil {
		return nil, err
	}

	return ngmPreKeyECDH.ECDH(ephemeralECDHKey)
}

func (u *User) DecryptSignedPairECPayload(sharedSecret, payload []byte) ([]byte, error) {
	key, iv, err := performHKDFDerivation(sharedSecret)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	cipher.NewCTR(block, iv).XORKeyStream(payload, payload)

	padding := binary.LittleEndian.Uint32(payload[len(payload)-4:])

	var inner idsproto.InnerMessage
	err = proto.Unmarshal(payload[:len(payload)-int(padding)-4], &inner)
	if err != nil {
		return nil, err
	}

	// TODO (BE-18897) verify the inner.Counter here

	return gnuzip.MaybeGUnzip(inner.Message)
}

func VerifySignedPairECPayload(sharedSecret []byte, myPreKey, myDeviceKey *ec.CompactPublicKey, outer *idsproto.OuterMessage, pub *ec.CompactPublicKey) bool {
	var r, s big.Int
	r.SetBytes(outer.Signature[:32])
	s.SetBytes(outer.Signature[32:])
	hash := sha256.Sum256(createSignatureData(sharedSecret, myPreKey, myDeviceKey, ec.CompactPublicKeyFromBytes(outer.EphemeralPubKey), outer.EncryptedPayload))
	return ecdsa.Verify(pub.PublicKey, hash[:], &r, &s)
}

func VerifyKeyValidator(keyValidator []byte, senderDeviceKey, receiverSigningKey, receiverPreKey *ec.CompactPublicKey) bool {
	validator := createKeyValidator(senderDeviceKey, receiverSigningKey, receiverPreKey)
	return bytes.Equal(validator[:6], keyValidator[:6]) // Last byte of the key validator seems to be NGM version, only compare the relevant bytes
}

func (u *User) VerifySignedPairECPayload(ctx context.Context, ourURI, theirURI uri.ParsedURI, theirPushToken, sharedSecret []byte, outer *idsproto.OuterMessage) error {
	log := zerolog.Ctx(ctx).With().
		Str("identifier", theirURI.Identifier).
		Str("push_token", base64.StdEncoding.EncodeToString(theirPushToken)).
		Logger()
	lookupResult, err := u.LookupDevice(ctx, ourURI, theirURI, theirPushToken, true)
	if err != nil {
		logEvt := log.Warn().Err(err)
		if lookupResult == nil {
			logEvt.Msg("Failed to lookup identifier and no cached result")
			return fmt.Errorf("failed to lookup identifier: %w", err)
		} else {
			logEvt.Msg("Failed to lookup identifier, continuing with cached result")
		}
	}

	ngmPublicIdentity := &idsproto.NgmPublicIdentity{}
	if lookupResult.KTLoggableData != nil {
		err = proto.Unmarshal(lookupResult.KTLoggableData.NgmPublicIdentity, ngmPublicIdentity)
		if err != nil {
			return err
		}
	} else if lookupResult.ClientData.NGMPublicIdentity != nil {
		ngmPublicIdentity = lookupResult.ClientData.NGMPublicIdentity
	} else {
		return fmt.Errorf("lookup result for push token didn't contain kt loggable data or ngm public identity")
	}

	theirPublicDeviceKey := ec.CompactPublicKeyFromBytes(ngmPublicIdentity.PublicKey)

	ecVersion := outer.KeyValidator[len(outer.KeyValidator)-1]
	prekeyOK := ValidatePreKey(lookupResult.ClientData.PublicDevicePrekey, theirPublicDeviceKey.PublicKey)
	if VerifySignedPairECPayload(sharedSecret, u.NGMPreKey.PublicKey(), u.NGMDeviceKey.PublicKey(), outer, theirPublicDeviceKey) {
		log.Debug().Bool("prekey_ok", prekeyOK).Int("ec_version", int(ecVersion)).Msg("Signature verification succeeded")
		return nil
	}
	if VerifyKeyValidator(outer.KeyValidator, theirPublicDeviceKey, u.NGMDeviceKey.PublicKey(), u.NGMPreKey.PublicKey()) {
		log.Warn().Bool("prekey_ok", prekeyOK).Int("ec_version", int(ecVersion)).Msg("Signature verification failed, but key validator is fine")
		return fmt.Errorf("signature verification failed, but key validator is fine (prekey ok: %t, ec version: %d)", prekeyOK, ecVersion)
	}
	log.Warn().
		Bool("prekey_ok", prekeyOK).
		Int("ec_version", int(ecVersion)).
		Hex("expected_key_validator", createKeyValidator(theirPublicDeviceKey, u.NGMDeviceKey.PublicKey(), u.NGMPreKey.PublicKey())).
		Hex("received_key_validator", outer.KeyValidator).
		Msg("Signature and key validator verification failed")
	return fmt.Errorf("signature and key validator verification failed (prekey ok: %t, ec version: %d)", prekeyOK, ecVersion)
}
