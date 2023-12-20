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
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"

	"github.com/rs/zerolog"
	"go.mau.fi/util/random"

	"github.com/beeper/imessage/imessage/direct/util/uri"
)

func (u *User) EncryptSignPairPayload(ctx context.Context, key *UserIdentity, payload []byte) ([]byte, error) {
	hmacInput := append(payload, 0x02)
	hmacInput = append(hmacInput, u.PublicIdentity().Hash()...)
	hmacInput = append(hmacInput, key.Hash()...)

	seed := random.Bytes(11)
	h := hmac.New(sha256.New, seed)
	_, err := h.Write(hmacInput)
	if err != nil {
		return nil, err
	}
	aesKey := append(seed, h.Sum(nil)[:5]...)

	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, err
	}
	stream := cipher.NewCTR(block, normalIV)
	ciphertext := make([]byte, len(payload))
	stream.XORKeyStream(ciphertext, payload)

	ciphertextSplitPoint := 100
	if len(ciphertext) < 100 {
		ciphertextSplitPoint = len(ciphertext)
	}

	// Encrypt the AES key with the public key of the recipient
	rsaBody, err := rsa.EncryptOAEP(
		sha1.New(),
		rand.Reader,
		key.EncryptionKey,
		append(aesKey, ciphertext[:ciphertextSplitPoint]...),
		nil)
	if err != nil {
		return nil, err
	}

	signingBody := append(rsaBody, ciphertext[ciphertextSplitPoint:]...)
	hashedSigningBody := sha1.Sum(signingBody)
	signature, err := u.IDSSigningKey.Sign(rand.Reader, hashedSigningBody[:], crypto.SHA1)
	if err != nil {
		return nil, err
	}

	return ParsedBody{
		Tag:       0x02,
		Body:      signingBody,
		Signature: signature,
	}.Bytes(), nil
}

type ParsedBody struct {
	Tag       byte
	Body      []byte
	Signature []byte
}

func (pb ParsedBody) Bytes() []byte {
	out := make([]byte, 3+len(pb.Body)+1+len(pb.Signature))
	out[0] = 0x02
	binary.BigEndian.PutUint16(out[1:3], uint16(len(pb.Body)))
	copy(out[3:], pb.Body)
	out[3+len(pb.Body)] = byte(len(pb.Signature))
	copy(out[3+len(pb.Body)+1:], pb.Signature)
	return out
}

func ParseBody(payload []byte) (out ParsedBody, err error) {
	if len(payload) < 4 {
		err = fmt.Errorf("too short payload (missing header, expected >4, got %d)", len(payload))
		return
	}
	out.Tag = payload[0]
	bodyLength := binary.BigEndian.Uint16(payload[1:3])
	expectedLength := int(3 + bodyLength + 1)
	if len(payload) < expectedLength {
		err = fmt.Errorf("too short payload (missing body, expected >%d, got %d)", expectedLength, len(payload))
		return
	}
	out.Body = payload[3 : 3+bodyLength]
	signatureLength := payload[3+bodyLength]
	expectedLength = int(3 + bodyLength + 1 + uint16(signatureLength))
	if len(payload) < expectedLength {
		err = fmt.Errorf("too short payload (missing signature, expected %d, got %d)", expectedLength, len(payload))
		return
	} else if len(payload) > expectedLength {
		err = fmt.Errorf("too long payload (expected %d, got %d)", expectedLength, len(payload))
	}
	out.Signature = payload[3+bodyLength+1:]
	expectedLength = int(3 + bodyLength + 1 + uint16(signatureLength))
	return
}

func VerifySignedPairPayload(senderKey *UserIdentity, body ParsedBody) bool {
	msgBodyHash := sha1.Sum(body.Body)
	return ecdsa.VerifyASN1(senderKey.SigningKey, msgBodyHash[:], body.Signature)
}

func (u *User) VerifySignedPairPayload(ctx context.Context, ourURI, theirURI uri.ParsedURI, theirPushToken []byte, body ParsedBody) error {
	lookupResult, err := u.LookupDevice(ctx, ourURI, theirURI, theirPushToken, false)
	if err != nil {
		logEvt := zerolog.Ctx(ctx).Warn().Err(err).
			Str("identifier", theirURI.Identifier).
			Str("push_token", base64.StdEncoding.EncodeToString(theirPushToken))
		if lookupResult == nil {
			logEvt.Msg("Failed to lookup identifier and no cached result")
			return fmt.Errorf("failed to lookup identifier: %w", err)
		} else {
			logEvt.Msg("Failed to lookup identifier, continuing with cached result")
		}
	}
	if lookupResult.ClientData.PublicMessageIdentityKey == nil {
		return fmt.Errorf("lookup result for push token didn't contain public message identity")
	} else if !VerifySignedPairPayload(lookupResult.ClientData.PublicMessageIdentityKey, body) {
		return fmt.Errorf("message signature didn't match")
	}
	return nil
}

func (u *User) DecryptSignedPairPayload(body ParsedBody) ([]byte, error) {
	if len(body.Body) < 160 {
		return nil, fmt.Errorf("too short payload (missing encryption key, expected >160, got %d)", len(body.Body))
	}
	encryptedEncryptionKey := body.Body[:160]
	actualEncryptedMessage := body.Body[160:]
	decryptedEncryptionKey, err := rsa.DecryptOAEP(sha1.New(), rand.Reader, u.IDSEncryptionKey, encryptedEncryptionKey, nil)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(decryptedEncryptionKey[:16])
	if err != nil {
		return nil, err
	}
	decryptionInput := append(decryptedEncryptionKey[16:], actualEncryptedMessage...)
	cipher.NewCTR(block, normalIV).XORKeyStream(decryptionInput, decryptionInput)
	return decryptionInput, nil
}
