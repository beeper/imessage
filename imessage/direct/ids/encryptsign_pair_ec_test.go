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

package ids_test

import (
	"bytes"
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/proto"

	"github.com/beeper/imessage/imessage/direct/ids"
	"github.com/beeper/imessage/imessage/direct/ids/idsproto"
	"github.com/beeper/imessage/imessage/direct/util/ec"
	"github.com/beeper/imessage/imessage/direct/util/uri"
)

func createPairECTestUser(t *testing.T, parsedURI uri.ParsedURI) *ids.User {
	t.Helper()
	user := ids.NewUser(nil, &ids.Config{}, nil, nil, true, nil, nil)
	var err error
	user.Handles = []uri.ParsedURI{parsedURI}
	user.DefaultHandle = parsedURI
	user.NGMDeviceKey, err = ec.NewCompactPrivateKey()
	assert.NoError(t, err)
	user.NGMPreKey, err = ec.NewCompactPrivateKey()
	assert.NoError(t, err)

	keyData := user.GeneratePreKeyData()
	var prekey idsproto.PublicDevicePrekey
	err = proto.Unmarshal(keyData, &prekey)
	assert.NoError(t, err)
	assert.True(t, ids.ValidatePreKey(&prekey, user.NGMDeviceKey.PublicKey().PublicKey))

	return user
}

func TestPairECEncryptDecryptRoundTrip(t *testing.T) {
	user1 := createPairECTestUser(t, uri.ParsedURI{Scheme: uri.SchemeMailto, Identifier: "foo@example.com"})
	user2 := createPairECTestUser(t, uri.ParsedURI{Scheme: uri.SchemeMailto, Identifier: "bar@example.com"})

	plaintext := bytes.Repeat([]byte{0x42}, 1024)

	encrypted, err := user1.EncryptSignPairECPayload(context.TODO(), user2.DefaultHandle, user2.NGMPreKey.PublicKey(), user2.NGMDeviceKey.PublicKey(), plaintext)
	assert.NoError(t, err)

	// Ensure that the EncryptSignPairECPayload call doesn't mutate the plaintext.
	expected := bytes.Repeat([]byte{0x42}, 1024)
	assert.Equal(t, expected, plaintext)

	var outer idsproto.OuterMessage
	err = proto.Unmarshal(encrypted, &outer)
	assert.NoError(t, err)

	sharedSecret, err := user2.DeriveExistingPairECSharedSecret(outer.EphemeralPubKey)
	assert.NoError(t, err)

	decrypted, err := user2.DecryptSignedPairECPayload(sharedSecret, outer.EncryptedPayload)
	assert.NoError(t, err)
	assert.Equal(t, expected, decrypted)
}

func TestPairECEncryptVerify(t *testing.T) {
	user1 := createPairECTestUser(t, uri.ParsedURI{Scheme: uri.SchemeMailto, Identifier: "foo@example.com"})
	user2 := createPairECTestUser(t, uri.ParsedURI{Scheme: uri.SchemeMailto, Identifier: "bar@example.com"})

	plaintext := bytes.Repeat([]byte{0x42}, 1024)

	encrypted, err := user1.EncryptSignPairECPayload(context.TODO(), user2.DefaultHandle, user2.NGMPreKey.PublicKey(), user2.NGMDeviceKey.PublicKey(), plaintext)
	assert.NoError(t, err)

	var outer idsproto.OuterMessage
	err = proto.Unmarshal(encrypted, &outer)
	assert.NoError(t, err)

	sharedSecret, err := user2.DeriveExistingPairECSharedSecret(outer.EphemeralPubKey)
	assert.NoError(t, err)

	verified := ids.VerifySignedPairECPayload(sharedSecret, user2.NGMPreKey.PublicKey(), user2.NGMDeviceKey.PublicKey(), &outer, user1.NGMDeviceKey.PublicKey())
	assert.True(t, verified)
}

func TestPairECVerifyKeyValidator(t *testing.T) {
	user1 := createPairECTestUser(t, uri.ParsedURI{Scheme: uri.SchemeMailto, Identifier: "foo@example.com"})
	user2 := createPairECTestUser(t, uri.ParsedURI{Scheme: uri.SchemeMailto, Identifier: "bar@example.com"})

	plaintext := bytes.Repeat([]byte{0x42}, 1024)

	encrypted, err := user1.EncryptSignPairECPayload(context.TODO(), user2.DefaultHandle, user2.NGMPreKey.PublicKey(), user2.NGMDeviceKey.PublicKey(), plaintext)
	assert.NoError(t, err)

	var outer idsproto.OuterMessage
	err = proto.Unmarshal(encrypted, &outer)
	assert.NoError(t, err)

	assert.NotNil(t, outer.KeyValidator)

	verified := ids.VerifyKeyValidator(outer.KeyValidator, user1.NGMDeviceKey.PublicKey(), user2.NGMDeviceKey.PublicKey(), user2.NGMPreKey.PublicKey())
	assert.True(t, verified)
}
