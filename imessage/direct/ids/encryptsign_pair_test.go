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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/beeper/imessage/imessage/direct/ids"
)

func createPairTestUser(t *testing.T) *ids.User {
	t.Helper()
	user := ids.NewUser(nil, &ids.Config{}, nil, nil, true, nil, nil)
	var err error
	user.IDSSigningKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	assert.NoError(t, err)
	user.IDSEncryptionKey, err = rsa.GenerateKey(rand.Reader, 1280)
	assert.NoError(t, err)
	return user
}

func TestPairEncryptDecryptRoundTrip(t *testing.T) {
	user1 := createPairTestUser(t)
	user2 := createPairTestUser(t)

	plaintext := bytes.Repeat([]byte{0x42}, 1024)

	encrypted, err := user1.EncryptSignPairPayload(context.TODO(), user2.PublicIdentity(), plaintext)
	assert.NoError(t, err)

	// Ensure that the EncryptSignPairPayload call doesn't mutate the plaintext.
	expected := bytes.Repeat([]byte{0x42}, 1024)
	assert.Equal(t, expected, plaintext)

	body, err := ids.ParseBody(encrypted)
	assert.NoError(t, err)

	decrypted, err := user2.DecryptSignedPairPayload(body)
	assert.NoError(t, err)
	assert.Equal(t, expected, decrypted)
}

func TestPairEncryptVerify(t *testing.T) {
	user1 := createPairTestUser(t)
	user2 := createPairTestUser(t)

	plaintext := bytes.Repeat([]byte{0x42}, 1024)

	encrypted, err := user1.EncryptSignPairPayload(context.TODO(), user2.PublicIdentity(), plaintext)
	assert.NoError(t, err)

	body, err := ids.ParseBody(encrypted)
	assert.NoError(t, err)

	verified := ids.VerifySignedPairPayload(user1.PublicIdentity(), body)
	assert.True(t, verified)
}
