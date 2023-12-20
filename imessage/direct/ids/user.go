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
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"math/big"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/rs/zerolog"
	"google.golang.org/protobuf/proto"
	"howett.net/plist"

	"github.com/beeper/imessage/imessage/direct/apns"
	"github.com/beeper/imessage/imessage/direct/ids/idsproto"
	"github.com/beeper/imessage/imessage/direct/ids/types"
	"github.com/beeper/imessage/imessage/direct/util/httputil"
	"github.com/beeper/imessage/imessage/direct/util/uri"
)

const ProtocolVersion = "1640"

type parentRegisterIDS func(ctx context.Context, force bool) error

type User struct {
	*Config
	LookupCache    LookupCache
	RerouteHistory RerouteHistory
	Conn           *apns.Connection

	enablePairECSending  bool
	OutgoingCounterStore OutgoingCounterStore
	DontPublishKeys      bool

	parentRegisterIDS    parentRegisterIDS
	lastLookupReregister time.Time
	lookupErrorCount     int
}

func NewUser(conn *apns.Connection, cfg *Config, lookupCache LookupCache, rerouteHistory RerouteHistory, enablePairECSending bool, outgoingCounterStore OutgoingCounterStore, parentRegisterIDS parentRegisterIDS) *User {
	if lookupCache == nil {
		lookupCache = make(InMemoryLookupCache)
	}
	if rerouteHistory == nil {
		rerouteHistory = make(InMemoryRerouteHistory)
	}
	if outgoingCounterStore == nil {
		outgoingCounterStore = make(InMemoryOutgoingCounterStore)
	}
	return &User{
		Config:         cfg,
		Conn:           conn,
		LookupCache:    lookupCache,
		RerouteHistory: rerouteHistory,

		enablePairECSending:  enablePairECSending,
		OutgoingCounterStore: outgoingCounterStore,

		parentRegisterIDS: parentRegisterIDS,
	}
}

func (u *User) HasAuthCerts() bool {
	if u.AuthPrivateKey == nil {
		return false
	}
	for _, pair := range u.AuthIDCertPairs {
		if pair.AuthCert != nil && !pair.RefreshNeeded {
			return true
		}
	}
	return false
}

func (u *User) HasValidIDCerts() bool {
	for _, pair := range u.AuthIDCertPairs {
		if pair.IDCert != nil && !pair.RefreshNeeded {
			return true
		}
	}
	return false
}

func (u *User) NeedsRefresh() bool {
	for _, pair := range u.AuthIDCertPairs {
		if pair.AuthCert != nil && pair.RefreshNeeded {
			return true
		}
	}
	return false
}

func (u *User) PublicIdentity() *UserIdentity {
	return &UserIdentity{
		SigningKey:    &u.IDSSigningKey.PublicKey,
		EncryptionKey: &u.IDSEncryptionKey.PublicKey,
	}
}

type Handle struct {
	URI uri.ParsedURI `plist:"uri"`
}

type getHandlesResp struct {
	Status  types.IDSStatus `plist:"status"`
	Handles []Handle        `plist:"handles"`
}

func (u *User) fetchHandles(ctx context.Context, profileID string, certs *AuthIDCertPair) ([]Handle, error) {
	req, err := httputil.Prepare(ctx, http.MethodGet, idGetHandlesURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Protocol-Version", ProtocolVersion)
	req.Header.Set("X-Auth-User-ID", profileID)
	// TODO should this have a prefix string like register?
	req.Header.Set("User-Agent", u.CombinedVersion())

	signingPayload := u.createSigningPayload("id-get-handles", "", nil)
	if err = u.addPushHeaders(req, signingPayload); err != nil {
		return nil, err
	} else if err = u.addAuthHeaders(req, signingPayload, "", certs.AuthCert); err != nil {
		return nil, err
	}

	_, body, err := httputil.Do(httputil.Apple, req)
	if err != nil {
		return nil, err
	}

	var handlesResp getHandlesResp
	_, err = plist.Unmarshal(body, &handlesResp)
	if err != nil {
		return nil, err
	} else if handlesResp.Handles == nil && handlesResp.Status != types.IDSStatusSuccess {
		return nil, types.IDSError{ErrorCode: handlesResp.Status}
	}

	return handlesResp.Handles, nil
}

func (u *User) UpdateHandles(ctx context.Context) (bool, map[string][]Handle, []string, error) {
	var newHandles []uri.ParsedURI
	fetchedHandles := make(map[string][]Handle)
	var refreshCredentials []string
	for profileID, certs := range u.AuthIDCertPairs {
		profileHandles, err := u.fetchHandles(ctx, profileID, certs)
		if errors.Is(err, types.ErrActionRefreshCredentials) {
			zerolog.Ctx(ctx).Err(err).Msg("Fetching handles failed, sending credential refresh required event")
			u.AuthIDCertPairs[profileID].RefreshNeeded = true
			refreshCredentials = append(refreshCredentials, profileID)
		} else if err != nil {
			return false, nil, refreshCredentials, err
		}

		for _, handle := range profileHandles {
			newHandles = append(newHandles, handle.URI)
		}
		fetchedHandles[profileID] = profileHandles
	}

	changed := u.UpdateHandlesIfChanged(ctx, newHandles)
	return changed, fetchedHandles, refreshCredentials, nil
}

func (u *User) UpdateHandlesIfChanged(ctx context.Context, handles []uri.ParsedURI) bool {
	log := zerolog.Ctx(ctx)
	// Sort handles so phone numbers are first and there are no duplicates
	handles = uri.Sort(handles)

	changed := !slices.Equal(u.Handles, handles)
	log.Debug().
		Array("old_handles", uri.ToZerologArray(u.Handles)).
		Array("new_handles", uri.ToZerologArray(handles)).
		Bool("changed", changed).
		Msg("Checking for changes in handles")
	u.Handles = handles

	// If default handle is not set or is not available anymore, reset to first (best) handle.
	if (u.DefaultHandle.IsEmpty() || !slices.Contains(u.Handles, u.DefaultHandle)) && len(u.Handles) != 0 {
		log.Debug().
			Str("old_default_handle", u.DefaultHandle.String()).
			Str("new_default_handle", u.Handles[0].String()).
			Msg("Changing default handle")
		u.DefaultHandle = u.Handles[0]
		changed = true
	}
	// If a preferred handle isn't set and there's a phone number handle, set the phone number handle as preferred.
	// This means if the phone number drops and then comes back, we'll switch back to the phone automatically,
	// even if the user never explicitly picked the phone number as preferred.
	if u.PreferredHandle.IsEmpty() && len(u.Handles) > 0 && u.Handles[0].Scheme == uri.SchemeTel {
		if u.DefaultHandle.Scheme == uri.SchemeTel {
			u.PreferredHandle = u.DefaultHandle
		} else {
			u.PreferredHandle = u.Handles[0]
		}
		log.Debug().
			Str("new_preferred_handle", u.PreferredHandle.String()).
			Msg("Saving current default handle as preferred handle")
	}
	// If a preferred handle is set (either by the user manually or by the previous if), is available,
	// and is not already set as the default, change it to be the default.
	// This means phone number handles or the user's preferred handle will always be re-set as the default,
	// even if they're temporarily lost from the available handle list.
	if !u.PreferredHandle.IsEmpty() && u.DefaultHandle != u.PreferredHandle && slices.Contains(u.Handles, u.PreferredHandle) {
		log.Debug().
			Str("old_default_handle", u.DefaultHandle.String()).
			Str("new_default_handle", u.PreferredHandle.String()).
			Msg("Changing default handle to preferred handle")
		u.DefaultHandle = u.PreferredHandle
		changed = true
	}

	return changed
}

func makeNGMPrekeySignatureData(key []byte, ts float64, enc binary.ByteOrder) []byte {
	var toSign bytes.Buffer
	toSign.WriteString("NGMPrekeySignature")
	toSign.Write(key)
	_ = binary.Write(&toSign, enc, ts)

	hashed := sha256.Sum256(toSign.Bytes())
	return hashed[:]
}

func ValidatePreKey(key *idsproto.PublicDevicePrekey, deviceKey *ecdsa.PublicKey) bool {
	var r, s big.Int
	r.SetBytes(key.PrekeySignature[:32])
	s.SetBytes(key.PrekeySignature[32:])
	return ecdsa.Verify(deviceKey, makeNGMPrekeySignatureData(key.Prekey, key.Timestamp, binary.LittleEndian), &r, &s)
}

func (u *User) GeneratePreKeyData() []byte {
	now := float64(time.Now().Unix())

	r, s, err := ecdsa.Sign(rand.Reader, u.NGMDeviceKey.PrivateKey, makeNGMPrekeySignatureData(u.NGMPreKey.PublicKey().Bytes(), now, binary.LittleEndian))
	if err != nil {
		panic(err)
	}

	signature := make([]byte, 64)
	r.FillBytes(signature[:32])
	s.FillBytes(signature[32:])
	prekeyData, err := proto.Marshal(&idsproto.PublicDevicePrekey{
		Prekey:          u.NGMPreKey.PublicKey().Bytes(),
		PrekeySignature: signature,
		Timestamp:       now,
	})
	if err != nil {
		panic(err)
	}
	return prekeyData
}

func (u *User) GenerateLoggableData() *idsproto.KeyTransparencyLoggableData {
	identity, err := proto.Marshal(&idsproto.NgmPublicIdentity{
		PublicKey: u.NGMDeviceKey.PublicKey().Bytes(),
	})
	if err != nil {
		panic(err)
	}

	return &idsproto.KeyTransparencyLoggableData{
		NgmPublicIdentity: identity,
		NgmVersion:        proto.Uint32(13),
		KtVersion:         proto.Uint32(5),
	}
}

func (u *User) GetPhoneRegistrationHandle() *uri.ParsedURI {
	for authID := range u.AuthIDCertPairs {
		if strings.HasPrefix(authID, "P:") {
			return &uri.ParsedURI{Scheme: uri.SchemeTel, Identifier: authID[2:]}
		}
	}
	return nil
}
