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
	"encoding/base64"
	"errors"
	"fmt"
	"math/rand"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"golang.org/x/exp/maps"
	"golang.org/x/time/rate"
	"google.golang.org/protobuf/proto"
	"howett.net/plist"

	"github.com/beeper/imessage/analytics"
	"github.com/beeper/imessage/imessage/direct/apns"
	"github.com/beeper/imessage/imessage/direct/ids/idsproto"
	"github.com/beeper/imessage/imessage/direct/ids/types"
	"github.com/beeper/imessage/imessage/direct/util/gnuzip"
	"github.com/beeper/imessage/imessage/direct/util/plistuuid"
	"github.com/beeper/imessage/imessage/direct/util/uri"
)

type LookupQuery struct {
	URIs []uri.ParsedURI `plist:"uris"`
}

type LookupIdentityClientData struct {
	PublicMessageIdentityKey *UserIdentity `json:"public_message_identity_key"`

	PublicDevicePrekey *idsproto.PublicDevicePrekey `json:"public_device_prekey"`
	NGMPublicIdentity  *idsproto.NgmPublicIdentity  `json:"ngm_public_identity"`

	Extra map[string]any `json:"extra"`
}

func (l *LookupIdentityClientData) MarshalPlist() (any, error) {
	var err error
	l.Extra["public-message-identity-key"], err = l.PublicMessageIdentityKey.MarshalBinary()
	return l.Extra, err
}

func (l *LookupIdentityClientData) UnmarshalPlist(unmarshal func(any) error) error {
	l.Extra = make(map[string]any)
	err := unmarshal(&l.Extra)
	if err != nil {
		return err
	}
	if publicMessageIdentityKey, ok := l.Extra["public-message-identity-key"]; ok {
		l.PublicMessageIdentityKey, err = deserializeUserIdentity(publicMessageIdentityKey.([]byte))
		if err != nil {
			return err
		}
	}

	if publicDevicePrekey, ok := l.Extra["public-message-ngm-device-prekey-data-key"]; ok {
		l.PublicDevicePrekey = &idsproto.PublicDevicePrekey{}
		err = proto.Unmarshal(publicDevicePrekey.([]byte), l.PublicDevicePrekey)
		if err != nil {
			return err
		}
	}

	if ngmPublicIdentity, ok := l.Extra["ngm-public-identity"]; ok {
		var ktLoggableData idsproto.KeyTransparencyLoggableData
		err = proto.Unmarshal(ngmPublicIdentity.([]byte), &ktLoggableData)
		if err != nil {
			return err
		}
		l.NGMPublicIdentity = &idsproto.NgmPublicIdentity{}
		err = proto.Unmarshal(ktLoggableData.NgmPublicIdentity, l.NGMPublicIdentity)
		if err != nil {
			return err
		}
	}

	return nil
}

type LookupIdentity struct {
	ClientData LookupIdentityClientData `plist:"client-data" json:"client_data"`

	KTLoggableData             *idsproto.KeyTransparencyLoggableData `plist:"kt-loggable-data" json:"kt_loggable_data"`
	PushToken                  []byte                                `plist:"push-token" json:"push_token"`
	SessionToken               []byte                                `plist:"session-token" json:"session_token"`
	SessionTokenExpiresSeconds int                                   `plist:"session-token-expires-seconds" json:"session_token_expires_seconds"`
	SessionTokenRefreshSeconds int                                   `plist:"session-token-refresh-seconds" json:"session_token_refresh_seconds"`
}

type LookupResult struct {
	Identities                  []LookupIdentity `plist:"identities" json:"identities"`
	KTAccountKey                []byte           `plist:"kt-account-key" json:"kt_account_key"`
	SenderCorrelationIdentifier string           `plist:"sender-correlation-identifier" json:"sender_correlation_identifier"`
	Status                      int              `plist:"status" json:"status"`

	Time        time.Time `plist:"-" json:"-"`
	Broadcasted bool      `plist:"-" json:"-"`
}

func (lr *LookupResult) FindIdentity(pushToken []byte, requireNGMKey bool) *LookupIdentity {
	for _, identity := range lr.Identities {
		if bytes.Equal(identity.PushToken, pushToken) {
			if requireNGMKey && (identity.ClientData.PublicDevicePrekey == nil ||
				(identity.ClientData.NGMPublicIdentity == nil && identity.KTLoggableData == nil)) {
				// We require an NGM identity, but our cached result doesn't
				// include one. Return nil to indicate that we need to do a
				// server lookup.
				return nil
			}
			return &identity
		}
	}
	return nil
}

type LookupCache interface {
	Get(ctx context.Context, ourURI, theirURI uri.ParsedURI) (*LookupResult, error)
	GetMany(ctx context.Context, ourURI uri.ParsedURI, theirURIs []uri.ParsedURI) (map[uri.ParsedURI]*LookupResult, error)
	Put(ctx context.Context, ourURI, theirURI uri.ParsedURI, result *LookupResult) error
	Delete(ctx context.Context, ourURI, theirURI uri.ParsedURI) error
	Invalidate(ctx context.Context, ourURI, theirURI uri.ParsedURI) error
	Clear(ctx context.Context) error
	MarkBroadcasted(ctx context.Context, handle uri.ParsedURI, broadcasted ...uri.ParsedURI) error
}

type uriTuple struct {
	our, their uri.ParsedURI
}

type InMemoryLookupCache map[uriTuple]*LookupResult

var _ LookupCache = (InMemoryLookupCache)(nil)

func (i InMemoryLookupCache) Get(_ context.Context, ourURI, theirURI uri.ParsedURI) (*LookupResult, error) {
	return i[uriTuple{ourURI, theirURI}], nil
}

func (i InMemoryLookupCache) GetMany(_ context.Context, ourURI uri.ParsedURI, theirURIs []uri.ParsedURI) (map[uri.ParsedURI]*LookupResult, error) {
	results := make(map[uri.ParsedURI]*LookupResult, len(theirURIs))
	for _, theirURI := range theirURIs {
		res, ok := i[uriTuple{ourURI, theirURI}]
		if ok {
			results[theirURI] = res
		}
	}
	return results, nil
}

func (i InMemoryLookupCache) MarkBroadcasted(ctx context.Context, handle uri.ParsedURI, broadcasted ...uri.ParsedURI) error {
	for _, theirURI := range broadcasted {
		res, ok := i[uriTuple{handle, theirURI}]
		if ok {
			res.Broadcasted = true
		}
	}
	return nil
}

func (i InMemoryLookupCache) Put(_ context.Context, ourURI, theirURI uri.ParsedURI, result *LookupResult) error {
	if result.Time.IsZero() {
		result.Time = time.Now()
	}
	i[uriTuple{ourURI, theirURI}] = result
	return nil
}

func (i InMemoryLookupCache) Delete(_ context.Context, ourURI, theirURI uri.ParsedURI) error {
	delete(i, uriTuple{ourURI, theirURI})
	return nil
}

func (i InMemoryLookupCache) Invalidate(_ context.Context, ourURI, theirURI uri.ParsedURI) error {
	res, ok := i[uriTuple{ourURI, theirURI}]
	if ok && time.Since(res.Time) < MinResultRefreshInterval {
		res.Time = time.Now().Add(-MinResultRefreshInterval)
	}
	return nil
}

func (i InMemoryLookupCache) Clear(_ context.Context) error {
	clear(i)
	return nil
}

type RerouteHistory interface {
	Get(ctx context.Context, handle uri.ParsedURI) (*time.Time, error)
	Put(ctx context.Context, handle uri.ParsedURI) error
	Delete(ctx context.Context, handle uri.ParsedURI) error
	Clear(ctx context.Context) error
}

type InMemoryRerouteHistory map[uri.ParsedURI]*time.Time

func (i InMemoryRerouteHistory) Get(_ context.Context, handle uri.ParsedURI) (*time.Time, error) {
	return i[handle], nil
}

func (i InMemoryRerouteHistory) Put(_ context.Context, handle uri.ParsedURI) error {
	now := time.Now()
	i[handle] = &now
	return nil
}

func (i InMemoryRerouteHistory) Delete(_ context.Context, handle uri.ParsedURI) error {
	delete(i, handle)
	return nil
}

func (i InMemoryRerouteHistory) Clear(_ context.Context) error {
	clear(i)
	return nil
}

type LookupResults struct {
	// TODO plist doesn't like decoding into a map[uri.ParsedURI]LookupResult
	Results map[uri.PlainURI]*LookupResult `plist:"results"`
	Status  int                            `plist:"status"`
}

const (
	day = 24 * time.Hour

	MinResultRefreshInterval         = 1 * day
	MinNegativeResultRefreshInterval = 1 * time.Hour
	ResultExpiry                     = 7 * day
)

func (u *User) LookupDevice(ctx context.Context, ownHandle, theirHandle uri.ParsedURI, wantedToken []byte, requireNGMKey bool) (*LookupIdentity, error) {
	log := zerolog.Ctx(ctx).With().
		Str("our_uri", ownHandle.String()).
		Str("target_uri", theirHandle.String()).
		Str("push_token", base64.StdEncoding.EncodeToString(wantedToken)).
		Bool("require_ngm_key", requireNGMKey).
		Str("method", "lookup single device").
		Logger()
	log.Trace().Msg("Looking up iMessage identity for device")
	cached, err := u.LookupCache.Get(ctx, ownHandle, theirHandle)
	if err != nil {
		return nil, fmt.Errorf("failed to get cached lookup results: %w", err)
	}
	var result *LookupIdentity
	if cached != nil {
		result = cached.FindIdentity(wantedToken, requireNGMKey)
	}
	if result == nil || time.Since(cached.Time) > MinResultRefreshInterval {
		if result == nil {
			log.Debug().Msg("Identity not in cache, looking up on server")
		} else {
			log.Debug().Time("cache_time", cached.Time).Msg("Identity in cache, but cache is old, looking up on server")
		}
		serverResults, err := u.LookupServer(ctx, ownHandle, theirHandle)
		if err != nil {
			return result, fmt.Errorf("failed to lookup on server: %w", err)
		}
		serverResult, ok := serverResults[theirHandle]
		if !ok {
			return result, fmt.Errorf("server didn't return result for user")
		}
		if cached != nil {
			serverResult.Broadcasted = cached.Broadcasted
		}
		serverResultForToken := serverResult.FindIdentity(wantedToken, requireNGMKey)
		logEvt := log.Debug().
			Bool("found_wanted_token", serverResultForToken != nil).
			Int("server_identity_count", len(serverResult.Identities))
		if cached != nil {
			logEvt.Int("cached_identity_count", len(cached.Identities))
		}
		logEvt.Msg("Got lookup results for device from server")
		if serverResultForToken == nil {
			return result, fmt.Errorf("server lookup for user didn't contain result for wanted push token")
		}
		result = serverResultForToken
		err = u.LookupCache.Put(ctx, ownHandle, theirHandle, serverResult)
		if len(serverResult.Identities) > 0 {
			// The user is now on iMessage, if they fall off again that's cause for rerouting
			_ = u.RerouteHistory.Delete(ctx, theirHandle)
		}
		if err != nil {
			// TODO should this just log instead of failing?
			return result, fmt.Errorf("failed to cache lookup result: %w", err)
		}
	} else {
		log.Debug().Msg("Found identity in cache")
	}
	return result, nil
}

type LookupParams struct {
	Force          bool
	Ratelimiter    *rate.Limiter
	AlwaysUseCache bool
}

var NoLookupParams = LookupParams{}

func (u *User) Lookup(ctx context.Context, ownHandle uri.ParsedURI, params LookupParams, uris []uri.ParsedURI) (map[uri.ParsedURI]*LookupResult, error) {
	log := zerolog.Ctx(ctx).With().Str("method", "ids lookup").Logger()
	log.Debug().
		Any("target_uris", uris).
		Bool("force", params.Force).
		Str("own_handle", ownHandle.String()).
		Msg("Looking up iMessage identities")
	cached, err := u.LookupCache.GetMany(ctx, ownHandle, uris)
	if err != nil {
		return nil, fmt.Errorf("failed to get cached lookup results: %w", err)
	}
	if cached == nil {
		cached = make(map[uri.ParsedURI]*LookupResult, len(uris))
	}
	missingFromCache := make(map[uri.ParsedURI]struct{})
	for _, uri := range uris {
		missingFromCache[uri] = struct{}{}
	}
	var remainingLookup []uri.ParsedURI
	cacheResultLog := zerolog.Dict()
	for theirURI, cachedResult := range cached {
		age := time.Since(cachedResult.Time)
		delete(missingFromCache, theirURI)
		willRelookup := params.Force ||
			age > MinResultRefreshInterval ||
			// Lower refresh interval for negative results
			(len(cachedResult.Identities) == 0 && age > MinNegativeResultRefreshInterval)
		if (willRelookup && !params.AlwaysUseCache) || age > ResultExpiry {
			if age > ResultExpiry {
				// Don't use cache
				delete(cached, theirURI)
			}
			remainingLookup = append(remainingLookup, theirURI)
		}
		cacheResultLog.Dict(theirURI.String(), zerolog.Dict().
			Bool("has_cache", true).
			Time("cache_time", cachedResult.Time).
			Int("identity_count", len(cachedResult.Identities)).
			Bool("will_lookup", willRelookup))
	}
	if params.Ratelimiter != nil && !params.Ratelimiter.AllowN(time.Now(), len(missingFromCache)) {
		var identifiers []string
		for uri := range missingFromCache {
			identifiers = append(identifiers, uri.String())
			cached[uri] = &LookupResult{}
		}
		log.Warn().
			Dict("cache_result", cacheResultLog).
			Strs("missing_identifiers", identifiers).
			Bool("ratelimit_exceeded", true).
			Msg("Got lookup results from cache, but exceeded server lookup ratelimit")
		analytics.Track("IMGo Lookup Ratelimit Exceeded", map[string]any{
			"identifiers": strings.Join(identifiers, ","),
			"own handle":  ownHandle.String(),
			"force":       params.Force,
		})
		time.Sleep(time.Duration((rand.Float64()*2 + 1) * float64(time.Second)))
		return cached, nil
	}
	for uri := range missingFromCache {
		cacheResultLog.Dict(uri.String(), zerolog.Dict().
			Bool("has_cache", false).
			Bool("will_lookup", true))
		remainingLookup = append(remainingLookup, uri)
	}
	log.Debug().
		Dict("cache_result", cacheResultLog).
		Any("server_lookup", remainingLookup).
		Msg("Got lookup results from cache")
	if len(remainingLookup) > 0 {
		serverRes, err := u.LookupServer(ctx, ownHandle, remainingLookup...)
		if err != nil {
			return cached, fmt.Errorf("failed to lookup on server: %w", err)
		}
		serverResultLog := zerolog.Dict()
		for theirURI, serverResult := range serverRes {
			cachedResult, hasCache := cached[theirURI]
			resultLogEntry := zerolog.Dict().
				Int("server_identity_count", len(serverResult.Identities))
			if hasCache {
				resultLogEntry.Int("cached_identity_count", len(cachedResult.Identities))
				serverResult.Broadcasted = cachedResult.Broadcasted
			}
			serverResultLog.Dict(theirURI.String(), resultLogEntry)
			cached[theirURI] = serverResult
			err = u.LookupCache.Put(ctx, ownHandle, theirURI, serverResult)
			if len(serverResult.Identities) > 0 {
				// The user is now on iMessage, if they fall off again that's cause for rerouting
				_ = u.RerouteHistory.Delete(ctx, theirURI)
			}
			if err != nil {
				// TODO should this just log instead of failing?
				return cached, fmt.Errorf("failed to cache lookup result: %w", err)
			}
		}
		log.Debug().Dict("server_result", serverResultLog).Msg("Got lookup results from server")
	}
	return cached, nil
}

func (u *User) splitLookupServer(ctx context.Context, ownHandle uri.ParsedURI, uris []uri.ParsedURI) (res map[uri.ParsedURI]*LookupResult, err error) {
	split := len(uris) / 2
	part1 := uris[:split]
	part2 := uris[split:]
	var part1Resp, part2Resp map[uri.ParsedURI]*LookupResult
	part1Resp, err = u.LookupServer(ctx, ownHandle, part1...)
	if err != nil {
		return nil, err
	}
	part2Resp, err = u.LookupServer(ctx, ownHandle, part2...)
	if err != nil {
		return nil, err
	}
	res = part1Resp
	maps.Copy(res, part2Resp)
	return res, nil
}

// LookupServer asks IDS whether the list of provided uris exist on iMessage and returns a map of results
// If the request completes successfully but the user is not on iMessage, the LookupResult in the map will have
// an empty list for the Identities array
func (u *User) LookupServer(ctx context.Context, ownHandle uri.ParsedURI, uris ...uri.ParsedURI) (map[uri.ParsedURI]*LookupResult, error) {
	if len(uris) > 20 {
		return u.splitLookupServer(ctx, ownHandle, uris)
	}
	log := zerolog.Ctx(ctx).With().Str("own_handle", ownHandle.String()).Logger()
	ctx = log.WithContext(ctx)

	res, err := u.actuallyLookupServer(ctx, ownHandle, uris...)
	if errors.Is(err, types.ErrActionRefreshCredentials) {
		u.lookupErrorCount++
		if time.Since(u.lastLookupReregister) < 1*time.Hour && u.lookupErrorCount > 1 {
			log.Err(err).Msg("Got error 6005 on IDS lookup, but last re-register was less than an hour ago, not retrying")
			return res, err
		}
		log.Err(err).Msg("Got error 6005 on IDS lookup, re-registering IDS and trying again")
		err = u.parentRegisterIDS(ctx, true)
		u.lastLookupReregister = time.Now()
		if err != nil {
			if errors.Is(err, types.ErrActionRefreshCredentials) {
				return nil, fmt.Errorf("credentials expired - re-login required")
			}
			return nil, fmt.Errorf("failed to reregister after 6005 error on lookup: %w", err)
		}
		if !slices.Contains(u.Handles, ownHandle) {
			log.Warn().
				Array("new_own_handles", uri.ToZerologArray(u.Handles)).
				Msg("Successfully reregistered after 6005 error, but lost outgoing handle")
			// TODO somehow retry automatically? (fixSendFromHandle fixes it in most cases, but that happens long before this function is called)
			return nil, fmt.Errorf("lost access to send as %s, please try again to send with different alias", ownHandle.Identifier)
		}
		log.Debug().Msg("Successfully reregistered after 6005 error, trying lookup again")
		res, err = u.actuallyLookupServer(ctx, ownHandle, uris...)
	} else if errors.Is(err, types.ErrProxyResponseTooLarge) && len(uris) > 1 {
		log.Err(err).Msg("Got error 5206 on IDS lookup, retrying in smaller chunks")
		return u.splitLookupServer(ctx, ownHandle, uris)
	} else if err == nil {
		u.lastLookupReregister = time.Time{}
		u.lookupErrorCount = 0
	}
	return res, err
}

func (u *User) actuallyLookupServer(ctx context.Context, ownHandle uri.ParsedURI, uris ...uri.ParsedURI) (map[uri.ParsedURI]*LookupResult, error) {
	log := zerolog.Ctx(ctx)

	query := LookupQuery{uris}
	uncompressed, err := plist.Marshal(query, plist.XMLFormat)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal lookup request: %w", err)
	}
	log.Trace().Any("uncompressed", string(uncompressed)).Msg("DEBUG: uncompressed IDS query")
	compressed, err := gnuzip.GZip(uncompressed)
	if err != nil {
		return nil, fmt.Errorf("failed to gzip lookup request: %w", err)
	}

	headers := map[string]string{}
	headers["X-ID-Self-URI"] = ownHandle.String()
	headers["X-Protocol-Version"] = ProtocolVersion

	var authIDCertPair *AuthIDCertPair
	var ok bool
	if ownHandle.Scheme == uri.SchemeTel {
		authIDCertPair, ok = u.AuthIDCertPairs["P:"+ownHandle.Identifier]
	}
	if authIDCertPair == nil {
		authIDCertPair, ok = u.AuthIDCertPairs[u.ProfileID]
	}
	if !ok {
		return nil, fmt.Errorf("failed to find ID certificate for for %s", ownHandle)
	}

	signingPayload := u.createSigningPayload("id-query", "", compressed)
	err = u.signWithIdentity(headers, signingPayload, authIDCertPair.IDCert)
	if err != nil {
		return nil, fmt.Errorf("failed to sign lookup request: %w", err)
	}

	msgID := uuid.New()
	req := apns.SendMessagePayload{
		HTTPContentType: "application/x-apple-plist",
		MessageUUID:     plistuuid.ByteUUID(msgID[:]),
		Command:         apns.MessageTypeHTTPRequest,
		HTTPURL:         idQueryURL,
		HTTPHeaders:     headers,
		Version:         2,
		HTTPBody:        compressed,
	}
	log.Trace().Any("req", req).Msg("DEBUG: ids request")

	messageBytes, err := plist.Marshal(req, plist.BinaryFormat)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal lookup request: %w", err)
	}

	waiter := u.Conn.WaitResponseUUID(msgID)
	err = u.Conn.SendMessage(apns.TopicMadrid, messageBytes, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to send lookup request: %w", err)
	}

	select {
	case <-ctx.Done():
		u.Conn.CancelResponseUUID(msgID)
		return nil, ctx.Err()
	case <-time.After(1 * time.Minute):
		u.Conn.CancelResponseUUID(msgID)
		return nil, fmt.Errorf("lookup request timed out")
	case data := <-waiter:
		if data.ResponseStatus != types.IDSStatusSuccess {
			return nil, fmt.Errorf("got non-success status from HTTP lookup proxy: %w (%s)", types.IDSError{ErrorCode: data.ResponseStatus}, data.HTTPErrorMessage)
		}
		decompressed, err := gnuzip.MaybeGUnzip(data.HTTPBody)
		if err != nil {
			return nil, fmt.Errorf("failed to gunzip lookup response: %w", err)
		}

		var result LookupResults
		_, err = plist.Unmarshal(decompressed, &result)
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal lookup response: %w", err)
		}

		log.Trace().
			Any("req", req).
			Any("result", result).
			Msg("DEBUG: got ids results from server")

		if result.Status != 0 {
			idsErr := types.IDSError{ErrorCode: types.IDSStatus(result.Status)}
			return nil, fmt.Errorf("received nonzero status from lookup: %w (%d)", idsErr, result.Status)
		}

		parsedURIResults := make(map[uri.ParsedURI]*LookupResult, len(result.Results))
		for uri, resultPart := range result.Results {
			resultPart.Time = time.Now()
			// TODO don't ignore error
			parsedURI, _ := uri.Parse()
			parsedURIResults[parsedURI] = resultPart
		}
		return parsedURIResults, nil
	}
}
