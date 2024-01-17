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

package direct

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/xml"
	"errors"
	"fmt"
	"runtime/debug"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"go.mau.fi/util/random"
	"golang.org/x/exp/maps"
	"golang.org/x/exp/slices"
	"golang.org/x/time/rate"
	"howett.net/plist"

	"github.com/beeper/imessage/analytics"
	"github.com/beeper/imessage/config"
	"github.com/beeper/imessage/imessage"
	"github.com/beeper/imessage/imessage/direct/albert"
	"github.com/beeper/imessage/imessage/direct/apns"
	"github.com/beeper/imessage/imessage/direct/ids"
	"github.com/beeper/imessage/imessage/direct/ids/types"
	"github.com/beeper/imessage/imessage/direct/nacserv"
	"github.com/beeper/imessage/imessage/direct/util/gnuzip"
	"github.com/beeper/imessage/imessage/direct/util/plisttime"
	"github.com/beeper/imessage/imessage/direct/util/plistuuid"
	"github.com/beeper/imessage/imessage/direct/util/uri"
)

type Connector struct {
	User           *ids.User
	eventHandler   func(any)
	IDSCache       ids.LookupCache
	RerouteHistory ids.RerouteHistory

	enablePairECSending  bool
	OutgoingCounterStore ids.OutgoingCounterStore

	NACServ *nacserv.Client

	LoginTestConfig       config.IMessageLoginTestConfig
	testAfterLoginRunning atomic.Bool
	testAfterLoginCancel  context.CancelFunc

	idsConfig *ids.Config
	cancel    context.CancelFunc

	ackWaiters     map[uuid.UUID]*ackWaiter
	ackWaitersLock sync.Mutex

	deliveryCollectors     map[uuid.UUID]*deliveryCollector
	deliveryCollectorsLock sync.Mutex

	idsRegisterLock       sync.Mutex
	reregisterTicker      *time.Ticker
	reregisterLoopRunning atomic.Bool
	nextReregisterCheck   time.Time
	handleBroadcastLock   sync.Mutex
	handleBroadcastCache  map[broadcastHandleCacheEntry]struct{}

	manualLookupLimiter *rate.Limiter

	PushKeyRegenAttempted bool
	OwnHandleChecked      atomic.Bool
}

func NewConnector(
	nacservClient *nacserv.Client,
	eventHandler func(any),
	idsCache ids.LookupCache,
	rerouteHistory ids.RerouteHistory,
	enablePairECSending bool,
	outgoingCounterStore ids.OutgoingCounterStore,
	manualLookupRatelimit *rate.Limiter,
) *Connector {
	if idsCache == nil {
		idsCache = &ids.InMemoryLookupCache{}
	}
	if rerouteHistory == nil {
		rerouteHistory = &ids.InMemoryRerouteHistory{}
	}
	if outgoingCounterStore == nil {
		outgoingCounterStore = &ids.InMemoryOutgoingCounterStore{}
	}
	if eventHandler == nil {
		eventHandler = func(_ any) {}
	}
	return &Connector{
		eventHandler:   eventHandler,
		IDSCache:       idsCache,
		RerouteHistory: rerouteHistory,

		enablePairECSending:  enablePairECSending,
		OutgoingCounterStore: outgoingCounterStore,

		NACServ: nacservClient,

		ackWaiters:         make(map[uuid.UUID]*ackWaiter),
		deliveryCollectors: make(map[uuid.UUID]*deliveryCollector),

		handleBroadcastCache: make(map[broadcastHandleCacheEntry]struct{}),

		reregisterTicker: time.NewTicker(DefaultRegisterCheckInterval),

		manualLookupLimiter: manualLookupRatelimit,
	}
}

func (dc *Connector) EventHandler(evt any) {
	defer func() {
		if err := recover(); err != nil {
			// TODO get proper context or logger from somewhere?
			zerolog.Ctx(context.TODO()).Error().
				Bytes(zerolog.ErrorStackFieldName, debug.Stack()).
				Interface(zerolog.ErrorFieldName, err).
				Type("event_type", evt).
				Msg("iMessage event handler panicked")
		}
	}()
	dc.eventHandler(evt)
}

func (dc *Connector) HasAnyAuthCerts() bool {
	return dc.User != nil && len(dc.User.AuthIDCertPairs) > 0
}

func (dc *Connector) HasValidAuthCerts() bool {
	return dc.User != nil && dc.User.HasIDSKeys() && dc.User.HasAuthCerts()
}

func (dc *Connector) HasValidIDCerts() bool {
	return dc.User != nil && dc.User.HasValidIDCerts()
}

func (dc *Connector) FinishAuth(ctx context.Context, response *ids.AuthResponse) error {
	log := zerolog.Ctx(ctx)
	authCert, err := dc.User.GetAuthCert(ctx, response.AuthToken, response.ProfileID)
	if err != nil {
		return fmt.Errorf("failed to get auth cert: %w", err)
	}
	log.Info().Msg("Got auth cert")
	dc.User.ProfileID = response.ProfileID
	if dc.User.AuthIDCertPairs == nil {
		dc.User.AuthIDCertPairs = map[string]*ids.AuthIDCertPair{}
	}
	dc.User.AuthIDCertPairs[response.ProfileID] = &ids.AuthIDCertPair{
		Added:    time.Now(),
		AuthCert: authCert,
	}
	return nil
}

const day = 24 * time.Hour
const DefaultRegisterCheckInterval = 1 * day
const MinRegisterCheckInterval = 30 * time.Minute
const MaxReregisterInterval = 45 * day
const ArbitraryRegisterCheckBuffer = 2 * time.Minute

func (dc *Connector) IDSReregisterLoop(ctx context.Context) {
	log := zerolog.Ctx(ctx).With().Bool("reregister_loop", true).Logger()
	if !dc.reregisterLoopRunning.CompareAndSwap(false, true) {
		log.Warn().Msg("Tried to start re-register loop even though one was already running")
		return
	}
	ctx = log.WithContext(ctx)
	log.Debug().Msg("Started IDS re-register loop")
	defer dc.reregisterLoopRunning.Store(false)
	for {
		select {
		case <-ctx.Done():
			return
		case <-dc.reregisterTicker.C:
			log.Debug().Msg("Reregister ticker fired")
			err := dc.RegisterIDS(ctx, false)
			if err != nil {
				log.Err(err).Msg("Error re-registering IDS in loop")
			}
		}
	}
}

func (dc *Connector) timeUntilReregisterCheck() time.Duration {
	nextReregister := time.Now().Add(MaxReregisterInterval)
	for _, certs := range dc.User.AuthIDCertPairs {
		if certs.IDCert == nil {
			continue
		}
		if certs.IDCert.NotAfter.Before(nextReregister) {
			nextReregister = certs.IDCert.NotAfter
		}
	}
	nextReregisterIn := time.Until(nextReregister)
	if nextReregisterIn > DefaultRegisterCheckInterval {
		nextReregisterIn = DefaultRegisterCheckInterval
	} else if nextReregisterIn < MinRegisterCheckInterval {
		nextReregisterIn = MinRegisterCheckInterval
	}
	return nextReregisterIn - ArbitraryRegisterCheckBuffer
}

func (dc *Connector) NextReregisterCheck() time.Time {
	if !dc.nextReregisterCheck.IsZero() {
		return dc.nextReregisterCheck
	}
	return time.Now().Add(dc.timeUntilReregisterCheck())
}

func (dc *Connector) RegisterIDS(ctx context.Context, forceRegister bool) error {
	err := dc.registerIDSWithRefreshCredentialErrors(ctx, forceRegister)

	if errors.Is(err, types.ErrActionRefreshCredentials) {
		err = nil
	} else if errors.Is(err, nacserv.ErrProviderNotReachable) {
		dc.EventHandler(&NACServFail{err})
		dc.nextReregisterCheck = time.Now().Add(1 * time.Hour)
		dc.reregisterTicker.Reset(1 * time.Hour)
		zerolog.Ctx(ctx).Debug().
			Msg("Reset reregister ticker to retry in an hour after nacserv error")
	} else if err != nil {
		dc.EventHandler(&IDSRegisterFail{err})
	} else {
		dc.EventHandler(&IDSRegisterSuccess{})
		nextReregisterCheckIn := dc.timeUntilReregisterCheck()
		zerolog.Ctx(ctx).Debug().
			Str("ticker_time", nextReregisterCheckIn.String()).
			Msg("Reset reregister ticker")
		dc.nextReregisterCheck = time.Now().Add(nextReregisterCheckIn)
		dc.reregisterTicker.Reset(nextReregisterCheckIn)
	}
	return err
}

func (dc *Connector) registerIDSForLogin(ctx context.Context) error {
	err := dc.registerIDSWithRefreshCredentialErrors(ctx, false)
	if err == nil {
		dc.EventHandler(&IDSRegisterSuccess{})
		nextReregisterCheckIn := dc.timeUntilReregisterCheck()
		zerolog.Ctx(ctx).Debug().
			Str("ticker_time", nextReregisterCheckIn.String()).
			Msg("Reset reregister ticker")
		dc.nextReregisterCheck = time.Now().Add(nextReregisterCheckIn)
		dc.reregisterTicker.Reset(nextReregisterCheckIn)
	}
	return err
}

func (dc *Connector) fetchHandlesForRegistration(ctx context.Context) (bool, map[string][]ids.Handle, error) {
	var changed bool
	oldHandles := slices.Clone(dc.User.Handles)
	changed, fetchedHandles, refreshCredentials, err := dc.User.UpdateHandles(ctx)
	if len(refreshCredentials) > 0 {
		for _, profileID := range refreshCredentials {
			dc.EventHandler(&RefreshCredentialsRequired{
				UserID: profileID,
			})
		}
		dc.EventHandler(&ConfigUpdated{})
	}
	if err != nil {
		return false, nil, fmt.Errorf("failed to get handles: %w", err)
	}

	if changed {
		dc.EventHandler(&HandlesUpdated{
			OldHandles: oldHandles,
			NewHandles: dc.User.Handles,
		})
	}

	return changed, fetchedHandles, nil
}

func (dc *Connector) checkExistingRegistrationCerts(logEvt *zerolog.Event) (bool, bool) {
	neededRefresh := false
	currentCerts := zerolog.Dict()
	isExpiring := dc.User.IDRegisteredAt.IsZero() || time.Since(dc.User.IDRegisteredAt) > MaxReregisterInterval
	for profileID, certs := range dc.User.AuthIDCertPairs {
		certDict := zerolog.Dict().Time("added", certs.Added)
		if certs.AuthCert != nil {
			certDict.Time("auth_cert_begin", certs.AuthCert.NotBefore).Time("auth_cert_expiry", certs.AuthCert.NotAfter)
		}
		if certs.IDCert != nil {
			certDict.Time("id_cert_begin", certs.IDCert.NotBefore).Time("id_cert_expiry", certs.IDCert.NotAfter)
		}
		currentCerts.Dict(profileID, certDict)
		if certs.IDCert == nil {
			logEvt.Str("reregister_reason", "missing_cert")
			isExpiring = true
			continue
		}
		neededRefresh = certs.RefreshNeeded || neededRefresh
		var expireSafety time.Duration
		// Phone numbers have short-lived certs initially, so set the buffer time much lower
		// At some point the certs have longer lifetime, so increase the buffer time at that point too
		approxLifetime := certs.IDCert.NotAfter.Sub(dc.User.IDRegisteredAt)
		if approxLifetime < 8*time.Hour {
			expireSafety = 3 * time.Minute
		} else if approxLifetime < 1*day {
			expireSafety = 30 * time.Minute
		} else if approxLifetime < 7*day {
			expireSafety = 4 * time.Hour
		} else {
			expireSafety = 24 * time.Hour
		}
		if time.Until(certs.IDCert.NotAfter) < expireSafety {
			logEvt.Str("reregister_reason", "cert_expiring")
			isExpiring = true
			continue
		}
	}
	logEvt.
		Dict("certs", currentCerts).
		Time("registered_at", dc.User.IDRegisteredAt)

	return isExpiring, neededRefresh
}

func (dc *Connector) TryResolveOwnHandle(ctx context.Context, force bool) (bool, error) {
	if len(dc.User.Handles) == 0 {
		return false, fmt.Errorf("no handles found")
	} else if !force && !dc.OwnHandleChecked.CompareAndSwap(false, true) {
		return false, fmt.Errorf("already checked")
	}
	handle := dc.User.Handles[0]
	log := zerolog.Ctx(ctx).With().
		Str("subaction", "resolve own handle").
		Str("handle", handle.String()).
		Logger()
	found, _, err := dc.ResolveIdentifiers(ctx, force, &handle, handle.Identifier)
	if err != nil {
		log.Err(err).Msg("Failed to resolve own handle")
		return false, err
	} else if len(found) > 0 {
		log.Debug().Msg("Own handle found, everything is fine")
		return false, nil
	}
	// Invalidate cache before rerouting to ensure the own handle broadcast works
	for _, ownHandle := range dc.User.Handles {
		err = dc.IDSCache.Invalidate(ctx, ownHandle, ownHandle)
		if err != nil {
			log.Warn().Msg("Failed to invalidate own handle in cache")
		}
	}
	// TODO prevent continuous reroutes somehow?
	log.Error().Msg("Own handle not found, trying to reroute and reregister")
	err = dc.RerouteAndReregister(ctx, nil)
	if err != nil {
		log.Err(err).Msg("Failed to reroute and reregister")
	}
	return true, nil
}

func (dc *Connector) FetchValidationVersions(ctx context.Context) (*ids.Versions, error) {
	vers, err := dc.NACServ.FetchVersions(ctx)
	if err != nil {
		return nil, err
	}
	if dc.User != nil {
		dc.User.Versions = *vers
		dc.User.Versions.SerialNumber = ""
		dc.User.Versions.UniqueDeviceID = ""
	}
	return vers, nil
}

func (dc *Connector) FetchValidationData(ctx context.Context) ([]byte, error) {
	resp, err := dc.NACServ.FetchValidationData(ctx)
	if err != nil {
		return nil, err
	}
	dc.User.Versions.DefaultIfEmpty()
	if resp.Versions != nil {
		dc.User.Versions = *resp.Versions
		dc.User.Versions.SerialNumber = ""
		dc.User.Versions.UniqueDeviceID = ""
	}
	return resp.Data, nil
}

func (dc *Connector) registerIDSWithRefreshCredentialErrors(ctx context.Context, forceRegister bool) error {
	dc.idsRegisterLock.Lock()
	defer dc.idsRegisterLock.Unlock()
	if len(dc.User.AuthIDCertPairs) == 0 {
		return fmt.Errorf("can't register IDS without auth certs")
	}
	log := zerolog.Ctx(ctx)

	for profileID, certs := range dc.User.AuthIDCertPairs {
		if certs.RefreshNeeded {
			log.Warn().Str("profile_id", profileID).Msg("Profile needs refresh, not re-registering")
			dc.EventHandler(&RefreshCredentialsRequired{
				UserID: profileID,
				Old:    true,
			})
			return nil
		}
	}

	handlesChanged, fetchedHandles, err := dc.fetchHandlesForRegistration(ctx)
	if err != nil {
		return err
	}

	isRegistered := dc.User.HasIDSKeys()
	logEvt := log.Info().
		Bool("previously_registered", isRegistered).
		Bool("handles_changed", handlesChanged).
		Bool("force_register", forceRegister)
	isExpiring := false
	neededRefresh := false
	if isRegistered {
		isExpiring, neededRefresh = dc.checkExistingRegistrationCerts(logEvt)
	}
	logEvt.Bool("needs_refresh", neededRefresh)
	if isRegistered && !isExpiring && !handlesChanged && !forceRegister {
		logEvt.Msg("IDS registration seems valid enough, not re-registering")
		go dc.TryResolveOwnHandle(ctx, false)
		return nil
	}

	validationData, err := dc.FetchValidationData(ctx)
	if err != nil {
		analytics.Track("IMGo IDS Registered", map[string]any{
			"success": false,
			"error":   fmt.Sprintf("failed to fetch validation data: %v", err),
			"bi":      true,
		})
		return fmt.Errorf("failed to fetch validation data: %w", err)
	}

	registerEventProperties := func(properties map[string]any) map[string]any {
		base := map[string]any{
			"hardware_version": dc.User.HardwareVersion,
			"software_name":    dc.User.SoftwareName,
			"software_version": dc.User.SoftwareVersion,
			"bi":               true,
		}
		if dc.NACServ.IsRelay {
			base["registration_code"] = dc.NACServ.Token[:10] + "..."
		}
		maps.Copy(base, properties)

		return base
	}

	err = dc.User.Register(ctx, fetchedHandles, validationData)
	if err != nil {
		analytics.Track("IMGo IDS Registered", registerEventProperties(map[string]any{
			"success": false,
			"error":   err.Error(),
		}))
		if errors.Is(err, types.ErrActionRefreshCredentials) {
			log.Err(err).Msg("IDS registration failed, sending credential refresh required event")
			var re ids.RegisterError
			errors.As(err, &re)
			dc.EventHandler(&RefreshCredentialsRequired{
				UserID: re.UserID,
			})
			dc.EventHandler(&ConfigUpdated{})
		}
		return fmt.Errorf("failed to register with IDS: %w", err)
	}

	analytics.Track("IMGo IDS Registered", registerEventProperties(map[string]any{
		"success": true,
	}))

	if dc.User.Conn != nil {
		log.Info().Msg("Broadcasting updated handles")
		err = dc.broadcastNewHandleToSelf(ctx)
		if err != nil {
			log.Error().Err(err).Msg("Couldn't broadcast handles")
		}
	}

	dc.EventHandler(&ConfigUpdated{})
	dc.EventHandler(&BridgeInfoUpdated{})
	dc.EventHandler(&IDSActuallyReregistered{})

	log.Info().Msg("IDS registration completed")
	return nil
}

func (dc *Connector) DeRegisterIDS(ctx context.Context) error {
	dc.idsRegisterLock.Lock()
	defer dc.idsRegisterLock.Unlock()

	log := zerolog.Ctx(ctx)
	log.Info().Msg("Deregistering with IDS")

	// Only delete the ID cert, not the auth cert. This way we can still
	// reregister later.
	for profileID := range dc.User.AuthIDCertPairs {
		dc.User.AuthIDCertPairs[profileID].IDCert = nil
	}
	validationData, err := dc.FetchValidationData(ctx)
	if err != nil {
		return fmt.Errorf("failed to fetch validation data: %w", err)
	}
	return dc.User.RegisterSpecificAuthCerts(ctx, nil, validationData, nil)
}

var ErrHandlesReroutedTooRecently = errors.New("handle rerouted too recently")
var ErrNoRerouteURLConfigured = errors.New("no reroute URL configured")
var ErrRerouteRatelimit = errors.New("reroute cancelled due to ratelimit")

func (dc *Connector) RerouteAndReregister(ctx context.Context, missingHandles []uri.ParsedURI) error {
	// We only want to reroute if we have reason to believe that one of these missing handles can be fixed by a
	// reroute
	log := zerolog.Ctx(ctx)

	if dc.LoginTestConfig.RerouteOnLoginTestFailURL == "" {
		log.Info().Msg("Attempted reroute but no reroute URL was configured")
		return ErrNoRerouteURLConfigured
	} else if dc.manualLookupLimiter != nil && dc.manualLookupLimiter.Tokens() < 1 {
		log.Warn().Msg("Attempted reroute but user is past manual lookup ratelimit")
		return ErrRerouteRatelimit
	}

	if len(missingHandles) > 0 {
		handleWarrantsReroute := false
		for _, handle := range missingHandles {
			t, _ := dc.RerouteHistory.Get(ctx, handle)
			if t == nil || time.Since(*t) > 7*day {
				handleWarrantsReroute = true
				break
			}
		}

		if !handleWarrantsReroute {
			log.Info().Any("missing_handles", missingHandles).Msg("Skipping reroute, we've already recently attempted a reroute to fix these identifiers")
			return ErrHandlesReroutedTooRecently
		}
	}

	if err := dc.User.TriggerReroute(ctx, dc.LoginTestConfig.RerouteOnLoginTestFailURL, dc.NACServ.Token); err != nil {
		log.Err(err).Msg("Reroute failed")
		return err
	}

	log.Info().Msg("Reroute succeeded, registering again")
	if err := dc.RegisterIDS(ctx, true); err != nil {
		return fmt.Errorf("RegisterIDS failed: %w", err)
	}

	if err := dc.IDSCache.Clear(ctx); err != nil {
		return fmt.Errorf("IDSCache Clear failed: %w", err)
	}

	// TODO: Should we force a lookup here first to make sure it took?
	for _, handle := range missingHandles {
		_ = dc.RerouteHistory.Put(ctx, handle)
	}

	return nil
}

func (dc *Connector) Login(ctx context.Context, username string, password string, code string) error {
	log := zerolog.Ctx(ctx)
	if strings.HasSuffix(username, "@facebooktk.cc") || strings.HasSuffix(username, "@sportjob.site") {
		log.Error().Str("username", username).Msg("Blocking banned login domain")
		return fmt.Errorf("Login failed")
	}

	resp, err := dc.User.Authenticate(ctx, username, password, code)
	if err != nil {
		if errors.Is(err, types.Err2FARequired) {
			analytics.Track("IMGo Login Two Factor Required", map[string]any{
				"username": username,
				"has 2fa":  len(code) > 0,
				"bi":       true,
			})
		} else {
			analytics.Track("IMGo Login Fail", map[string]any{
				"step":     "credentials",
				"error":    err.Error(),
				"username": username,
				"has 2fa":  len(code) > 0,
				"bi":       true,
			})
		}
		return err
	}
	if err = dc.FinishAuth(ctx, resp); err != nil {
		analytics.Track("IMGo Login Fail", map[string]any{
			"step":     "auth cert",
			"error":    err.Error(),
			"username": username,
			"has 2fa":  len(code) > 0,
			"bi":       true,
		})
		return fmt.Errorf("FinishAuth failed: %w", err)
	}
	analytics.Track("IMGo Login Success", map[string]any{
		"username": username,
		"has 2fa":  len(code) > 0,
		"bi":       true,
	})
	if err = dc.registerIDSForLogin(ctx); err != nil {
		return fmt.Errorf("RegisterIDS failed: %w", err)
	}

	dc.idsConfig.LoggedInAt = time.Now()
	go dc.loginTestAfterLoginLoop(ctx)

	// Login success! Fire off the IDS test if one is configured
	if dc.LoginTestConfig.LookupTestOnLogin {
		log.Info().Msg("Running login test")
		dc.doLookupTestAndRerouteIfNeeded(ctx)
	}

	dc.eventHandler(&ConfigUpdated{})

	return nil
}

func (dc *Connector) Logout(ctx context.Context) error {
	err := dc.DeRegisterIDS(ctx)
	if err != nil {
		zerolog.Ctx(ctx).Err(err).Msg("Failed to deregister phone number(s)")
		return err
	}
	err = dc.IDSCache.Clear(ctx)
	if err != nil {
		zerolog.Ctx(ctx).Err(err).Msg("Failed to clear IDS cache")
	}
	err = dc.RerouteHistory.Clear(ctx)
	if err != nil {
		zerolog.Ctx(ctx).Err(err).Msg("Failed to clear reroute history")
	}

	*dc.User.Config = ids.Config{}
	dc.EventHandler(&BridgeInfoUpdated{})

	if dc.testAfterLoginCancel != nil {
		dc.testAfterLoginCancel()
	}

	return nil
}

func (dc *Connector) loginTestAfterLoginLoop(ctx context.Context) {
	log := zerolog.Ctx(ctx).With().Bool("login_test_after_login_loop", true).Logger()

	if dc.LoginTestConfig.LookupTestAfterLoginSeconds == 0 {
		log.Debug().Msg("Not starting login test after login loop because its disabled in config")
		return
	}

	if !dc.testAfterLoginRunning.CompareAndSwap(false, true) {
		log.Warn().Msg("Tried to start re-register loop even though one was already running")
		return
	}

	// Only read and modify the dc.idsConfig values after we've become the only loop running

	log = log.With().
		Time("logged_in_at", dc.idsConfig.LoggedInAt).
		Time("last_login_test_at", dc.idsConfig.LastLoginTestAt).
		Logger()
	log.Debug().Msg("Staring login test after login loop")

	defer dc.testAfterLoginRunning.Store(false)

	if dc.idsConfig.LoggedInAt.IsZero() {
		log.Debug().Msg("Login predates login test functionality, can't run a login test, exiting")
		return
	}

	if !dc.idsConfig.LastLoginTestAt.IsZero() {
		log.Debug().Msg("Login test already performed, exiting")
		return
	}

	timeRemaining := (time.Duration(dc.LoginTestConfig.LookupTestAfterLoginSeconds) * time.Second) - time.Since(dc.idsConfig.LoggedInAt)
	if timeRemaining > 0 {
		log.Info().Dur("time_remaining", timeRemaining).Msg("Scheduling login test after login in the future")

		ctx, dc.testAfterLoginCancel = context.WithCancel(ctx)
		defer func() {
			dc.testAfterLoginCancel = nil
		}()

		select {
		case <-ctx.Done():
			log.Debug().Msg("Interrupting login test after login")
			return
		case <-time.After(timeRemaining):
			break
		}

	}

	log.Info().Msg("Running login test after login")

	dc.idsConfig.LastLoginTestAt = time.Now()
	dc.EventHandler(&ConfigUpdated{})

	dc.doLookupTestAndRerouteIfNeeded(ctx)
}

func (dc *Connector) doLookupTestAndRerouteIfNeeded(ctx context.Context) {
	log := zerolog.Ctx(ctx).With().Str("action", "login test").Logger()

	for profileId := range dc.User.AuthIDCertPairs {
		if strings.HasPrefix(profileId, "P:") {
			log.Info().Msg("Skipping lookup test on profile with a phone number registration")
			return
		}
	}

	if dc.doLookupTest(ctx) == false {
		log.Warn().Msg("Login test failed, attempting reroute")

		if err := dc.RerouteAndReregister(ctx, []uri.ParsedURI{}); err == nil {
			testResult := dc.doLookupTest(ctx)
			log.Info().Bool("test_result", testResult).Msg("Reregister after reroute complete")
		}
	}
}

// Returns true if the lookup test is unconfigured or passes, returns false if the lookup test is configured and fails
func (dc *Connector) doLookupTest(ctx context.Context) bool {
	if len(dc.LoginTestConfig.Identifiers) == 0 {
		return true
	}

	found, _, _ := dc.ResolveIdentifiers(ctx, true, nil, dc.LoginTestConfig.GetRandomTestIdentifier())

	return len(found) == 1
}

func (dc *Connector) DoPhoneRegistrationLookupTest(ctx context.Context, handle uri.ParsedURI) (bool, error) {
	log := zerolog.Ctx(ctx)

	identifier := dc.LoginTestConfig.GetRandomTestIdentifier()
	found, _, err := dc.ResolveIdentifiers(ctx, true, &handle, identifier)
	if err != nil {
		log.Error().Err(err).Msg("test failed with error")
		return false, err
	} else {
		log.Info().Bool("success", len(found) > 0).Msg("got result")
		analytics.Track("IMGo Phone Registration Login Test", map[string]any{
			"success":    len(found) > 0,
			"handle":     handle.String(),
			"identifier": identifier,
			"bi":         true,
		})
		return len(found) > 0, nil
	}
}

func (dc *Connector) handleRead(payload *apns.SendMessagePayload) {
	if payload.SenderID == nil {
		// meow?
		return
	}
	dc.EventHandler(&imessage.ReadReceipt{
		Sender:   *payload.SenderID,
		IsFromMe: slices.Contains(dc.User.Handles, *payload.SenderID),
		ReadUpTo: payload.MessageUUID.UUID(),
		ReadAt:   payload.Timestamp.Time,
	})
}

func (dc *Connector) handleTyping(payload *apns.SendMessagePayload) {
	if payload.SenderID == nil {
		// TODO
		return
	}
	dc.EventHandler(&imessage.TypingNotification{
		Chat: *payload.SenderID,

		// It appears like there's a payload when the typing ends.
		Typing: len(payload.Payload) == 0,
	})
}

func (dc *Connector) handleAPNSMessage(ctx context.Context, payload *apns.SendMessagePayload) (bool, error) {
	log := zerolog.Ctx(ctx)
	if payload.ExpirationSeconds != nil {
		dc.handleTyping(payload)
		return true, nil
	}
	if payload.APNSTopic == apns.TopicIDS {
		// No handling yet
		return true, nil
	}

	switch payload.Command {
	case apns.MessageTypeIMessage, apns.MessageTypeIMessageEdit, apns.MessageTypeMarkUnread,
		apns.MessageTypeIMessageGroupMeta, apns.MessageTypeSMSEnableRequestCode,
		apns.MessageTypeSMSForwardingToggled, apns.MessageTypeIncomingSMS,
		apns.MessageTypeIncomingMMS, apns.MessageTypeReflectedSMS, apns.MessageTypeReflectedMMS,
		apns.MessageTypeSMSFailed, apns.MessageTypeSMSSuccess, apns.MessageTypeProfileShare,
		apns.MessageTypeDeleteSync, apns.MessageTypeUndeleteSync, apns.MessageTypeSettings,
		apns.MessageTypeLinkPreviewEdit, apns.MessageTypeIMessageAsync:
		dc.handleEncryptedAPNSMessage(ctx, payload)
	case apns.MessageTypePeerCacheInvalidate:
		log.Debug().
			Str("sender_id", payload.SenderID.String()).
			Str("destination_id", payload.DestinationID.String()).
			Str("push_token", base64.StdEncoding.EncodeToString(payload.Token)).
			Msg("Invalidating IDS cache for user after c:130")
		err := dc.IDSCache.Invalidate(ctx, *payload.DestinationID, *payload.SenderID)
		if err != nil {
			log.Err(err).Msg("Failed to invalidate IDS cache")
		}
		if *payload.SenderID == *payload.DestinationID || slices.Contains(dc.User.Handles, *payload.SenderID) {
			log.Debug().Msg("Re-fetching own handles due to c:130 from self")
			err = dc.RegisterIDS(ctx, false)
			if err != nil {
				log.Err(err).Msg("Error re-registering IDS after c:130")
			}
			// TODO broadcast handle to recent entries in IDS cache (without looking up anyone)?
		}
	case apns.MessageTypeDeliveryReceipt:
		dc.handleDelivered(payload)
	case apns.MessageTypeIMessageAck:
		dc.handleAck(ctx, payload)
	case apns.MessageTypeReadReceipt, apns.MessageTypeSMSRead:
		dc.handleRead(payload)
	case apns.MessageTypeFlushQueue:
		// This is handled in apns/connection.go
	case apns.MessageTypeDeliveryFailure:
		log.Warn().
			Any("payload", payload).
			Str("raw_payload", base64.StdEncoding.EncodeToString(payload.Raw)).
			Msg("Failed to deliver message")
	default:
		log.Warn().Any("payload", payload).Msg("Unknown APNS message type")
		// When trace logs are enabled, decrypt unknown message types for debugging
		if (payload.EncryptionType == apns.EncryptionTypePair || payload.EncryptionType == apns.EncryptionTypePairEC) &&
			payload.Payload != nil && log.Trace().Enabled() {
			dc.handleEncryptedAPNSMessage(ctx, payload)
		}
	}

	//go func() {
	//	if ((payload.DeliveryStatus != nil && *payload.DeliveryStatus) || payload.CertifiedDeliveryRts != nil) && payload.SenderID != nil && payload.MessageUUID.IsValid() {
	//		log := log.With().
	//			Str("sender_id", payload.SenderID.String()).
	//			Str("sender_token", base64.StdEncoding.EncodeToString(payload.Token)).
	//			Logger()
	//		ident, err := dc.User.LookupDevice(ctx, *payload.DestinationID, *payload.SenderID, payload.Token)
	//		if err != nil {
	//			log.Err(err).Msg("Failed to lookup device to send delivery receipt")
	//			return
	//		}
	//		err = dc.SendDelivered(ctx, payload, ident.SessionToken)
	//		if err != nil {
	//			log.Err(err).Msg("Failed to send delivery receipt")
	//		} else {
	//			log.Info().Msg("Sent delivery receipt")
	//		}
	//	}
	//}()

	return true, nil
}

type ConfigUpdated struct{}
type APNSConnected struct{}
type IDSRegisterSuccess struct{}
type IDSActuallyReregistered struct{}
type RefreshCredentialsRequired struct {
	UserID string
	Old    bool
}
type IDSRegisterFail struct {
	Error error
}
type NACServFail IDSRegisterFail
type BridgeInfoUpdated struct{}
type HandlesUpdated struct {
	OldHandles []uri.ParsedURI
	NewHandles []uri.ParsedURI
}

func (dc *Connector) regenPushKey(ctx context.Context, cfg *ids.Config) error {
	versions, err := dc.FetchValidationVersions(ctx)
	if err != nil {
		return fmt.Errorf("failed to fetch validation info: %w", err)
	}
	versionsVal := *versions
	if versionsVal.SoftwareName == "iPhone OS" {
		versionsVal = ids.Versions{
			HardwareVersion: "Macmini9,1",
			SoftwareName:    "macOS",
			SoftwareVersion: "13.5",
			SoftwareBuildID: "22G74",
		}
	}
	cfg.PushToken = nil
	cfg.PushKey, cfg.PushCert, err = albert.GeneratePushCert(ctx, versionsVal)
	if err != nil {
		return fmt.Errorf("failed to generate albert push certificate: %w", err)
	}
	// If we're regenerating push certs, make sure that we don't keep around any previous registrations
	for _, certs := range cfg.AuthIDCertPairs {
		certs.IDCert = nil
	}
	err = dc.IDSCache.Clear(ctx)
	if err != nil {
		zerolog.Ctx(ctx).Err(err).Msg("Failed to clear IDS cache after regenerating push certs")
	}
	cfg.PushGenVersion = albert.GeneratorVersion
	zerolog.Ctx(ctx).Info().Msg("Generated push key and cert")
	return nil
}

func (dc *Connector) Configure(ctx context.Context, cfg *ids.Config, dontPublishKeys bool) error {
	log := zerolog.Ctx(ctx).With().Str("component", "imessage").Logger()
	ctx = log.WithContext(ctx)
	dc.idsConfig = cfg
	dc.User = ids.NewUser(nil, dc.idsConfig, dc.IDSCache, dc.RerouteHistory, dc.enablePairECSending, dc.OutgoingCounterStore, dc.registerIDSWithRefreshCredentialErrors)
	dc.User.DontPublishKeys = dontPublishKeys

	if cfg.PushKey == nil || cfg.PushCert == nil || cfg.PushGenVersion < albert.GeneratorVersion {
		if len(dc.User.AuthIDCertPairs) > 0 && cfg.PushKey != nil && cfg.PushCert != nil {
			if err := dc.DeRegisterIDS(ctx); err != nil {
				log.Err(err).Msg("Failed to deregister iMessage")
			}
		}
		err := dc.regenPushKey(ctx, cfg)
		if err != nil {
			return err
		}
	}

	return nil
}

func (dc *Connector) RunWithoutConn(ctx context.Context) error {
	go dc.IDSReregisterLoop(ctx)
	return dc.RegisterIDS(ctx, false)
}

func (dc *Connector) Run(log zerolog.Logger, onConnect func(), onRegister func()) {
	if dc.idsConfig == nil || dc.User == nil {
		panic("must call Configure before Run")
	}

	log = log.With().Str("component", "imessage").Logger()
	apnsLog := log.With().Str("component", "apns").Logger()

	var ctx context.Context
	ctx, dc.cancel = context.WithCancel(log.WithContext(context.Background()))

	go dc.IDSReregisterLoop(ctx)

	conn := apns.NewConnection(&apnsLog, dc.idsConfig.PushKey, dc.idsConfig.PushCert)
	conn.ConnectErrorHandler = func(handlerCtx context.Context, status []byte) {
		if bytes.Equal(status, []byte{2}) {
			if dc.PushKeyRegenAttempted || dc.idsConfig.PushGenRetried {
				log.Warn().Msg("APNS connection failed with status 0x02, but we already tried to regenerate the push key, not trying again")
				return
			}
			dc.PushKeyRegenAttempted = true
			err := dc.regenPushKey(ctx, dc.idsConfig)
			dc.idsConfig.PushGenRetried = true
			dc.EventHandler(&ConfigUpdated{})
			if err != nil {
				analytics.Track("IMGo Push Key Reset", map[string]any{
					"success": false,
					"error":   err.Error(),
				})
				log.Err(err).Msg("Failed to regenerate push key after apns 0x02")
			} else {
				analytics.Track("IMGo Push Key Reset", map[string]any{
					"success": true,
				})
				log.Info().Msg("Regenerated push key after apns 0x02, reconnecting")
				conn.SetPushKey(dc.idsConfig.PushKey, dc.idsConfig.PushCert)
				err = conn.Close()
				if err != nil {
					log.Warn().Err(err).Msg("Failed to close APNS connection after regenerating push key")
				}
			}
		}
	}
	conn.ConnectHandler = func(ctx context.Context) {
		log := zerolog.Ctx(ctx)
		dc.idsConfig.PushToken = conn.GetToken()
		log.Info().Msg("Connected to APNs")
		err := conn.SetState(1)
		if err != nil {
			log.Err(err).Msg("Failed to send SetState request after connect")
			return
		}
		err = conn.Filter(apns.TopicMadrid, apns.TopicAlloySMS, apns.TopicIDS)
		if err != nil {
			log.Err(err).Msg("Failed to set filter topics after connect")
			return
		}
		log.Debug().Msg("Set APNs connection state and topic filter")

		dc.User.Conn = conn
		if onConnect != nil {
			onConnect()
		}

		if dc.User.HasAuthCerts() {
			go func() {
				err := dc.RegisterIDS(ctx, false)
				if onRegister != nil {
					onRegister()
				}
				if err != nil {
					log.Err(err).Msg("Failed to register IDS after connect")
					return
				}
			}()

			go dc.loginTestAfterLoginLoop(ctx)
		} else {
			if onRegister != nil {
				onRegister()
			}
			if dc.User.NeedsRefresh() {
				dc.EventHandler(&RefreshCredentialsRequired{
					UserID: dc.User.ProfileID,
				})
			}
		}

		dc.EventHandler(&APNSConnected{})
	}

	conn.MessageHandler = dc.handleAPNSMessage
	jsonConfig := dc.idsConfig.ToJSONConfig()

	for {
		connectTime := time.Now()
		log.Info().
			Any("push_key", jsonConfig.Push.Key.Sha256Fingerprint()).
			Any("push_cert", jsonConfig.Push.Cert.Sha256Fingerprint()).
			Any("push_token", dc.idsConfig.PushToken).
			Msg("Connecting to APNS")
		err := conn.Connect(ctx, true, dc.idsConfig.PushToken)
		if errors.Is(err, context.Canceled) {
			log.Info().Err(err).Msg("Context canceled, exiting APNS connection")
			return
		} else if err != nil {
			analytics.Track("IMGo APNs Connection Failed", map[string]any{
				"error": err.Error(),
			})
			log.Err(err).Msg("Connecting to APNS failed, retrying in 3 seconds")
			time.Sleep(3 * time.Second)
			continue
		}

		err = conn.Run(ctx)
		if errors.Is(err, context.Canceled) {
			log.Info().Err(err).Msg("Context canceled, exiting APNS connection")
			return
		}
		if time.Since(connectTime) < 90*time.Second {
			log.Debug().Err(err).Msg("Disconnected from APNS, reconnecting in 6 seconds")
			// Prevent reconnection tight loop
			time.Sleep(6 * time.Second)
		} else {
			log.Debug().Err(err).Msg("Disconnected from APNS, reconnecting immediately")
		}
	}
}

func (dc *Connector) Stop(ctx context.Context) {
	if dc.cancel != nil {
		dc.cancel()
	}

	log := zerolog.Ctx(ctx)
	if dc.User != nil && dc.User.Conn != nil {
		log.Debug().Msg("Stopping connection")
		err := dc.User.Conn.Close()
		if err != nil {
			log.Warn().Err(err).Msg("Failed to close APNS connection")
		}
		dc.User.Conn = nil
	}
}

func (dc *Connector) ResolveIdentifiers(ctx context.Context, force bool, handle *uri.ParsedURI, identifiers ...string) (found, notFound []uri.ParsedURI, err error) {
	output := make([]uri.ParsedURI, 0, len(identifiers))
	for _, identifier := range identifiers {
		parsed, err := uri.ParseIdentifier(identifier, uri.ParseiMessageDM|uri.POShortcodes)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to parse %q: %v", identifier, err)
		}
		if parsed.IsShortcode() {
			// Don't even try to resolve shortcodes, but do return them so the caller can switch to SMS forwarding
			notFound = append(notFound, parsed)
		} else {
			output = append(output, parsed)
		}
	}

	if handle == nil {
		handle = &dc.User.DefaultHandle
	}

	result, err := dc.User.Lookup(ctx, *handle, ids.LookupParams{Force: force, Ratelimiter: dc.manualLookupLimiter}, output)
	if err != nil {
		return nil, output, err
	}

	notFound = make([]uri.ParsedURI, 0)
	found = output[:0]
	for _, identifier := range output {
		identifierResult, ok := result[identifier]
		if !ok {
			for key, val := range result {
				if key.Scheme == identifier.Scheme && strings.EqualFold(key.Identifier, identifier.Identifier) {
					zerolog.Ctx(ctx).Warn().
						Str("original_identifier", identifier.String()).
						Str("result_identifier", key.String()).
						Msg("Lookup result included identifier with different case")
					identifierResult = val
					identifier = key
					ok = true
					break
				}
			}
			if !ok {
				notFound = append(notFound, identifier)
				zerolog.Ctx(ctx).Warn().
					Str("identifier", identifier.String()).
					Msg("Lookup result didn't include identifier at all (not even an empty result)")
				continue
			}
		}
		if len(identifierResult.Identities) == 0 {
			notFound = append(notFound, identifier)
		} else {
			found = append(found, identifier)
		}

		analytics.Track("IMGo Identifier Resolved", map[string]any{
			"success":                  len(identifierResult.Identities) > 0,
			"uri scheme":               identifier.Scheme,
			"force":                    force,
			"is login test identifier": slices.Contains(dc.LoginTestConfig.Identifiers, identifier.String()),
		})
	}
	found = uri.Sort(found)
	notFound = uri.Sort(notFound)
	return
}

func (dc *Connector) broadcastNewHandleToSelf(ctx context.Context) error {
	if dc.User == nil || dc.User.Conn == nil {
		return fmt.Errorf("can't broadcast handles without being connected to APNs")
	} else if len(dc.User.Handles) == 0 {
		return fmt.Errorf("no handles to broadcast")
	}

	for _, handle := range dc.User.Handles {
		err := dc.BroadcastHandleTo(ctx, []uri.ParsedURI{handle}, handle, false)
		if err != nil {
			return fmt.Errorf("failed to broadcast handle %s to self: %w", handle, err)
		}
	}

	return nil
}

func (dc *Connector) SendDelivered(ctx context.Context, input *apns.SendMessagePayload, sessionToken []byte) error {
	noResponseNeeded := true
	newPayload := &apns.SendMessagePayload{
		Command:          apns.MessageTypeCertifiedDelivery,
		UserAgent:        dc.User.Versions.CombinedVersion(),
		Version:          8,
		MessageUUID:      input.MessageUUID,
		SenderID:         input.DestinationID,
		DestinationID:    input.SenderID,
		SessionToken:     sessionToken,
		Token:            input.Token,
		NoResponseNeeded: &noResponseNeeded,
	}
	// TODO this is probably wrong
	if input.CertifiedDeliveryRts != nil {
		newPayload.CertifiedDeliveryVersion = input.CertifiedDeliveryVersion
		newPayload.CertifiedDeliveryRts = input.CertifiedDeliveryRts
	}

	msgBytes, err := plist.Marshal(newPayload, plist.BinaryFormat)
	if err != nil {
		return fmt.Errorf("failed to marshal payload: %w", err)
	}
	log := zerolog.Ctx(ctx)
	if log.Trace().Enabled() {
		var unmarshaled map[string]any
		_, _ = plist.Unmarshal(msgBytes, &unmarshaled)
		log.Trace().Any("message_data", unmarshaled).Msg("DEBUG: Sending certified delivery receipt to iMessage")
	}

	err = dc.User.Conn.SendMessage(apns.TopicMadrid, msgBytes, random.Bytes(4))
	if err != nil {
		return fmt.Errorf("failed to send payload: %w", err)
	}

	return nil
}

type broadcastHandleCacheEntry struct {
	sender uri.ParsedURI
	target uri.ParsedURI
}

func (dc *Connector) BroadcastHandleTo(ctx context.Context, identities []uri.ParsedURI, senderHandle uri.ParsedURI, onlyIfNotBroadcasted bool) error {
	dc.handleBroadcastLock.Lock()
	defer dc.handleBroadcastLock.Unlock()
	log := zerolog.Ctx(ctx).With().
		Str("source_handle", senderHandle.String()).
		Str("action", "broadcast handle").
		Logger()
	ctx = log.WithContext(ctx)
	if onlyIfNotBroadcasted {
		identities = slices.DeleteFunc(identities, func(parsedURI uri.ParsedURI) bool {
			_, alreadyBroadcasted := dc.handleBroadcastCache[broadcastHandleCacheEntry{sender: senderHandle, target: parsedURI}]
			return alreadyBroadcasted
		})
		if len(identities) == 0 {
			return nil
		}
	}
	messageUUID := uuid.New()
	status := false
	dtl, extraRes, err := dc.constructDTL(ctx, senderHandle, identities, func(ctx context.Context, participant uri.ParsedURI, ident ids.LookupIdentity) (apns.SendMessagePayload, error) {
		return apns.SendMessagePayload{
			DestinationID:  &participant,
			DeliveryStatus: &status,
			SessionToken:   ident.SessionToken,
			Token:          ident.PushToken,
		}, nil
	}, constructDTLExtra{omitParticipant: func(ctx context.Context, handle uri.ParsedURI, res *ids.LookupResult) bool {
		return onlyIfNotBroadcasted && res.Broadcasted
	}, idsParams: ids.LookupParams{
		// We want to minimize IDS lookups for these broadcasts, so disable the usual cache expiry
		// and only refetch if we don't have a cached result or if it's over 7 days old.
		AlwaysUseCache: onlyIfNotBroadcasted,
	}})
	if err != nil {
		return fmt.Errorf("failed to construct DTL: %w", err)
	}
	for _, skippedURI := range extraRes.Skipped {
		dc.handleBroadcastCache[broadcastHandleCacheEntry{sender: senderHandle, target: skippedURI}] = struct{}{}
	}
	if len(dtl) == 0 {
		return nil
	}

	log.Debug().
		Bool("only_if_not_broadcasted", onlyIfNotBroadcasted).
		Array("destinations", uri.ToZerologArray(extraRes.Found)).
		Int("destination_device_count", len(dtl)).
		Array("skipped", uri.ToZerologArray(extraRes.Skipped)).
		Msg("Broadcasting handle")
	commandBodies, err := dc.splitDTL(apns.MessageTypePeerCacheInvalidate, messageUUID, senderHandle, dtl, 200, true)
	for _, body := range commandBodies {
		err = dc.User.Conn.SendMessage(apns.TopicMadrid, body.body, body.messageID)
		if err != nil {
			return fmt.Errorf("failed to send broadcast message: %w", err)
		}
	}

	err = dc.IDSCache.MarkBroadcasted(ctx, senderHandle, extraRes.Found...)
	if err != nil {
		log.Err(err).Msg("Failed to mark handle as broadcasted")
	}
	for _, broadcastedURI := range extraRes.Found {
		dc.handleBroadcastCache[broadcastHandleCacheEntry{sender: senderHandle, target: broadcastedURI}] = struct{}{}
	}

	return nil
}

type SendResponse struct {
	ID      uuid.UUID        `json:"id"`
	Service imessage.Service `json:"service"`
	Time    time.Time        `json:"time"`
}

func (dc *Connector) fixSendFromHandle(ctx context.Context, handle uri.ParsedURI, participants []uri.ParsedURI) (uri.ParsedURI, []uri.ParsedURI) {
	log := zerolog.Ctx(ctx)
	if handle.IsEmpty() {
		handle = dc.User.DefaultHandle
	} else if !slices.Contains(dc.User.Handles, handle) {
		log.Warn().
			Str("handle", handle.String()).
			Msg("Tried to send message from handle that isn't in handles list, overriding with default")
		handle = dc.User.DefaultHandle
		// TODO remove old own handle from group?
	}
	if !slices.Contains(participants, handle) {
		participants = append(participants, handle)
	}
	return handle, participants
}

type constructDTLExtra struct {
	omitParticipant func(ctx context.Context, handle uri.ParsedURI, lookup *ids.LookupResult) bool
	idsParams       ids.LookupParams
}

type constructDTLExtraResult struct {
	Found    []uri.ParsedURI
	NotFound []uri.ParsedURI
	Skipped  []uri.ParsedURI
}

// constructDTL builds an array of payloads for a provided list of participants, using the dtlConstructor func
// to generate the payload for each participants URI and resolved identity
// Returns an array of generated payloads and an array of participants (excluding us) that we weren't able to find
// any identiies for
func (dc *Connector) constructDTL(
	ctx context.Context,
	sendFromHandle uri.ParsedURI,
	participants []uri.ParsedURI,
	dtlConstructor func(context.Context, uri.ParsedURI, ids.LookupIdentity) (apns.SendMessagePayload, error),
	extras ...constructDTLExtra,
) ([]apns.SendMessagePayload, *constructDTLExtraResult, error) {
	if len(extras) > 1 {
		panic("too many extra args")
	}
	var extra constructDTLExtra
	if len(extras) == 1 {
		extra = extras[0]
	}

	log := zerolog.Ctx(ctx).With().Str("method", "construct dtl").Str("send_from", sendFromHandle.String()).Logger()
	ctx = log.WithContext(ctx)

	userLookup, err := dc.User.Lookup(ctx, sendFromHandle, extra.idsParams, participants)
	if err != nil {
		return nil, nil, err
	}

	var dtl []apns.SendMessagePayload
	participantLogDict := zerolog.Dict()
	var foundParticipants, notFoundParticipants, skippedParticipants []uri.ParsedURI
	var pairCount, pairECCount int
	for _, participant := range participants {
		log := log.With().Str("participant", participant.String()).Logger()

		pushTokensLogArr := zerolog.Arr()
		lookupResult := userLookup[participant]
		if extra.omitParticipant != nil && extra.omitParticipant(ctx, participant, lookupResult) {
			skippedParticipants = append(skippedParticipants, participant)
			continue
		}
		if len(lookupResult.Identities) == 0 && !slices.Contains(dc.User.Handles, participant) {
			notFoundParticipants = append(notFoundParticipants, participant)
		} else {
			foundParticipants = append(foundParticipants, participant)
		}
		for _, ident := range lookupResult.Identities {
			if bytes.Equal(ident.PushToken, dc.User.PushToken) {
				continue
			}
			log := log.With().Str("push_token", base64.StdEncoding.EncodeToString(ident.PushToken)).Logger()
			ctx := log.WithContext(ctx)

			if ident.ClientData.PublicMessageIdentityKey == nil {
				log.Debug().
					Str("handle", participant.String()).
					Str("push_token", base64.StdEncoding.EncodeToString(ident.PushToken)).
					Msg("No encryption keys found for participant")
				continue
			}

			pushTokensLogArr.Str(base64.StdEncoding.EncodeToString(ident.PushToken))

			payload, err := dtlConstructor(ctx, participant, ident)
			if err != nil {
				return nil, nil, err
			}
			switch payload.EncryptionType {
			case apns.EncryptionTypePair:
				pairCount++
			case apns.EncryptionTypePairEC:
				pairECCount++
			}
			dtl = append(dtl, payload)
		}
		participantLogDict.Array(participant.Identifier, pushTokensLogArr)
	}

	logEvt := log.Debug().
		Dict("participants", participantLogDict).
		Array("not_found_participants", uri.ToZerologArray(notFoundParticipants))
	if pairCount > 0 || pairECCount > 0 {
		logEvt.Dict(
			"encryption_types",
			zerolog.Dict().
				Int("pair", pairCount).
				Int("pair_ec", pairECCount),
		)
	}
	if skippedParticipants != nil {
		logEvt.Array("skipped_participants", uri.ToZerologArray(skippedParticipants))
	}
	logEvt.Msg("Constructed DTL to participants")
	return dtl, &constructDTLExtraResult{
		Found:    foundParticipants,
		NotFound: notFoundParticipants,
		Skipped:  skippedParticipants,
	}, nil
}

var ErrNotOnIMessage = errors.New("requested user is not on iMessage")
var ErrNoSMSForwarding = errors.New("SMS forwarding not enabled")

func (dc *Connector) SendSMS(ctx context.Context, msg *ReflectedSMS) (*SendResponse, error) {
	handle := dc.User.SMSForwarding.GetHandle()
	if handle.IsEmpty() {
		// TODO enable this (breaks existing users until they re-enable SMS forwarding)
		return nil, ErrNoSMSForwarding
	}
	apnsType := apns.MessageTypeReflectedSMS
	// TODO do long messages actually need MMS? They seem to work without it fine
	if msg.Data.XHTML != "" || msg.Data.Subject != "" || len(msg.Data.PlainBody) > 160 || len(msg.Recipients) > 1 {
		apnsType = apns.MessageTypeReflectedMMS
	}
	return dc.sendEncryptedMessage(ctx, handle, []uri.ParsedURI{handle}, nil, msg, apnsType, msg.Data.GUID.UUID, false, true)
}

func (dc *Connector) SendMessage(ctx context.Context, sendFromHandle uri.ParsedURI, msg *IMessage, id uuid.UUID) (*SendResponse, error) {
	sendFromHandle, msg.Participants = dc.fixSendFromHandle(ctx, sendFromHandle, msg.Participants)
	return dc.sendEncryptedMessage(ctx, sendFromHandle, msg.Participants, nil, msg, apns.MessageTypeIMessage, id, true, true)
}

type commandPart struct {
	body      []byte
	messageID []byte
}

func (dc *Connector) splitDTL(
	command apns.MessageType,
	messageUUID uuid.UUID,
	sendFromHandle uri.ParsedURI,
	dtl []apns.SendMessagePayload,
	approxMessageSize int,
	noResponseNeeded bool,
) ([]commandPart, error) {
	var commandBodies []commandPart
	chunkSize := dc.User.Conn.MaxLargeMessageSize / approxMessageSize
	if chunkSize > 20 {
		chunkSize = 20
	} else if chunkSize < 1 {
		chunkSize = 1
	}
	var noResp *bool
	if noResponseNeeded {
		noResp = &noResponseNeeded
	}
	for chunk := 0; chunk*chunkSize < len(dtl); chunk++ {
		end := (chunk + 1) * chunkSize
		if end > len(dtl) {
			end = len(dtl)
		}
		messageID := random.Bytes(4)
		commandBody := &apns.SendMessagePayload{
			Command:           command,
			UserAgent:         dc.User.CombinedVersion(),
			FanoutChunkNumber: chunk + 1,
			Version:           8,
			MessageID:         binary.BigEndian.Uint32(messageID),
			MessageUUID:       messageUUID[:],
			DTL:               dtl[chunk*chunkSize : end],
			NoResponseNeeded:  noResp,
			SenderID:          &sendFromHandle,
		}
		commandBodyBytes, err := plist.Marshal(commandBody, plist.BinaryFormat)
		if err != nil {
			return nil, err
		}
		// Uncertain if these are actually included in the size count
		// 32 bytes of push token, 20 byte sha1 hash of topic, 4 byte message id, 5 bytes of apns overhead, 3 bytes per apns field
		const apnsSendMessageOverhead = 32 + 20 + 4 + 5 + 4*3
		if chunkSize > 1 && len(commandBodyBytes)+apnsSendMessageOverhead > dc.User.Conn.MaxLargeMessageSize {
			// If the marshaled message looks too big, try again with a smaller chunk size
			chunkSize--
			chunk--
			continue
		}
		commandBodies = append(commandBodies, commandPart{body: commandBodyBytes, messageID: messageID})
	}
	return commandBodies, nil
}

func (dc *Connector) sendEncryptedMessage(ctx context.Context, sendFromHandle uri.ParsedURI, participants, origParticipants []uri.ParsedURI, msg any, command apns.MessageType, messageUUID uuid.UUID, isRetriable bool, rerouteOnIDSFailure bool) (*SendResponse, error) {
	if messageUUID == uuid.Nil {
		messageUUID = uuid.New()
	}
	if origParticipants == nil {
		origParticipants = participants
	}
	log := zerolog.Ctx(ctx).With().
		Str("message_uuid", messageUUID.String()).
		Str("outgoing_handle", sendFromHandle.String()).
		Logger()
	ctx = log.WithContext(ctx)
	dat, err := plist.Marshal(msg, plist.BinaryFormat)
	if err != nil {
		return nil, err
	}
	if log.Trace().Enabled() {
		var unmarshaled map[string]any
		_, _ = plist.Unmarshal(dat, &unmarshaled)
		log.Trace().Any("message_data", unmarshaled).Msg("DEBUG: Sending converted message to iMessage")
	}
	compressed, err := gnuzip.GZip(dat)
	if err != nil {
		return nil, err
	}

	dtl, extraRes, err := dc.constructDTL(ctx, sendFromHandle, participants, func(ctx context.Context, participant uri.ParsedURI, ident ids.LookupIdentity) (apns.SendMessagePayload, error) {
		payload, encryptionType, err := dc.User.EncryptSignPayload(ctx, participant, &ident, compressed)
		if err != nil {
			return apns.SendMessagePayload{}, err
		}

		deliveryStatus := participant != sendFromHandle
		smp := apns.SendMessagePayload{
			DestinationID:  &participant,
			EncryptionType: encryptionType,
			DeliveryStatus: &deliveryStatus,
			SessionToken:   ident.SessionToken,
			Token:          ident.PushToken,
			Payload:        payload,
		}

		//if deliveryStatus && ident.ClientData.Extra["supports-certified-delivery-v1"] == true {
		//	smp.CertifiedDeliveryVersion = 1
		//	hash := sha1.Sum(payload)
		//	smp.CertifiedDeliveryRts = hash[:]
		//}
		return smp, nil
	})
	if err != nil {
		return nil, err
	} else if len(origParticipants) >= 2 && len(extraRes.NotFound) >= len(origParticipants)-1 {
		if rerouteOnIDSFailure {
			log.Info().Msg("IDS lookups failed, let's try rerouting and sending again")
			err = dc.RerouteAndReregister(ctx, extraRes.NotFound)
			if err == nil {
				log.Info().Msg("Reroute succeeded, attempting the send again")
				return dc.sendEncryptedMessage(ctx, sendFromHandle, participants, origParticipants, msg, command, messageUUID, isRetriable, false)
			}
		}

		// No identities were found for this send, after accounting for us also being in the participants list
		return nil, ErrNotOnIMessage
	} else if len(dtl) == 0 {
		log.Warn().Any("not_found", extraRes.NotFound).Msg("No participants to send message to")
		return nil, nil
	}
	topic := apns.TopicMadrid
	service := imessage.ServiceIMessage
	if command == apns.MessageTypeReflectedSMS || command == apns.MessageTypeReflectedMMS {
		topic = apns.TopicAlloySMS
		service = imessage.ServiceSMS
		if dc.User.SMSForwarding != nil {
			for i, item := range dtl {
				if bytes.Equal(item.Token, dc.User.SMSForwarding.Token) {
					dtl = dtl[i : i+1]
					break
				}
			}
		}
	}
	aw := dc.newAckWaiter(len(dtl), messageUUID)
	i := 0
	for i2, part := range dtl {
		// TODO check length? what to do if it's not 32 🤔
		tokenArr := *(*pushToken)(part.Token)
		existing, tokenExists := aw.payloads[tokenArr]
		// Keep duplicates for the same destination in the DTL, in case there are duplicate entries (like with and without pair-ec keys)
		if !tokenExists || existing.Destination == *part.DestinationID {
			aw.payloads[tokenArr] = &ackWaiterPayload{Destination: *part.DestinationID}
			aw.ackedUsers[*part.DestinationID] = false
			if i2 != i {
				dtl[i] = part
			}
			i++
		} else {
			log.Warn().
				Str("existing_destination", existing.Destination.String()).
				Str("omitted_destination", part.DestinationID.String()).
				Str("token", base64.StdEncoding.EncodeToString(part.Token)).
				Msg("Ignoring duplicate push token with different handle in DTL")
		}
	}
	dtl = dtl[:i]
	// We have to add the length of the map and not the length of dtl because there may be duplicate push tokens?!?
	aw.wg.Add(len(aw.payloads))
	aw.userWG.Add(len(aw.ackedUsers))

	commandBodies, err := dc.splitDTL(command, messageUUID, sendFromHandle, dtl, len(compressed)+300, false)

	for _, part := range commandBodies {
		err = dc.User.Conn.SendMessage(topic, part.body, part.messageID)
		if err != nil {
			aw.Cancel()
			dc.finishAckWaiting(messageUUID, aw)
			return nil, err
		}
	}
	sentAt := time.Now()

	waitChan := aw.Wait()
	select {
	case <-waitChan:
		log.Debug().Msg("Received all acks within initial timeout")
	case <-aw.ErrorChan():
		log.Warn().Msg("Received server error within initial timeout")
	case <-ctx.Done():
		aw.Cancel()
		log.Warn().Err(ctx.Err()).Msg("Context was done before all acks were received")
		return nil, ctx.Err()
	case <-time.After(1 * time.Second):
		log.Debug().Msg("Didn't receive all acks within initial timeout, waiting for at least one ack from each user")
		select {
		case <-waitChan:
		case <-aw.WaitForUsers():
		case <-aw.ErrorChan():
			log.Warn().Msg("Received server error during extended timeout")
		case <-ctx.Done():
			aw.Cancel()
			log.Warn().Err(ctx.Err()).Msg("Context was done before at least one ack from each user was received")
			return nil, ctx.Err()
		case <-time.After(19 * time.Second):
			aw.Cancel()
			log.Warn().Msg("Reached timeout before acks from all users were received")
		}
	}
	if servErr := aw.ServerError(); servErr != 0 {
		return &SendResponse{
			ID:      messageUUID,
			Service: service,
			Time:    sentAt,
		}, types.IDSError{ErrorCode: servErr}
	}
	sme := aw.CompileError()
	if sme.MissingCount > 0 || sme.ErrorCount > 0 {
		var logEvt *zerolog.Event
		if sme.hasError() {
			logEvt = log.Warn()
		} else {
			logEvt = log.Debug()
		}
		logEvt.
			Any("error_counts", sme.CountByErrorType).
			Object("full_status", sme.StatusByUser).
			Int("success_count", sme.SuccessCount).
			Int("missing_count", sme.MissingCount).
			Msg("One or more destinations failed or was missing when sending message")
	} else {
		log.Debug().
			Int("token_count", sme.DestinationTokenCount).
			Int("user_count", sme.DestinationUserCount).
			Msg("Message was successfully sent to all destinations")
	}
	if len(sme.MissingUsers) > 0 {
		log.Warn().
			Array("missing_users", uri.ToZerologArray(sme.MissingUsers)).
			Msg("Didn't receive acks from some users")
		analytics.Track("IMGo Missed Acks", map[string]any{
			"target user count": len(aw.ackedUsers),
			"missed user count": len(sme.MissingUsers),
			"message id":        messageUUID.String(),
		})
	}
	if isRetriable && sme.CountByErrorType[types.IDSStatusBadSignature] > 0 {
		var resendTo []uri.ParsedURI
		for dest, uec := range sme.StatusByUser {
			if len(uec.Failed) == 0 || !slices.Contains(maps.Values(uec.Failed), types.IDSStatusBadSignature) {
				continue
			}
			resendTo = append(resendTo, dest)
		}
		if len(resendTo) > 0 {
			aw.Close()
			log.Debug().
				Any("destinations", resendTo).
				Msg("Redoing IDS lookup and resending to destinations")
			_, err = dc.User.Lookup(ctx, sendFromHandle, ids.LookupParams{Force: true}, resendTo)
			if err != nil {
				log.Err(err).Msg("Relookup for bad signature destinations failed")
			} else {
				return dc.sendEncryptedMessage(ctx, sendFromHandle, resendTo, origParticipants, msg, command, messageUUID, false, rerouteOnIDSFailure)
			}
		}
	}
	if sme.hasError() {
		err = sme
	}

	return &SendResponse{
		ID:      messageUUID,
		Service: service,
		Time:    sentAt,
	}, err
}

func (dc *Connector) SendReadReceipt(ctx context.Context, sendFromHandle uri.ParsedURI, participants []uri.ParsedURI, readUpTo uuid.UUID, service imessage.Service) error {
	log := zerolog.Ctx(ctx)
	sendFromHandle, participants = dc.fixSendFromHandle(ctx, sendFromHandle, participants)
	command := apns.MessageTypeReadReceipt
	topic := apns.TopicMadrid
	if service == imessage.ServiceSMS {
		command = apns.MessageTypeSMSRead
		topic = apns.TopicAlloySMS
		participants = []uri.ParsedURI{sendFromHandle}
	}
	dtl, _, err := dc.constructDTL(ctx, sendFromHandle, participants, func(ctx context.Context, participant uri.ParsedURI, ident ids.LookupIdentity) (apns.SendMessagePayload, error) {
		deliveryStatus := participant != sendFromHandle
		return apns.SendMessagePayload{
			DestinationID:  &participant,
			DeliveryStatus: &deliveryStatus,
			SessionToken:   ident.SessionToken,
			Token:          ident.PushToken,
		}, nil
	})
	if err != nil {
		return err
	}

	on := true
	now := plisttime.UnixNanoNow()
	messageID := random.Bytes(4)

	commandBody := &apns.SendMessagePayload{
		Command:           command,
		Timestamp:         &now,
		NoResponseNeeded:  &on,
		Version:           8,
		MessageUUID:       readUpTo[:],
		DTL:               dtl,
		SenderID:          &sendFromHandle,
		MessageID:         binary.BigEndian.Uint32(messageID),
		FanoutChunkNumber: 1,
		UserAgent:         dc.User.CombinedVersion(),
	}

	commandBodyBytes, err := plist.Marshal(commandBody, plist.BinaryFormat)
	if err != nil {
		return err
	}
	log.Trace().
		Any("command_body_bytes", commandBodyBytes).
		Str("read_up_to", readUpTo.String()).
		Msg("DEBUG: SENDING READ RECEIPT")

	return dc.User.Conn.SendMessage(topic, commandBodyBytes, messageID)
}

func (dc *Connector) SendMarkUnread(ctx context.Context, sendFromHandle uri.ParsedURI, messageGUID uuid.UUID) error {
	log := zerolog.Ctx(ctx)
	dat, err := plist.Marshal(&MarkUnread{
		MessageID: plistuuid.NewFromUUID(messageGUID),
	}, plist.BinaryFormat)
	if err != nil {
		return err
	}
	dtl, _, err := dc.constructDTL(ctx, sendFromHandle, []uri.ParsedURI{sendFromHandle}, func(ctx context.Context, participant uri.ParsedURI, ident ids.LookupIdentity) (apns.SendMessagePayload, error) {
		payload, encryptionType, err := dc.User.EncryptSignPayload(ctx, participant, &ident, dat)
		if err != nil {
			return apns.SendMessagePayload{}, err
		}

		smp := apns.SendMessagePayload{
			DestinationID:  &participant,
			EncryptionType: encryptionType,
			SessionToken:   ident.SessionToken,
			Token:          ident.PushToken,
			Payload:        payload,
		}
		return smp, nil
	})
	if err != nil {
		return err
	}

	on := true
	now := plisttime.UnixNanoNow()
	commandBody := &apns.SendMessagePayload{
		Command:          apns.MessageTypeMarkUnread,
		Timestamp:        &now,
		NoResponseNeeded: &on,
		Version:          8,
		DTL:              dtl,
		SenderID:         &sendFromHandle,
		MessageUUID:      messageGUID[:],
		UserAgent:        dc.User.CombinedVersion(),
	}

	commandBodyBytes, err := plist.Marshal(commandBody, plist.BinaryFormat)
	if err != nil {
		return err
	}
	log.Trace().
		Any("command_body_bytes", commandBodyBytes).
		Msg("DEBUG: SENDING MARK UNREAD")

	return dc.User.Conn.SendMessage(apns.TopicMadrid, commandBodyBytes, random.Bytes(4))
}

func (dc *Connector) SendTypingNotification(ctx context.Context, sendFromHandle uri.ParsedURI, participants []uri.ParsedURI, groupID string, typing bool) (*SendResponse, error) {
	sendFromHandle, participants = dc.fixSendFromHandle(ctx, sendFromHandle, participants)
	if !typing {
		// Send an empty message with no content to tell the other devices that we have stopped typing.
		// TODO stop typing messages are probably also supposed to have ExpirationSeconds set to 0
		return dc.sendEncryptedMessage(ctx, sendFromHandle, participants, nil, &IMessage{
			Participants:      participants,
			GroupID:           groupID,
			GroupVersion:      CurrentGroupVersion,
			PropertiesVersion: 0,
			ProtocolVersion:   CurrentProtocolVersion,
		}, apns.MessageTypeIMessage, uuid.New(), false, true)
	}

	dtl, _, err := dc.constructDTL(ctx, sendFromHandle, participants, func(ctx context.Context, participant uri.ParsedURI, ident ids.LookupIdentity) (apns.SendMessagePayload, error) {
		return apns.SendMessagePayload{
			DestinationID: &participant,
			SessionToken:  ident.SessionToken,
			Token:         ident.PushToken,
		}, nil
	})
	if err != nil {
		return nil, err
	}

	messageUUID := uuid.New()
	now := plisttime.UnixNanoNow()
	zero := 0
	on := true
	commandBody := &apns.SendMessagePayload{
		Command:           apns.MessageTypeIMessage,
		IsTrustedSender:   true,
		Version:           8,
		MessageUUID:       messageUUID[:],
		SenderID:          &sendFromHandle,
		Timestamp:         &now,
		DTL:               dtl,
		ExpirationSeconds: &zero,
		NoResponseNeeded:  &on,
	}

	commandBodyBytes, err := plist.Marshal(commandBody, plist.BinaryFormat)
	if err != nil {
		return nil, err
	}
	err = dc.User.Conn.SendMessage(apns.TopicMadrid, commandBodyBytes, random.Bytes(4))
	if err != nil {
		return nil, err
	}

	return &SendResponse{
		ID:      messageUUID,
		Service: imessage.ServiceIMessage,
		Time:    time.Now(),
	}, nil
}

func (dc *Connector) SendUnsend(ctx context.Context, sendFromHandle uri.ParsedURI, participants []uri.ParsedURI, groupID string, messageUUID uuid.UUID, partIndex int) (*SendResponse, error) {
	sendFromHandle, participants = dc.fixSendFromHandle(ctx, sendFromHandle, participants)
	return dc.sendEncryptedMessage(ctx, sendFromHandle, participants, nil, &IMessageEdit{
		EditMessageID:   plistuuid.NewFromUUID(messageUUID),
		EditType:        EditTypeUnsend,
		EditPartIndex:   partIndex,
		RS:              true,
		ProtocolVersion: CurrentProtocolVersion,
	}, apns.MessageTypeIMessageEdit, uuid.New(), true, true)
}

func (dc *Connector) SendEdit(ctx context.Context, sendFromHandle uri.ParsedURI, participants []uri.ParsedURI, groupID string, messageUUID uuid.UUID, part int, xhtml string) (*SendResponse, error) {
	editXML := IMessageEditDetails{
		Edits: []imessage.MessagePart{
			{PartIdx: part, Value: xhtml},
		},
	}
	editXMLBytes, err := xml.Marshal(editXML)
	if err != nil {
		return nil, err
	}

	sendFromHandle, participants = dc.fixSendFromHandle(ctx, sendFromHandle, participants)
	return dc.sendEncryptedMessage(ctx, sendFromHandle, participants, nil, &IMessageEdit{
		EditMessageID:   plistuuid.NewFromUUID(messageUUID),
		EditXML:         string(editXMLBytes),
		EditType:        EditTypeEdit,
		EditPartIndex:   part,
		ProtocolVersion: CurrentProtocolVersion,
	}, apns.MessageTypeIMessageEdit, uuid.New(), true, true)
}

func participantsStrings(participants []uri.ParsedURI) []string {
	participantsStrings := make([]string, len(participants))
	for i, participant := range participants {
		participantsStrings[i] = participant.Identifier
	}
	return participantsStrings
}

func (dc *Connector) UpdateChatName(ctx context.Context, sendFromHandle uri.ParsedURI, participants []uri.ParsedURI, groupID, newName string) (*SendResponse, error) {
	sendFromHandle, participants = dc.fixSendFromHandle(ctx, sendFromHandle, participants)

	return dc.sendEncryptedMessage(ctx, sendFromHandle, participants, nil, &IMessageGroupMetaChange{
		GroupID:      groupID,
		GroupVersion: CurrentGroupVersion,
		Type:         GroupMetaChangeName,
		Participants: participantsStrings(participants),

		GroupName:    newName,
		NewGroupName: newName,
	}, apns.MessageTypeIMessageGroupMeta, uuid.New(), true, true)
}

func (dc *Connector) UpdateChatAvatar(ctx context.Context, sendFromHandle uri.ParsedURI, participants []uri.ParsedURI, groupID, groupName string, propertiesVersion int, avatar []byte) (string, error) {
	var newGroupAvatar *IMFileTransfer
	var avatarGUID string
	if avatar != nil {
		attachment, err := dc.User.UploadAttachment(ctx, avatar, "GroupPhotoImage", "image/png")
		if err != nil {
			return "", err
		}

		avatarGUID = fmt.Sprintf("at_0_%s", strings.ToUpper(uuid.New().String()))

		transferMessageGUID := plistuuid.New()
		newGroupAvatar = &IMFileTransfer{
			IMFileTransferCreatedDate: float64(time.Now().UnixMicro()) / 1000000,
			IMFileTransferFilenameKey: "GroupPhotoImage",
			IMFileTransferGUID:        avatarGUID,
			IMFileTransferMessageGUID: &transferMessageGUID,
			IMFileTransferLocalUserInfoKey: IMFileTransferLocalUserInfoKey{
				DecryptionKey:    attachment.DecryptionKey,
				FileSize:         fmt.Sprintf("%d", attachment.FileSize),
				MMCSOwner:        attachment.MMCSOwner,
				MMCSSignatureHex: attachment.MMCSSignatureHex,
				MMCSURL:          attachment.MMCSURL,
			},
		}
	}

	_, err := dc.sendEncryptedMessage(ctx, sendFromHandle, participants, nil, &IMessageGroupMetaChange{
		GroupID:           groupID,
		GroupVersion:      CurrentGroupVersion,
		PropertiesVersion: propertiesVersion,
		Type:              GroupMetaChangeAvatar,
		Participants:      participantsStrings(participants),

		GroupName:      groupName,
		NewGroupAvatar: newGroupAvatar,
	}, apns.MessageTypeIMessageGroupMeta, uuid.New(), true, true)
	return avatarGUID, err
}

func (dc *Connector) UpdateParticipants(ctx context.Context, sendFromHandle uri.ParsedURI, participants []uri.ParsedURI, groupID string, newParticipants []uri.ParsedURI) (*SendResponse, error) {
	sendFromHandle, participants = dc.fixSendFromHandle(ctx, sendFromHandle, participants)

	return dc.sendEncryptedMessage(ctx, sendFromHandle, participants, nil, &IMessageGroupMetaChange{
		GroupID:            groupID,
		GroupVersion:       CurrentGroupVersion,
		PropertiesVersion:  0, // TODO
		Type:               GroupMetaChangeParticipants,
		Participants:       participantsStrings(participants),
		TargetParticipants: participantsStrings(newParticipants),
	}, apns.MessageTypeIMessageGroupMeta, uuid.New(), true, true)
}
