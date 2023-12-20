// beeper-imessage - A Matrix-iMessage puppeting bridge.
// Copyright (C) 2022 Tulir Asokan
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

package main

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	"go.mau.fi/util/exfmt"
	"golang.org/x/exp/slices"
	"golang.org/x/time/rate"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
	log "maunium.net/go/maulogger/v2"
	"maunium.net/go/mautrix/bridge/commands"
	"maunium.net/go/mautrix/bridge/status"

	"github.com/beeper/imessage/analytics"
	"github.com/beeper/imessage/imessage"
	"github.com/beeper/imessage/imessage/direct"
	"github.com/beeper/imessage/imessage/direct/ids"
	"github.com/beeper/imessage/imessage/direct/nacserv"
	"github.com/beeper/imessage/imessage/direct/util/uri"

	"maunium.net/go/mautrix/appservice"
	"maunium.net/go/mautrix/bridge"
	"maunium.net/go/mautrix/bridge/bridgeconfig"

	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"

	"github.com/beeper/imessage/database"
)

type User struct {
	*database.User

	PermissionLevel bridgeconfig.PermissionLevel
	Admin           bool
	Whitelisted     bool

	bridge *IMBridge
	log    log.Logger
	zlog   zerolog.Logger

	IM *direct.Connector

	DoublePuppetIntent     *appservice.IntentAPI
	mgmtCreateLock         sync.Mutex
	spaceMembershipChecked bool
	commandState           *commands.CommandState
	BridgeState            *bridge.BridgeStateQueue

	manualLookupRatelimiter *rate.Limiter
}

var _ bridge.User = (*User)(nil)

func (br *IMBridge) getUserByMXID(userID id.UserID, onlyIfExists bool) *User {
	if br.IsGhost(userID) || userID == br.Bot.UserID {
		return nil
	}
	br.usersLock.Lock()
	defer br.usersLock.Unlock()
	user, ok := br.usersByMXID[userID]
	if !ok {
		userIDPtr := &userID
		if onlyIfExists {
			userIDPtr = nil
		}
		ctx := context.TODO()
		dbUser, err := br.DB.User.GetByMXID(ctx, userID)
		if err != nil {
			br.ZLog.Err(err).
				Str("user_id", userID.String()).
				Msg("Failed to load user from database")
			return nil
		}
		return br.loadDBUser(ctx, dbUser, userIDPtr)
	}
	return user
}

func (br *IMBridge) GetUserByRowID(rowID int) *User {
	br.usersLock.Lock()
	defer br.usersLock.Unlock()
	user, ok := br.usersByRowID[rowID]
	if !ok {
		ctx := context.TODO()
		dbUser, err := br.DB.User.GetByRowID(ctx, rowID)
		if err != nil {
			br.ZLog.Err(err).
				Int("rowid", rowID).
				Msg("Failed to load user from database")
			return nil
		}
		return br.loadDBUser(ctx, dbUser, nil)
	}
	return user
}

func (br *IMBridge) GetUserByMXID(userID id.UserID) *User {
	return br.getUserByMXID(userID, false)
}

func (br *IMBridge) GetUserByMXIDIfExists(userID id.UserID) *User {
	return br.getUserByMXID(userID, true)
}

func (br *IMBridge) GetAllUsersWithSession() []*User {
	return br.loadManyUsers(br.DB.User.GetAllWithAppleRegistration)
}

func (br *IMBridge) GetAllUsersWithDoublePuppet() []*User {
	return br.loadManyUsers(br.DB.User.GetAllWithDoublePuppet)
}

func (br *IMBridge) loadManyUsers(query func(ctx context.Context) ([]*database.User, error)) []*User {
	br.usersLock.Lock()
	defer br.usersLock.Unlock()
	ctx := context.TODO()
	dbUsers, err := query(ctx)
	if err != nil {
		br.ZLog.Err(err).Msg("Failed to all load users from database")
		return []*User{}
	}
	output := make([]*User, len(dbUsers))
	for index, dbUser := range dbUsers {
		user, ok := br.usersByMXID[dbUser.MXID]
		if !ok {
			user = br.loadDBUser(ctx, dbUser, nil)
		}
		output[index] = user
	}
	return output
}

func (br *IMBridge) loadDBUser(ctx context.Context, dbUser *database.User, mxid *id.UserID) *User {
	if dbUser == nil {
		if mxid == nil {
			return nil
		}
		dbUser = br.DB.User.New()
		dbUser.MXID = *mxid
		err := dbUser.Insert(ctx)
		if err != nil {
			br.ZLog.Err(err).
				Str("user_id", mxid.String()).
				Msg("Failed to insert user to database")
			return nil
		}
	}
	user := br.NewUser(dbUser)
	br.usersByMXID[user.MXID] = user
	br.usersByRowID[user.RowID] = user
	if len(user.ManagementRoom) > 0 {
		br.managementRooms[user.ManagementRoom] = user
	}
	if user.AppleRegistration != nil && user.AppleRegistration.PushGenVersion == 0 && user.AppleRegistration.PushKey != nil {
		user.AppleRegistration.PushGenVersion = 2
	}
	return user
}

func (br *IMBridge) NewUser(dbUser *database.User) *User {
	user := &User{
		User:   dbUser,
		bridge: br,
		log:    br.Log.Sub("User").Sub(string(dbUser.MXID)),
		zlog:   br.ZLog.With().Str("user_id", dbUser.MXID.String()).Logger(),

		manualLookupRatelimiter: br.Config.IMessage.LookupRatelimit.Compile(),
	}

	user.PermissionLevel = user.bridge.Config.Bridge.Permissions.Get(user.MXID)
	user.Whitelisted = user.PermissionLevel >= bridgeconfig.PermissionLevelUser
	user.Admin = user.PermissionLevel >= bridgeconfig.PermissionLevelAdmin

	user.BridgeState = br.NewBridgeStateQueue(user)

	return user
}

func (br *IMBridge) GetIUser(userID id.UserID, create bool) bridge.User {
	u := br.getUserByMXID(userID, !create)
	if u == nil {
		return nil
	}
	return u
}

func (user *User) GetPuppetByURI(uri uri.ParsedURI) *Puppet {
	return user.bridge.GetPuppetByURI(database.Key{Receiver: user.RowID, URI: uri})
}

func (user *User) GetPortalByURI(uri uri.ParsedURI) *Portal {
	return user.bridge.GetPortalByID(database.Key{Receiver: user.RowID, URI: uri})
}

func (user *User) GetAllPortals() []*Portal {
	return user.bridge.GetAllPortalsForUser(user.RowID)
}

func (user *User) FindPortalsWithRecentMessages(interval time.Duration) []*Portal {
	return user.bridge.FindPortalsWithRecentMessages(user.RowID, interval)
}

func (user *User) FindPortalByParticipants(participants []uri.ParsedURI) *Portal {
	return user.bridge.FindPortalByParticipants(participants, user.RowID)
}

func (user *User) GetPermissionLevel() bridgeconfig.PermissionLevel {
	return user.PermissionLevel
}

func (user *User) makeNACClient() *nacserv.Client {
	nacClient := &nacserv.Client{
		URL:     user.bridge.Config.Bridge.NACValidationDataURL,
		Token:   user.bridge.Config.Bridge.NACValidationDataToken,
		IsRelay: user.bridge.Config.Bridge.NACValidationIsRelay,
	}
	if nacURLOverride := user.bridge.DB.KV.Get(database.KVNACServURL); nacURLOverride != "" {
		user.zlog.Info().Str("url", nacURLOverride).Msg("Using relay URL saved in database")
		nacClient.URL = nacURLOverride
	}
	if strings.HasPrefix(nacClient.URL, "https://registration-relay.beeper") {
		nacClient.BeeperToken = user.bridge.Config.Bridge.Provisioning.SharedSecret
	}
	if nacTokenOverride := user.bridge.DB.KV.Get(database.KVNACServToken); nacTokenOverride != "" {
		user.zlog.Info().Msg("Using relay token saved in database")
		nacClient.Token = nacTokenOverride
		nacClient.IsRelay = true
	}

	return nacClient
}

var ErrNoNAC = errors.New("no nac configured")

func (user *User) Start() error {
	// TODO lock creating connector
	if user.IM == nil {
		nacClient := user.makeNACClient()
		if nacClient.Token == "" && nacClient.URL == "" {
			return ErrNoNAC
		}
		user.IM = direct.NewConnector(
			nacClient,
			user.HandleEvent,
			&database.IDSCache{Query: user.bridge.DB.IDSCache, UserID: user.RowID},
			&database.RerouteHistory{Query: user.bridge.DB.RerouteHistory, UserID: user.RowID},
			user.bridge.Config.IMessage.EnablePairECSending,
			database.NewOutgoingCounterStore(user.bridge.DB.OutgoingCounter, user.RowID),
			user.manualLookupRatelimiter,
		)
		user.IM.LoginTestConfig = user.bridge.Config.IMessage.LoginTest
		cfg := user.AppleRegistration
		cfgWasNil := false
		if cfg == nil {
			cfgWasNil = true
			cfg = &ids.Config{}
			user.AppleRegistration = cfg
		}
		ctx := user.zlog.WithContext(context.TODO())
		err := user.IM.Configure(ctx, cfg, false)
		if err != nil {
			user.zlog.Err(err).Msg("Failed to configure iMessage connection")
			user.BridgeState.Send(status.BridgeState{StateEvent: status.StateUnknownError, Error: "im-albert-fail"})
			return err
		}
		if cfgWasNil {
			user.bridge.DB.KV.Delete(database.KVHackyNACErrorPersistence)
		}
		go user.IM.Run(user.zlog, nil, nil)

		if user.bridge.DB.KV.Get(database.KVLookedForPortals) != "true" {
			if err = user.FindPortalsFromMatrix(); err != nil {
				user.zlog.Err(err).Msg("Error populating portals from Matrix rooms")
			} else {
				user.bridge.DB.KV.Set(database.KVLookedForPortals, "true")
			}
		}
	}
	return nil
}

func (user *User) Stop() {
	if user.IM != nil {
		user.IM.Stop(context.TODO())
		user.IM = nil
	}
}

func (user *User) Logout() {
	err := user.IM.Logout(context.TODO())
	if err != nil {
		user.zlog.Warn().Err(err).Msg("Failed to logout")
	}
	user.BridgeState.Send(status.BridgeState{StateEvent: status.StateLoggedOut})
	user.bridge.DB.KV.Delete(database.KVHackyNACErrorPersistence)
	user.Stop()
	user.AppleRegistration = nil
	// TODO don't ignore errors
	user.Update(context.TODO())
}

var letterRegex = regexp.MustCompile("[A-Z0-9]")

func (user *User) FillBridgeState(state status.BridgeState) status.BridgeState {
	if state.Info == nil {
		state.Info = make(map[string]any)
	}

	if state.StateEvent == status.StateConnected {
		if user.NeedsRefresh() {
			state.StateEvent = status.StateBadCredentials
			state.Error = "im-ids-refresh-credentials"
			state.Info["refresh_profile_id"] = user.IM.User.ProfileID
		} else if !user.IsIDSRegistered() {
			state.StateEvent = status.StateUnknownError
			state.Error = "im-ids-not-registered"
		}
	}
	if user.IM != nil {
		handles := make([]string, len(user.IM.User.Handles))
		for i, handle := range user.IM.User.Handles {
			handles[i] = handle.String()
		}
		state.Info["handles"] = handles

		if user.IM.NACServ.Token == "" && user.IM.NACServ.URL == "" {
			state.StateEvent = status.StateUnknownError
			state.Error = "im-nacserv-not-configured"
		} else if user.IM.NACServ.IsRelay {
			state.Info["relay"] = map[string]any{
				"url":   user.IM.NACServ.URL,
				"token": user.IM.NACServ.Token[:10] + letterRegex.ReplaceAllString(user.IM.NACServ.Token[10:], "*"),
			}
		}

		state.Info["default_handle"] = user.IM.User.DefaultHandle.String()
		state.Info["preferred_handle"] = user.IM.User.PreferredHandle.String()
		if user.IM.User.SMSForwarding != nil {
			state.Info["sms_forwarding"] = map[string]any{
				"enabled": user.IM.User.SMSForwarding.Token != nil,
				"via":     user.IM.User.SMSForwarding.Handle.String(),
			}
		} else {
			state.Info["sms_forwarding"] = map[string]any{"enabled": false}
		}
	} else if user.AppleRegistration != nil {
		handles := make([]string, len(user.AppleRegistration.Handles))
		for i, handle := range user.AppleRegistration.Handles {
			handles[i] = handle.String()
		}
		state.Info["handles"] = handles
		state.Info["default_handle"] = user.AppleRegistration.DefaultHandle.String()
		state.Info["preferred_handle"] = user.AppleRegistration.DefaultHandle.String()
		state.Info["im_missing"] = true
	}
	state.Info["hide_read_receipts"] = user.HideReadReceipts
	return state
}

func (user *User) HasCredentials() bool {
	return user.AppleRegistration != nil &&
		user.AppleRegistration.AuthPrivateKey != nil &&
		!user.AppleRegistration.IDRegisteredAt.IsZero() &&
		len(user.AppleRegistration.AuthIDCertPairs) > 0
}

func (user *User) NeedsRefresh() bool {
	if user.AppleRegistration == nil {
		return false
	}
	pair := user.AppleRegistration.AuthIDCertPairs[user.AppleRegistration.ProfileID]
	return pair != nil && pair.RefreshNeeded
}

func (user *User) IsIDSRegistered() bool {
	if user.AppleRegistration == nil {
		return false
	}
	pair := user.AppleRegistration.AuthIDCertPairs[user.AppleRegistration.ProfileID]
	return pair != nil && pair.IDCert != nil
}

func (user *User) IsLoggedIn() bool {
	return user.HasValidAuthCerts() && user.IM.HasValidIDCerts()
}

func (user *User) HasValidAuthCerts() bool {
	return user.IM != nil && user.IM.HasValidAuthCerts()
}

func (user *User) GetManagementRoomID() id.RoomID {
	return user.ManagementRoom
}

func (user *User) GetOrCreateManagementRoom() id.RoomID {
	if user.ManagementRoom == "" {
		user.mgmtCreateLock.Lock()
		defer user.mgmtCreateLock.Unlock()
		if user.ManagementRoom != "" {
			return user.ManagementRoom
		}
		creationContent := make(map[string]any)
		if !user.bridge.Config.Bridge.FederateRooms {
			creationContent["m.federate"] = false
		}
		resp, err := user.bridge.Bot.CreateRoom(&mautrix.ReqCreateRoom{
			Topic:           "iMessage bridge notices",
			IsDirect:        true,
			CreationContent: creationContent,
			Invite:          []id.UserID{user.MXID},

			BeeperAutoJoinInvites: true,
		})
		if err != nil {
			user.log.Errorln("Failed to auto-create management room:", err)
		} else {
			user.SetManagementRoom(resp.RoomID)
		}
	}
	return user.ManagementRoom
}

func (user *User) SetManagementRoom(roomID id.RoomID) {
	user.ManagementRoom = roomID
	// TODO don't ignore errors
	user.Update(context.TODO())
}

func (user *User) GetMXID() id.UserID {
	return user.MXID
}

func (user *User) GetRemoteID() string {
	if user.IM != nil && user.IM.User != nil {
		return user.IM.User.ProfileID
	} else if user.AppleRegistration != nil {
		return user.AppleRegistration.ProfileID
	} else {
		return "unknown"
	}
}

func (user *User) GetRemoteName() string {
	if user.IM != nil && user.IM.User != nil {
		return user.IM.User.DefaultHandle.Identifier
	} else if user.AppleRegistration != nil {
		return user.AppleRegistration.DefaultHandle.Identifier
	} else {
		return ""
	}
}

func (user *User) GetCommandState() *commands.CommandState {
	return user.commandState
}

func (user *User) SetCommandState(state *commands.CommandState) {
	user.commandState = state
}

func (user *User) GetIDoublePuppet() bridge.DoublePuppet {
	return user
}

func (user *User) GetIGhost() bridge.Ghost {
	return nil
}

func (user *User) ensureInvited(intent *appservice.IntentAPI, roomID id.RoomID, isDirect bool) (ok bool) {
	extraContent := map[string]interface{}{}
	if isDirect {
		extraContent["is_direct"] = true
	}
	if user.DoublePuppetIntent != nil {
		extraContent["fi.mau.will_auto_accept"] = true
	}
	_, err := intent.InviteUser(roomID, &mautrix.ReqInviteUser{UserID: user.MXID}, extraContent)
	var httpErr mautrix.HTTPError
	if err != nil && errors.As(err, &httpErr) && httpErr.RespError != nil && strings.Contains(httpErr.RespError.Err, "is already in the room") {
		user.bridge.StateStore.SetMembership(roomID, user.MXID, event.MembershipJoin)
		ok = true
		return
	} else if err != nil {
		user.log.Warnfln("Failed to invite user to %s: %v", roomID, err)
	} else {
		ok = true
	}

	if user.DoublePuppetIntent != nil {
		err = user.DoublePuppetIntent.EnsureJoined(roomID)
		if err != nil {
			user.log.Warnfln("Failed to auto-join %s as %s: %v", roomID, user.MXID, err)
		}
	}
	return
}

func (user *User) GetSpaceRoom() id.RoomID {
	if !user.bridge.Config.Bridge.PersonalFilteringSpaces {
		return ""
	}

	if len(user.SpaceRoom) == 0 {
		name := "iMessage"
		resp, err := user.bridge.Bot.CreateRoom(&mautrix.ReqCreateRoom{
			Visibility: "private",
			Name:       name,
			Topic:      fmt.Sprintf("Your %s bridged chats", name),
			InitialState: []*event.Event{{
				Type: event.StateRoomAvatar,
				Content: event.Content{
					Parsed: &event.RoomAvatarEventContent{
						URL: user.bridge.Config.AppService.Bot.ParsedAvatar,
					},
				},
			}},
			CreationContent: map[string]interface{}{
				"type": event.RoomTypeSpace,
			},
			PowerLevelOverride: &event.PowerLevelsEventContent{
				Users: map[id.UserID]int{
					user.bridge.Bot.UserID: 9001,
					user.MXID:              100,
				},
			},
		})

		if err != nil {
			user.log.Errorln("Failed to auto-create space room:", err)
		} else {
			user.SpaceRoom = resp.RoomID
			user.Update(context.TODO())
			user.ensureInvited(user.bridge.Bot, user.SpaceRoom, false)
		}
	} else if !user.spaceMembershipChecked && !user.bridge.StateStore.IsInRoom(user.SpaceRoom, user.MXID) {
		user.ensureInvited(user.bridge.Bot, user.SpaceRoom, false)
	}
	user.spaceMembershipChecked = true

	return user.SpaceRoom
}

type StartChatRequest struct {
	Identifiers []string `json:"identifiers"`
}

type StartChatResponse struct {
	RoomID      id.RoomID     `json:"room_id,omitempty"`
	URI         uri.ParsedURI `json:"uri"`
	JustCreated bool          `json:"just_created"`
}

func (user *User) startChat(req StartChatRequest) (*StartChatResponse, error) {
	var resp StartChatResponse
	var err error

	if len(req.Identifiers) == 0 {
		return nil, fmt.Errorf("no identifiers provided")
	} else if len(req.Identifiers) > 32 {
		return nil, fmt.Errorf("too many identifiers")
	}

	service := imessage.ServiceIMessage

	ctx := user.zlog.With().Str("action", "start chat").Logger().WithContext(context.Background())
	participants, notFound, err := user.IM.ResolveIdentifiers(ctx, false, nil, req.Identifiers...)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve identifiers: %w", err)
	} else if len(participants) == 0 && user.IM.User.SMSForwarding.Token != nil {
		// If we didn't find any matching identifiers and SMS forwarding is enabled, check if all requested
		// participants are phone numbers. Will only work if all participants are non-iMessage.
		participants = make([]uri.ParsedURI, len(req.Identifiers))
		for i, identifier := range req.Identifiers {
			participants[i], err = uri.ParseIdentifier(identifier, uri.ParseOutgoingSMSForward)
			if err != nil {
				return nil, fmt.Errorf("some identifiers not found or not SMS: %+v", notFound)
			}
		}
		participants = uri.Sort(participants)
		service = imessage.ServiceSMS
	} else if len(notFound) > 0 {
		return nil, fmt.Errorf("some identifiers not found: %+v", notFound)
	}

	sourceMsg := &imessage.Message{
		Participants: participants,
		Service:      service,
	}
	var portal *Portal
	if len(participants) == 1 {
		resp.URI = participants[0]
	} else {
		portal = user.FindPortalByParticipants(participants)
		if portal == nil {
			// Group chat, create a new group.
			sourceMsg.GroupID = strings.ToUpper(uuid.New().String())
			resp.URI = uri.ParsedURI{Scheme: uri.SchemeGroup, Identifier: sourceMsg.GroupID}
		} else {
			sourceMsg.GroupID = portal.GroupID
			resp.URI = portal.URI
		}
	}
	if portal == nil {
		portal = user.GetPortalByURI(resp.URI)
	}
	if len(portal.MXID) > 0 {
		resp.RoomID = portal.MXID
		return &resp, nil
	}
	portal.Participants = participants
	portal.OutgoingHandle = user.IM.User.DefaultHandle

	if err = portal.CreateMatrixRoom(sourceMsg); err != nil {
		return nil, fmt.Errorf("failed to create Matrix room: %w", err)
	} else {
		resp.JustCreated = true
		resp.RoomID = portal.MXID
		return &resp, nil
	}
}

func (user *User) setDefaultHandle(handle uri.ParsedURI) error {
	if !slices.Contains(user.IM.User.Handles, handle) {
		return fmt.Errorf("unknown handle")
	}

	analytics.Track("IMGo Default Handle Changed", map[string]any{
		"old_handle": user.IM.User.DefaultHandle,
		"new_handle": handle,
		"bi":         true,
	})
	user.IM.User.DefaultHandle = handle
	user.IM.User.PreferredHandle = handle
	if err := user.Update(context.TODO()); err != nil {
		return err
	}
	user.BridgeState.Send(status.BridgeState{StateEvent: status.StateConnected})
	return nil
}

func (user *User) setHideReadReceipts(hide bool) error {
	user.HideReadReceipts = hide
	if err := user.Update(context.Background()); err != nil {
		return err
	}
	user.zlog.Debug().Bool("hide", hide).Msg("Toggled hide read receipts status")
	user.BridgeState.Send(status.BridgeState{StateEvent: status.StateConnected})
	return nil
}

func (user *User) broadcastHandlesToRecentConversations() {
	recentPortals := user.FindPortalsWithRecentMessages(14 * exfmt.Day)
	recipientURIs := make([]uri.ParsedURI, 0, len(recentPortals))
	for _, portal := range recentPortals {
		recipientURIs = append(recipientURIs, portal.Participants...)
	}
	// Sort and remove duplicates
	recipientURIs = uri.Sort(recipientURIs)

	user.zlog.Info().
		Any("handles", user.IM.User.Handles).
		Any("recipients", recipientURIs).
		Msg("Broadcasting handles to recent conversations")

	for _, handle := range user.IM.User.Handles {
		err := user.IM.BroadcastHandleTo(context.TODO(), recipientURIs, handle, false)
		if err != nil {
			user.zlog.Err(err).Str("handle", handle.String()).Msg("Failed to broadcast handle to recent conversations")
		}
	}
}
