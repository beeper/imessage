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
	_ "embed"
	"encoding/json"
	"errors"
	"sync"

	"go.mau.fi/util/configupgrade"
	"maunium.net/go/mautrix/bridge"
	"maunium.net/go/mautrix/bridge/commands"
	"maunium.net/go/mautrix/bridge/status"
	"maunium.net/go/mautrix/id"

	"github.com/beeper/imessage/analytics"
	"github.com/beeper/imessage/config"
	"github.com/beeper/imessage/database"
	_ "github.com/beeper/imessage/imessage/direct"
	"github.com/beeper/imessage/imessage/direct/ids"
)

var (
	// These are filled at build time with the -X linker flag
	Tag       = "unknown"
	Commit    = "unknown"
	BuildTime = "unknown"
)

//go:embed example-config.yaml
var ExampleConfig string

type IMBridge struct {
	bridge.Bridge
	Config       *config.Config
	DB           *database.Database
	Provisioning *ProvisioningAPI

	portalsByMXID   map[id.RoomID]*Portal
	portalsByKey    map[database.Key]*Portal
	portalsLock     sync.Mutex
	usersByMXID     map[id.UserID]*User
	usersByRowID    map[int]*User
	managementRooms map[id.RoomID]*User
	usersLock       sync.Mutex
	puppetsByKey    map[database.Key]*Puppet
	puppetsLock     sync.Mutex
}

func (br *IMBridge) GetExampleConfig() string {
	return ExampleConfig
}

func (br *IMBridge) GetConfigPtr() interface{} {
	br.Config = &config.Config{
		BaseConfig: &br.Bridge.Config,
	}
	br.Config.BaseConfig.Bridge = &br.Config.Bridge
	return br.Config
}

func (br *IMBridge) CreatePrivatePortal(roomID id.RoomID, user bridge.User, ghost bridge.Ghost) {
	// TODO implement
}

func (br *IMBridge) Init() {
	br.CommandProcessor = commands.NewProcessor(&br.Bridge)
	br.RegisterCommands()

	br.DB = database.New(br.Bridge.DB)

	analytics.Init(br.Config.Analytics, br.ZLog.With().Str("component", "analytics").Logger(), analytics.BridgeTypeCloud, nil)
	analytics.Version = br.Version

	br.Bridge.BeeperNetworkName = "imessage"
	br.Bridge.BeeperServiceName = "imessagego"

	ids.DeviceName = br.Config.IMessage.DeviceName

	ss := br.Config.Bridge.Provisioning.SharedSecret
	if len(ss) > 0 && ss != "disable" {
		br.Provisioning = &ProvisioningAPI{bridge: br}
	}
}

func (br *IMBridge) Start() {
	br.ZLog.Debug().Msg("Starting users")
	for _, user := range br.GetAllUsersWithDoublePuppet() {
		// TODO handle error
		user.StartCustomMXID(true)
	}
	startedAnyUsers := false
	for _, user := range br.GetAllUsersWithSession() {
		if !user.HasCredentials() {
			continue
		}
		startedAnyUsers = true
		err := user.Start()
		if errors.Is(err, ErrNoNAC) {
			user.zlog.Warn().Msg("NAC not configured, logging out user")
			state := status.BridgeState{StateEvent: status.StateBadCredentials, Error: "im-nacserv-not-configured"}
			stateForDB := state.Fill(user)
			user.BridgeState.Send(state)
			data, _ := json.Marshal(&stateForDB)
			br.DB.KV.Set(database.KVHackyNACErrorPersistence, string(data))
			user.AppleRegistration = nil
			// TODO don't ignore errors
			user.Update(context.TODO())
		} else if err == nil {
			user.tryAutomaticDoublePuppeting()
		}
	}
	if !startedAnyUsers {
		if hackyNACErrorPersistence := br.DB.KV.Get(database.KVHackyNACErrorPersistence); hackyNACErrorPersistence != "" {
			var state status.BridgeState
			_ = json.Unmarshal([]byte(hackyNACErrorPersistence), &state)
			br.ZLog.Debug().Interface("bridge_state", state).Msg("Sending cached NAC error state")
			br.GetUserByMXID(state.UserID).BridgeState.Send(state)
		} else {
			br.SendGlobalBridgeState(status.BridgeState{StateEvent: status.StateUnconfigured})
		}
	}

	br.WaitWebsocketConnected()

	if br.Provisioning != nil {
		br.ZLog.Debug().Msg("Initializing provisioning API")
		br.Provisioning.Init()
	}

	br.ZLog.Info().Msg("Initialization complete")
}

func (br *IMBridge) Stop() {
	br.ZLog.Debug().Msg("Stopping users")
	for _, user := range br.usersByMXID {
		if user.IM != nil {
			user.Stop()
		}
	}
}

func main() {
	br := &IMBridge{
		portalsByMXID:   make(map[id.RoomID]*Portal),
		portalsByKey:    make(map[database.Key]*Portal),
		puppetsByKey:    make(map[database.Key]*Puppet),
		usersByMXID:     make(map[id.UserID]*User),
		usersByRowID:    make(map[int]*User),
		managementRooms: make(map[id.RoomID]*User),
	}
	br.Bridge = bridge.Bridge{
		Name: "beeper-imessage",

		URL:          "https://github.com/beeper/imessage",
		Description:  "A Matrix-iMessage puppeting bridge.",
		Version:      "0.1.0",
		ProtocolName: "iMessage",

		CryptoPickleKey: "go.mau.fi/mautrix-imessage",

		ConfigUpgrader: &configupgrade.StructUpgrader{
			SimpleUpgrader: configupgrade.SimpleUpgrader(config.DoUpgrade),
			Blocks:         config.SpacedBlocks,
			Base:           ExampleConfig,
		},

		Child: br,
	}
	br.InitVersion(Tag, Commit, BuildTime)

	br.Main()
}
