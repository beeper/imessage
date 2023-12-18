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

package main

import "C"
import (
	"context"
	_ "embed"
	"io"
	"os"
	"os/signal"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/rs/zerolog"
	deflog "github.com/rs/zerolog/log"
	"go.mau.fi/util/dbutil"
	_ "go.mau.fi/util/dbutil/litestream"
	"go.mau.fi/util/exzerolog"
	"go.mau.fi/zeroconfig"

	"github.com/beeper/imessage/analytics"
	"github.com/beeper/imessage/database"
	"github.com/beeper/imessage/imessage/direct/ids"
	"github.com/beeper/imessage/imessage/direct/util/uri"
	"github.com/beeper/imessage/ipc"
	"github.com/beeper/imessage/msgconv"
)

const writerTypeStdoutIPC zeroconfig.WriterType = "com.beeper.imessage.stdout-ipc"

func initLog() *zerolog.Logger {
	logConfig := global.Cfg.Logging
	if logConfig == nil {
		minLevel := zerolog.DebugLevel
		logConfig = &zeroconfig.Config{
			Writers:  []zeroconfig.WriterConfig{{Type: writerTypeStdoutIPC}},
			MinLevel: &minLevel,
		}
	}
	log, err := logConfig.Compile()
	if err != nil {
		panic(err)
	}
	defaultCtxLog := log.With().Bool("default_context_log", true).Caller().Logger()
	zerolog.TimeFieldFormat = time.RFC3339Nano
	zerolog.CallerMarshalFunc = exzerolog.CallerWithFunctionName
	zerolog.DefaultContextLogger = &defaultCtxLog
	deflog.Logger = log.With().Bool("global_log", true).Caller().Logger()
	return log
}

var (
	Commit    string
	BuildTime string
)

func secondaryIMLog(ctx context.Context) context.Context {
	return zerolog.Ctx(ctx).With().Bool("secondary_im", true).Logger().WithContext(ctx)
}

type AnalyticsEvent struct {
	Event      string         `json:"event"`
	Properties map[string]any `json:"properties"`
}

func analyticsTrackOverIPC(event string, properties map[string]any) error {
	return global.IPC.Send(CmdAnalyticEvent, &AnalyticsEvent{
		Event:      event,
		Properties: properties,
	})
}

func main() {}

//export start
func start() {
	writer := ipc.NewLockedWriter(&FFIStdout)
	zeroconfig.RegisterWriter(writerTypeStdoutIPC, func(config *zeroconfig.WriterConfig) (io.Writer, error) {
		return writer, nil
	})
	log := initLog()
	global.Log = log
	ctx, cancelGlobalCtx := context.WithCancel(log.WithContext(context.Background()))
	global.Ctx = ctx
	log.Info().
		Str("version", Commit).
		Str("built_at", BuildTime).
		Str("go_version", runtime.Version()).
		Msg("Initializing iMessage IPC")

	analytics.Init(global.Cfg.Analytics, log.With().Str("component", "analytics").Logger(), analytics.BridgeTypeIMA, analyticsTrackOverIPC)
	analytics.Version = Commit

	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt, syscall.SIGTERM)

	global.MC = &msgconv.MessageConverter{
		PortalMethods: global,
		ConvertHEIF:   false,
		ConvertTIFF:   false,
		ConvertMOV:    false,
		ConvertCAF:    false,
		AsyncFiles:    global.Cfg.AsyncFileTransfer,
		Threads:       true,
	}

	ipcLog := log.With().Str("component", "ipc").Logger()
	global.IPC = ipc.NewProcessor(writer, FFIStdinReader, &ipcLog)
	global.IPC.SetHandler(CmdLogin, ipc.TypedHandler(fnLogin))
	global.IPC.SetHandler(CmdMessage, ipc.TypedHandler(fnMessage))
	global.IPC.SetHandler(CmdMultipartMessage, ipc.TypedHandler(fnMultipartMessage))
	global.IPC.SetHandler(CmdStartChat, ipc.TypedHandler(fnStartChat))
	global.IPC.SetHandler(CmdResolveIdentifier, ipc.TypedHandler(fnResolveIdentifier))
	global.IPC.SetHandler(CmdRegisterPhoneNumber, ipc.TypedHandler(fnRegisterPhoneNumber))
	global.IPC.SetHandler(CmdReregister, ipc.TypedHandler(fnReregister))
	global.IPC.SetHandler(CmdClearIDSCache, ipc.NoDataHandler(fnClearIDSCache))
	global.IPC.SetHandler(CmdDeregister, ipc.NoDataHandler(fnDeregister))
	global.IPC.SetHandler(CmdGetBridgeInfo, ipc.NoDataHandler(fnGetBridgeInfo))
	global.IPC.SetHandler(CmdSetDefaultHandle, ipc.TypedHandler(fnSetDefaultHandle))
	global.IPC.SetHandler(CmdBroadcastIMessage, ipc.TypedHandler(fnBroadcastIMessage))
	global.IPC.SetHandler(CmdSwapRegistrations, ipc.NoDataHandler(fnSwapRegistrations))
	global.IPC.SetHandler(CmdDeregisterSecondary, ipc.NoDataHandler(fnDeregisterSecondary))
	global.IPC.SetHandler(CmdLogout, ipc.NoDataHandler(fnLogout))
	global.IPC.SetHandler(CmdPing, ipc.NoDataHandler(func(ctx context.Context) any {
		return map[string]any{"ok": true, "logged_in": global.IM.HasValidAuthCerts()}
	}))
	global.IPC.SetHandler(CmdStop, ipc.NoDataHandler(func(ctx context.Context) any {
		select {
		case ch <- syscall.SIGUSR1:
		default:
		}
		return nil
	}))
	global.IPC.SetHandler(CmdRefreshRooms, ipc.NoDataHandler(fnRefreshRooms))
	global.IPC.SetHandler(CmdSetFCMPushToken, ipc.TypedHandler(fnSetFCMPushToken))
	global.IPC.SetHandler(CmdAppStateChange, ipc.TypedHandler(fnAppStateChange))
	global.IPC.SetHandler(CmdPanic, ipc.NoDataHandler(fnPanic))
	global.IPC.SetHandler(CmdCreateASP, ipc.TypedHandler(fnCreateAppSpecificPassword))
	global.IPC.SetHandler(CmdCheckConnection, ipc.NoDataHandler(fnCheckConnection))
	global.IPC.SetHandler(CmdSetRelay, ipc.TypedHandler(fnSetRelay))

	db, err := dbutil.NewWithDialect("ipcmessage.db", "sqlite3-fk-wal")
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to open database")
	}
	db.Owner = "beeper-imessage"
	db.Log = dbutil.ZeroLogger(log.With().Str("component", "database").Logger())
	global.DB = database.New(db)
	err = global.DB.Upgrade()
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to upgrade database")
	}
	user, err := global.DB.User.GetByRowID(ctx, 1)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to get user")
	} else if user == nil {
		user = global.DB.User.New()
		user.MXID = "@user:beeper.local"
		user.AppleRegistration = &ids.Config{}
		err = user.Insert(ctx)
		if err != nil {
			log.Fatal().Err(err).Msg("Failed to insert user")
		}
	}
	global.IM.IDSCache = &database.IDSCache{
		Query:  global.DB.IDSCache,
		UserID: user.RowID,
	}
	global.IM.OutgoingCounterStore = database.NewOutgoingCounterStore(global.DB.OutgoingCounter, user.RowID)
	global.DBUser = user

	removeExpiredCerts(log)

	if global.NAC.Token != "" {
		global.InitialConfigureDone = true
		initialConfigure(ctx)
	} else {
		global.StartConfirmed = true
		global.IPC.Send(CmdStarted, ReqStarted{LoggedIn: false, PendingNACURL: true})
		global.IPC.Send(CmdBridgeInfo, GetBridgeInfo())
	}

	ipcLoop := func() {
		global.IPC.Loop()
		select {
		case ch <- syscall.SIGHUP:
		default:
		}
	}

	if global.InitialConfigureDone {
		var ipcLoopOnce sync.Once
		go global.IM.Run(*log, func() {
			ipcLoopOnce.Do(func() {
				go ipcLoop()
			})
		}, nil)
	} else {
		go ipcLoop()
	}

	<-ch
	log.Info().Msg("Shutting down")
	global.Stopping.Store(true)
	stopCtx := log.WithContext(context.Background())
	cancelGlobalCtx()
	global.IM.Stop(stopCtx)
	global.SecondaryIM.Stop(stopCtx)
	global.StopImux(stopCtx)
	err = db.Close()
	if err != nil {
		log.Err(err).Msg("Failed to close database")
	}
	log.Info().Msg("Shutdown preparations complete, exiting")
}

func initialConfigure(ctx context.Context) {
	err := global.IM.Configure(ctx, global.DBUser.AppleRegistration, false)
	if err != nil {
		zerolog.Ctx(ctx).Fatal().Err(err).Msg("Failed to configure iMessage")
	}
	if global.DBUser.SecondaryReg != nil {
		secondaryContext := secondaryIMLog(ctx)
		err = global.SecondaryIM.Configure(secondaryContext, global.DBUser.SecondaryReg, true)
		if err != nil {
			zerolog.Ctx(ctx).Fatal().Err(err).Msg("Failed to configure secondary iMessage connector")
		}

		go func() {
			err := global.SecondaryIM.RunWithoutConn(secondaryIMLog(ctx))
			if err != nil {
				zerolog.Ctx(ctx).Err(err).Msg("Error in secondary iMessage connector registration")
			}
		}()
	}

	global.ResetImux()
}

func removeExpiredCerts(log *zerolog.Logger) {
	if global.Cfg.OwnPhoneNumbers == nil {
		return
	}
	changed := removeExpiredCertsInReg(*log, global.DBUser.AppleRegistration)
	if global.DBUser.SecondaryReg != nil {
		changed = removeExpiredCertsInReg(log.With().Bool("secondary_im", true).Logger(), global.DBUser.SecondaryReg) || changed

		var hasValidCerts = false
		for profileID := range global.DBUser.SecondaryReg.AuthIDCertPairs {
			if strings.HasPrefix(profileID, "P:") {
				hasValidCerts = true
			}
		}
		if !hasValidCerts {
			global.DBUser.SecondaryReg = nil
		}
	}
	if changed {
		err := global.DBUser.Update(global.Ctx)
		if err != nil {
			log.Fatal().Err(err).Msg("Failed to update user")
		}
	}
}

var groupOutgoingHandlesUpdated atomic.Bool

func updateGroupOutgoingHandles() {
	if !groupOutgoingHandlesUpdated.CompareAndSwap(false, true) {
		return
	}
	log := global.Log.With().Str("action", "update group outgoing handles").Logger()
	if global.DB.KV.Get("com.beeper.group_resynced_post_phone_reg_removal") == "v2" {
		log.Debug().Msg("Not resyncing: already resynced earlier")
		return
	}
	ctx := log.WithContext(global.Ctx)
	portals, err := global.DB.Portal.GetAllForUser(ctx, global.DBUser.RowID)
	if err != nil {
		log.Err(err).Msg("Failed to get all portals")
		return
	}
	log.Info().
		Int("total_portal_count", len(portals)).
		Strs("registered_phone_numbers", global.DBUser.RegisteredPhoneNumbers).
		Msg("Checking portals to update outgoing handle")
	newOutgoingHandle := global.IM.User.DefaultHandle
	for _, portal := range portals {
		if portal.URI.Scheme == uri.SchemeGroup && portal.OutgoingHandle.Scheme == uri.SchemeTel && !slices.Contains(global.IM.User.Handles, portal.OutgoingHandle) {
			oldParticipants := slices.Clone(portal.Participants)
			oldHandle := portal.OutgoingHandle
			newParticipants := slices.DeleteFunc(portal.Participants, func(participant uri.ParsedURI) bool {
				return participant == oldHandle
			})
			newParticipants = append(newParticipants, newOutgoingHandle)
			newParticipants = uri.Sort(newParticipants)
			portal.OutgoingHandle = newOutgoingHandle
			portal.Participants = newParticipants
			//portal.GroupID = strings.ToUpper(uuid.New().String())
			log.Info().
				Str("portal_uri", portal.URI.String()).
				Str("group_id", portal.GroupID).
				Str("old_outgoing_handle", oldHandle.String()).
				Str("new_outgoing_handle", portal.OutgoingHandle.String()).
				Array("old_participants", uri.ToZerologArray(oldParticipants)).
				Array("new_participants", uri.ToZerologArray(portal.Participants)).
				Msg("Updating outgoing handle for portal")
			err = portal.Update(ctx)
			if err != nil {
				log.Err(err).Msg("Failed to update portal")
				continue
			}
			sendUpdatedBridgeInfo(ctx, "", time.Now(), portal)
		}
	}
	log.Info().Msg("Finished updating portals")
	global.DB.KV.Set("com.beeper.group_resynced_post_phone_reg_removal", "v2")
}

func removeExpiredCertsInReg(log zerolog.Logger, reg *ids.Config) (changed bool) {
	for profileID, certs := range reg.AuthIDCertPairs {
		if strings.HasPrefix(profileID, "P:") && certs.RefreshNeeded && !slices.Contains(global.Cfg.OwnPhoneNumbers, profileID[2:]) {
			log.Info().
				Str("profile_id", profileID).
				Strs("own_phone_numbers", global.Cfg.OwnPhoneNumbers).
				Msg("Removing expired cert")
			delete(reg.AuthIDCertPairs, profileID)
			changed = true
		}
	}
	return
}

type ReqStarted struct {
	LoggedIn bool `json:"logged_in"`

	PendingNACURL bool `json:"pending_nac_url"`
}
