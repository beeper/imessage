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

import (
	"context"
	_ "embed"
	"encoding/gob"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"

	"github.com/rs/zerolog"
	"go.mau.fi/zeroconfig"
	"golang.org/x/time/rate"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"

	"github.com/beeper/imessage/config"
	"github.com/beeper/imessage/database"
	"github.com/beeper/imessage/imessage"
	"github.com/beeper/imessage/imessage/appleid"
	"github.com/beeper/imessage/imessage/direct"
	"github.com/beeper/imessage/imessage/direct/ids"
	"github.com/beeper/imessage/imessage/direct/nacserv"
	"github.com/beeper/imessage/imessage/direct/util/httputil"
	"github.com/beeper/imessage/imessage/ipc/imux"
	"github.com/beeper/imessage/ipc"
	"github.com/beeper/imessage/msgconv"
)

type Config struct {
	IMuxURL        string `json:"imux_url"`
	NACServURL     string `json:"nacserv_url"`
	NACServToken   string `json:"nacserv_token"`
	NACServIsRelay bool   `json:"nacserv_is_relay"`
	IMAToken       string `json:"ima_token"`

	OwnPhoneNumbers []string `json:"own_phone_numbers"`

	DeviceName        string `json:"device_name"`
	AttachmentDir     string `json:"attachment_directory"`
	WaitForMessage    bool   `json:"wait_for_message"`
	AsyncFileTransfer bool   `json:"async_file_transfer"`

	Logging   *zeroconfig.Config     `json:"logging"`
	Analytics config.AnalyticsConfig `json:"analytics"`
	MITM      MITMConfig             `json:"mitm"`

	EnablePairECSending bool `json:"enable_pair_ec_sending"`

	LoginTest config.IMessageLoginTestConfig `json:"login_test"`

	SendMultipart bool `json:"send_multipart"`
}

type MITMConfig struct {
	DisableTLSVerification bool `json:"disable_tls_verification"`
}

type IMContext struct {
	Log *zerolog.Logger
	IM  *direct.Connector
	IPC *ipc.Processor
	MC  *msgconv.MessageConverter
	Ctx context.Context
	DB  *database.Database
	Cfg *Config
	AID *appleid.Client
	NAC *nacserv.Client

	imux *imux.IMux

	SecondaryIM *direct.Connector

	DBUser *database.User

	StartConfirmed       bool
	InitialConfigureDone bool
	NACNotReachable      bool

	Stopping atomic.Bool
}

var _ msgconv.PortalMethods = (*IMContext)(nil)

var global = &IMContext{}

func must[T any](val T, err error) T {
	if err != nil {
		panic(err)
	}
	return val
}

//	var manualLookupRatelimiter = (&config.RatelimitConfig{
//		Every: 1 * time.Minute,
//		Burst: 128,
//	}).Compile()
var manualLookupRatelimiter *rate.Limiter

type RoomAvatarEventContent struct {
	URL  id.ContentURIString `json:"url"`
	Info *event.FileInfo     `json:"info,omitempty"`
}

var EventTypeMarkedUnreadIPC = event.Type{Class: event.UnknownEventType, Type: "m.marked_unread"}

type MarkedUnreadEventContent struct {
	Unread    bool   `json:"unread"`
	Timestamp uint64 `json:"timestamp"`
}

func init() {
	httputil.MaxRetries = 5
	// Register the alternative room avatar event type
	event.TypeMap[event.StateRoomAvatar] = reflect.TypeOf(RoomAvatarEventContent{})
	event.TypeMap[EventTypeMarkedUnreadIPC] = reflect.TypeOf(MarkedUnreadEventContent{})
	gob.Register(&RoomAvatarEventContent{})
	gob.Register(&MarkedUnreadEventContent{})

	must(0, json.Unmarshal(must(os.ReadFile("config.json")), &global.Cfg))

	global.NAC = &nacserv.Client{
		URL:     global.Cfg.NACServURL,
		Token:   global.Cfg.NACServToken,
		IsRelay: global.Cfg.NACServIsRelay,

		BeeperToken: global.Cfg.IMAToken,
	}

	global.IM = direct.NewConnector(global.NAC, handleEvent, nil, nil, global.Cfg.EnablePairECSending, nil, manualLookupRatelimiter)
	global.IM.LoginTestConfig = global.Cfg.LoginTest

	global.SecondaryIM = direct.NewConnector(global.NAC, handleSecondaryEvent, nil, nil, false, nil, manualLookupRatelimiter)
	if global.Cfg.AttachmentDir == "" {
		global.Cfg.AttachmentDir = "attachments"
	}
	if global.Cfg.DeviceName != "" {
		ids.DeviceName = global.Cfg.DeviceName
	}
	var err error
	global.Cfg.AttachmentDir, err = filepath.Abs(global.Cfg.AttachmentDir)
	if err != nil {
		panic(fmt.Errorf("failed to get absolute path of attachment directory: %w", err))
	}
	err = os.MkdirAll(global.Cfg.AttachmentDir, 0700)
	if err != nil {
		panic(fmt.Errorf("failed to create attachment directory: %w", err))
	}
}

func (imc *IMContext) GetMatrixReply(ctx context.Context, msg *imessage.Message) (threadRoot, replyFallback id.EventID) {
	if msg.ThreadRoot == nil {
		return "", ""
	}
	return messageToMXID(msg.ThreadRoot.ID, msg.ThreadRoot.MessagePartInfo), ""
}

func (imc *IMContext) GetiMessageThreadRoot(ctx context.Context, content *event.MessageEventContent) string {
	targetMXID := content.RelatesTo.GetThreadParent()
	if targetMXID == "" {
		targetMXID = content.RelatesTo.GetNonFallbackReplyTo()
		if targetMXID == "" {
			return ""
		}
	}
	msgID, part, err := mxidToMessageID(targetMXID)
	if err != nil {
		zerolog.Ctx(ctx).Warn().Err(err).Str("target_mxid", targetMXID.String()).Msg("Failed to parse reply target ID")
		return ""
	}
	return imessage.ParsedThreadRoot{
		MessagePartInfo: imessage.MessagePartInfo{
			PartID:     part.PartID,
			StartIndex: part.StartIndex,
			Length:     part.Length,
		},
		ID: msgID,
	}.String()
}

func (imc *IMContext) GetIM() *direct.Connector {
	return imc.IM
}

type contextKey int

const (
	contextKeyPortal contextKey = iota
)

func (imc *IMContext) GetData(ctx context.Context) *database.Portal {
	return ctx.Value(contextKeyPortal).(*database.Portal)
}

func (imc *IMContext) ResetImux() {
	if imc.imux != nil {
		imc.Log.Info().Msg("Closing old imux connection")
		imc.imux.Close()

		if !imc.IM.HasValidAuthCerts() || !imc.imux.IsUsingApnsPushToken(global.DBUser.AppleRegistration.PushToken) || !imc.imux.IsUsingFCMPushToken(global.DBUser.FCMPushToken) {
			imc.Log.Info().Msg("Push tokens changed or logged out, deregistering from imux")
			imc.imux.Deregister(context.TODO())
		}
		imc.imux = nil
	}

	if !imc.IM.HasValidAuthCerts() {
		imc.Log.Info().Msg("Not logged in, not connecting to imux")
	} else if global.DBUser.FCMPushToken == "" {
		imc.Log.Warn().Msg("Cannot start imux connection, no fcm token set")
	} else {
		imc.Log.Info().Msg("Starting imux connection")
		imuxLog := imc.Log.With().Str("component", "imux").Logger()
		global.imux = imux.NewIMux(&imuxLog, global.Cfg.IMuxURL, global.Cfg.IMAToken, global.DBUser.FCMPushToken, global.DBUser.AppleRegistration, global.DBUser.SecondaryReg)
		global.imux.Start(context.TODO())
	}
}

func (imc *IMContext) StopImux(ctx context.Context) {
	if imc.imux != nil {
		imc.Log.Info().Msg("Stopping imux")
		imc.imux.Stop(ctx)
		imc.imux = nil
	}
}

func (imc *IMContext) DeleteImux(ctx context.Context) {
	if imc.imux != nil {
		imc.Log.Info().Msg("Disconnecting and deleting imux")
		imc.imux.Close()
		imc.imux.Deregister(ctx)
		imc.imux = nil
	}
}

func maybeFatalLog(log *zerolog.Logger, err error) *zerolog.Event {
	if errors.Is(err, context.Canceled) {
		return log.Err(err)
	} else if strings.HasSuffix(err.Error(), "sql: database is closed") && global.Stopping.Load() {
		// Hacky hack because database/sql checks if the db is closed before checking if the context is done
		return log.Err(err).Bool("stopping", true)
	} else {
		return log.Fatal().Err(err)
	}
}
