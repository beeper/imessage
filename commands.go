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
	"errors"
	"fmt"
	"time"

	"maunium.net/go/mautrix/bridge/commands"

	"github.com/beeper/imessage/imessage/direct/ids"
	"github.com/beeper/imessage/imessage/direct/ids/types"
)

type WrappedCommandEvent struct {
	*commands.Event
	Bridge *IMBridge
	User   *User
	Portal *Portal
}

func wrapCommand(handler func(*WrappedCommandEvent)) func(*commands.Event) {
	return func(ce *commands.Event) {
		var portal *Portal
		if ce.Portal != nil {
			portal = ce.Portal.(*Portal)
		}
		handler(&WrappedCommandEvent{
			Event:  ce,
			Bridge: ce.Bridge.Child.(*IMBridge),
			User:   ce.User.(*User),
			Portal: portal,
		})
	}
}

type twofaState struct {
	Username string
	Password string
}

func fnLogin(ce *WrappedCommandEvent) {
	if len(ce.Args) != 2 {
		ce.ReplyAdvanced("**Usage:** `login <username> <password>`", true, false)
		return
	}

	if ce.User.IsLoggedIn() && !ce.User.NeedsRefresh() && ce.User.IsIDSRegistered() {
		ce.Reply("You are already logged in")
		return
	}

	go ce.Redact()
	err := ce.User.Start()
	if errors.Is(err, ErrNoNAC) {
		ce.Reply("NAC validation fields not configured.")
		return
	} else if err != nil {
		ce.Reply("Failed to prepare for login: %v", err)
		return
	}
	username := ce.Args[0]
	password := ce.Args[1]

	err = ce.User.IM.Login(ce.Ctx, username, password, "")
	if errors.Is(err, types.Err2FARequired) {
		ce.User.commandState = &commands.CommandState{
			Next:   cmdLogin2fa,
			Action: "login",
			Meta: twofaState{
				Username: username,
				Password: password,
			},
		}
		ce.Reply("Successs (so far)! Send your two-factor auth code next")
	} else if err != nil {
		ce.Reply("Login failed: %s", err)
	} else {
		ce.User.tryAutomaticDoublePuppeting()
		ce.Reply("Success!")
		// TODO don't ignore errors
		// also maybe the connector should just send an event when the config needs to be saved, instead of it being hardcoded here
		ce.User.Update(ce.Ctx)
		go ce.User.broadcastHandlesToRecentConversations()
	}
}

var cmdLogin = &commands.FullHandler{
	Func: wrapCommand(fnLogin),
	Name: "login",
	Help: commands.HelpMeta{
		Section:     commands.HelpSectionAuth,
		Description: "Link the bridge to your iMessage account",
		Args:        "<_username_> <_password_>",
	},
}

func fnLogin2fa(ce *WrappedCommandEvent) {
	var username, password, code string
	if ce.User.commandState == nil || ce.User.commandState.Action != "login" {
		ce.Reply("How'd you get here 🤔")
		return
	} else if len(ce.Args) == 0 {
		ce.Reply("Send your 2-factor auth code here")
		return
	}
	state := ce.User.commandState.Meta.(twofaState)
	username = state.Username
	password = state.Password
	code = ce.Args[0]

	if ce.User.IsLoggedIn() {
		ce.Reply("You are already logged in")
		return
	}

	err := ce.User.IM.Login(ce.Ctx, username, password, code)
	if err != nil {
		ce.Reply("Login failed: %s", err)
	} else {
		ce.User.tryAutomaticDoublePuppeting()
		ce.Reply("Success!")
		ce.User.Update(ce.Ctx)
	}
}

var cmdLogin2fa = &commands.FullHandler{
	Func: wrapCommand(fnLogin2fa),
	Name: "login-2fa",
	Help: commands.HelpMeta{
		Section:     commands.HelpSectionAuth,
		Description: "Link the bridge to your iMessage account with a 2fa code",
		Args:        "<_username_> <_password_> [_2fa_]",
	},
}

func fnLogout(ce *WrappedCommandEvent) {
	if ce.User.AppleRegistration == nil {
		ce.Reply("You are not logged in.")
		return
	}

	ce.User.Logout()
	ce.Reply("Success!")
}

var cmdLogout = &commands.FullHandler{
	Func: wrapCommand(fnLogout),
	Name: "logout",
	Help: commands.HelpMeta{
		Section:     commands.HelpSectionAuth,
		Description: "Forget the credentials to your iMessage account",
	},
}

func fnResolveIdentifier(ce *WrappedCommandEvent) {
	if !ce.User.IsLoggedIn() {
		ce.Reply("You are not logged in.")
		return
	}
	force := ce.Args[0] == "--force"
	if force {
		ce.Args = ce.Args[1:]
	}
	found, notFound, err := ce.User.IM.ResolveIdentifiers(ce.Ctx, force, nil, ce.Args...)
	if err != nil {
		ce.Reply("Error resolving identifiers: %v", err)
	} else {
		ce.Reply("On iMessage: %+v\n\nNot on iMessage: %+v", found, notFound)
	}
}

var cmdResolveIdentifier = &commands.FullHandler{
	Func: wrapCommand(fnResolveIdentifier),
	Name: "resolve-identifier",
	Help: commands.HelpMeta{
		Section:     commands.HelpSectionGeneral,
		Description: "Resolve iMessage identifiers",
		Args:        "[--force] [_uri_ ...]",
	},
}

func fnStartChat(ce *WrappedCommandEvent) {
	if !ce.User.IsLoggedIn() {
		ce.Reply("You are not logged in.")
		return
	}

	resp, err := ce.User.startChat(StartChatRequest{
		Identifiers: ce.Args,
	})

	if err != nil {
		ce.Reply("Error starting dm: %s", err)
	} else if resp.JustCreated {
		ce.Reply("Created room %s for uri %s", resp.RoomID, resp.URI)
	} else {
		ce.Reply("Found existing room %s for uri %s", resp.RoomID, resp.URI)
	}
}

var cmdStartChat = &commands.FullHandler{
	Func: wrapCommand(fnStartChat),
	Name: "start-chat",
	Help: commands.HelpMeta{
		Section:     commands.HelpSectionGeneral,
		Description: "Start a chat with the provided URIs",
		Args:        "[_uri_ ...]",
	},
}

func fnReRegisterIDS(ce *WrappedCommandEvent) {
	err := ce.User.IM.RegisterIDS(ce.Ctx, true)
	if err != nil {
		ce.Reply("Failed to reregister: %v", err)
		return
	}
	ce.Reply("Successfully reregistered")
}

var cmdReRegisterIDS = &commands.FullHandler{
	Func: wrapCommand(fnReRegisterIDS),
	Name: "reregister-ids",
	Help: commands.HelpMeta{
		Section:     commands.HelpSectionAuth,
		Description: "Reregister with IDS",
	},
	RequiresLogin: true,
}

func fnDeRegisterIDS(ce *WrappedCommandEvent) {
	if err := ce.User.IM.DeRegisterIDS(ce.Ctx); err != nil {
		ce.Reply("Failed to deregister: %v", err)
		return
	}
	if err := ce.User.Update(ce.Ctx); err != nil {
		ce.Reply("Failed to update user: %v", err)
		return
	}
	ce.Reply("Successfully deregistered")
}

var cmdDeRegisterIDS = &commands.FullHandler{
	Func: wrapCommand(fnDeRegisterIDS),
	Name: "deregister-ids",
	Help: commands.HelpMeta{
		Section:     commands.HelpSectionAuth,
		Description: "Deregister with IDS, but keep the auth certificates so reregistering is possible",
	},
	RequiresLogin: true,
}

func fnRegisterPhoneNumber(ce *WrappedCommandEvent) {
	if len(ce.Args) != 1 {
		ce.Reply("Usage: register-phone-number <mmcmnc>")
		return
	}
	err := ce.User.Start()
	if errors.Is(err, ErrNoNAC) {
		ce.Reply("NAC validation fields not configured.")
		return
	} else if err != nil {
		ce.Reply("Failed to prepare for login: %v", err)
		return
	} else if ce.User.IM.User.Versions.SoftwareName != "iPhone OS" {
		ce.Reply("Phone number registration only works when using an iPhone as the registration data provider")
		return
	}
	mccmnc := ce.Args[0]

	log := ce.ZLog.With().Str("mccmnc", mccmnc).Logger()
	ce.Ctx = log.WithContext(ce.Ctx)

	gateway, err := ids.GetGatewayByMCCMNC(ce.Ctx, mccmnc)
	if err != nil {
		ce.Reply("failed to get gateway: %v", err)
		return
	}

	log.Info().Str("gateway", gateway).Msg("Got gateway")

	smsText := ids.CreateSMSRegisterRequest(ce.User.IM.User.PushToken)

	ce.User.commandState = &commands.CommandState{
		Next:   cmdRegisterPhoneNumberFinish,
		Action: "register-phone-number",
	}
	msg := fmt.Sprintf("Send the following SMS to %s:\n\n```%s```\n\nand then send the SMS response here. (The SMS response is hidden, you need to use something like [JJTech0130/PNRGatewayClientV2](https://github.com/JJTech0130/PNRGatewayClientV2) to send and receive the SMS.)", gateway, smsText)
	ce.ReplyAdvanced(msg, true, false)
}

var cmdRegisterPhoneNumber = &commands.FullHandler{
	Func: wrapCommand(fnRegisterPhoneNumber),
	Name: "register-phone-number",
	Help: commands.HelpMeta{
		Section:     commands.HelpSectionAuth,
		Description: "Register a phone number with iMessage",
		Args:        "[_mmcmnc_]",
	},
	RequiresLogin: true,
}

func fnRegisterPhoneNumberFinish(ce *WrappedCommandEvent) {
	if ce.User.commandState == nil || ce.User.commandState.Action != "register-phone-number" {
		ce.Reply("How'd you get here 🤔")
		return
	} else if len(ce.Args) != 1 {
		ce.Reply("Please enter the phone number registration response (starts with `REG-RESP?`) or use `cancel` to cancel.")
		return
	}
	respText := ce.Args[0]

	phoneNumber, signature, err := ids.ParseSMSRegisterResponse(respText)
	if err != nil {
		ce.Reply("failed to parse register response: %v", err)
		return
	}

	authCert, err := ce.User.IM.User.GetAuthCertSMS(ce.Ctx, ce.User.IM.User.PushToken, signature, phoneNumber)
	if err != nil {
		ce.Reply("failed to get auth cert: %v", err)
		return
	}
	ce.ZLog.Info().Str("phone_number", phoneNumber).Msg("Got auth cert")

	if ce.User.IM.User.AuthIDCertPairs == nil {
		ce.User.IM.User.AuthIDCertPairs = map[string]*ids.AuthIDCertPair{}
	}
	ce.User.IM.User.AuthIDCertPairs["P:"+phoneNumber] = &ids.AuthIDCertPair{
		Added:    time.Now(),
		AuthCert: authCert,
	}

	err = ce.User.IM.RegisterIDS(ce.Ctx, true)
	if err != nil {
		ce.Reply("failed to register IDS: %v", err)
		return
	}

	if err := ce.User.Update(ce.Ctx); err != nil {
		ce.Reply("failed to update user: %v", err)
	}
	ce.Reply("Phone number registered")
}

var cmdRegisterPhoneNumberFinish = &commands.FullHandler{
	Func: wrapCommand(fnRegisterPhoneNumberFinish),
	Name: "register-phone-number-finish",
	Help: commands.HelpMeta{
		Section:     commands.HelpSectionAuth,
		Description: "Finish registering a phone number with iMessage",
		Args:        "[_sms\\_response_]",
	},
	RequiresLogin: true,
}

var cmdToggleReadReceipts = &commands.FullHandler{
	Func: wrapCommand(fnToggleReadReceipts),
	Name: "toggle-read-receipts",
	Help: commands.HelpMeta{
		Section:     commands.HelpSectionGeneral,
		Description: "Toggle whether read receipts are sent to the other party in a chat.",
	},
	RequiresLogin: true,
}

func fnToggleReadReceipts(ce *WrappedCommandEvent) {
	err := ce.User.setHideReadReceipts(!ce.User.HideReadReceipts)
	if err != nil {
		ce.Reply("failed to toggle read receipts: %v", err)
		return
	}
	if ce.User.HideReadReceipts {
		ce.Reply("Disabled read receipts")
	} else {
		ce.Reply("Enabled read receipts")
	}
}

var cmdDeletePortal = &commands.FullHandler{
	Func: wrapCommand(fnDeletePortal),
	Name: "delete-portal",
	Help: commands.HelpMeta{
		Description: "Delete the current portal.",
	},
	RequiresPortal: true,
}

func fnDeletePortal(ce *WrappedCommandEvent) {
	ce.Portal.zlog.Info().Str("mx_id", ce.User.MXID.String()).Msg("requested deletion of portal.")
	ce.Portal.Delete()
	ce.Portal.Cleanup(false)
}

var cmdSyncPortal = &commands.FullHandler{
	Func: wrapCommand(fnSyncPortal),
	Name: "sync-portal",
	Help: commands.HelpMeta{
		Description: "Sync the current portal.",
	},
	RequiresPortal: true,
}

func fnSyncPortal(ce *WrappedCommandEvent) {
	ce.Portal.Sync(false)
}

func (br *IMBridge) RegisterCommands() {
	proc := br.CommandProcessor.(*commands.Processor)
	proc.AddHandlers(
		cmdLogin,
		cmdLogout,
		cmdResolveIdentifier,
		cmdStartChat,
		cmdReRegisterIDS,
		cmdDeRegisterIDS,
		cmdRegisterPhoneNumber,
		cmdToggleReadReceipts,
		cmdDeletePortal,
		cmdSyncPortal,
	)
}
