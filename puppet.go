// beeper-imessage - A Matrix-iMessage puppeting bridge.
// Copyright (C) 2021 Tulir Asokan
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
	"crypto/sha256"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/gabriel-vasile/mimetype"
	"github.com/rs/zerolog"
	log "maunium.net/go/maulogger/v2"
	"maunium.net/go/mautrix/appservice"
	"maunium.net/go/mautrix/bridge"
	"maunium.net/go/mautrix/bridge/bridgeconfig"
	"maunium.net/go/mautrix/id"

	"github.com/beeper/imessage/database"
	"github.com/beeper/imessage/imessage"
	"github.com/beeper/imessage/imessage/direct/util/uri"
)

var userIDRegex *regexp.Regexp

func (br *IMBridge) ParsePuppetMXID(mxid id.UserID) (uri.ParsedURI, int, bool) {
	if userIDRegex == nil {
		userIDRegex = br.Config.MakeUserIDRegex(`(\d+)\.(.+)`)
	}
	match := userIDRegex.FindStringSubmatch(string(mxid))
	if match == nil || len(match) != 3 {
		return uri.ParsedURI{}, 0, false
	}

	receiver, err := strconv.Atoi(match[1])
	if err != nil {
		br.ZLog.Debug().Err(err).
			Str("input_mxid", mxid.String()).
			Str("receiver", match[1]).
			Str("local_id", match[2]).
			Msg("Failed to decode user receiver")
		return uri.ParsedURI{}, 0, false
	}
	localpart, err := id.DecodeUserLocalpart(match[2])
	if err != nil {
		br.ZLog.Debug().Err(err).
			Str("input_mxid", mxid.String()).
			Str("receiver", match[1]).
			Str("local_id", match[2]).
			Msg("Failed to decode user localpart")
		return uri.ParsedURI{}, 0, false
	}
	if strings.ContainsRune(localpart, '@') {
		return uri.ParsedURI{Scheme: uri.SchemeMailto, Identifier: localpart}, receiver, true
	} else {
		return uri.ParsedURI{Scheme: uri.SchemeTel, Identifier: localpart}, receiver, true
	}
}

func (br *IMBridge) GetPuppetByMXID(mxid id.UserID) *Puppet {
	parsedURI, receiver, ok := br.ParsePuppetMXID(mxid)
	if !ok {
		return nil
	}
	return br.GetPuppetByURI(database.Key{URI: parsedURI, Receiver: receiver})
}

func (br *IMBridge) GetPuppetByURI(key database.Key) *Puppet {
	br.puppetsLock.Lock()
	defer br.puppetsLock.Unlock()
	puppet, ok := br.puppetsByKey[key]
	if !ok {
		ctx := context.TODO()
		dbPuppet, err := br.DB.Puppet.Get(ctx, key)
		if err != nil {
			br.ZLog.Err(err).Object("puppet_key", key).Msg("Failed to get puppet from database")
			return nil
		}
		if dbPuppet == nil {
			dbPuppet = br.DB.Puppet.New()
			dbPuppet.Key = key
			err = dbPuppet.Insert(ctx)
			if err != nil {
				br.ZLog.Err(err).Object("puppet_key", key).Msg("Failed to insert puppet")
				return nil
			}
		}
		puppet = br.NewPuppet(dbPuppet)
		br.puppetsByKey[puppet.Key] = puppet
	}
	return puppet
}

func (br *IMBridge) IsGhost(userID id.UserID) bool {
	_, _, isPuppet := br.ParsePuppetMXID(userID)
	return isPuppet
}

func (br *IMBridge) GetIGhost(userID id.UserID) bridge.Ghost {
	puppet := br.GetPuppetByMXID(userID)
	if puppet != nil {
		return puppet
	}
	return nil
}

func (br *IMBridge) dbPuppetsToPuppets(dbPuppets []*database.Puppet) []*Puppet {
	br.puppetsLock.Lock()
	defer br.puppetsLock.Unlock()
	output := make([]*Puppet, len(dbPuppets))
	for index, dbPuppet := range dbPuppets {
		if dbPuppet == nil {
			continue
		}
		puppet, ok := br.puppetsByKey[dbPuppet.Key]
		if !ok {
			puppet = br.NewPuppet(dbPuppet)
			br.puppetsByKey[dbPuppet.Key] = puppet
		}
		output[index] = puppet
	}
	return output
}

func (br *IMBridge) FormatPuppetMXID(receiver int, uri uri.ParsedURI) id.UserID {
	return id.NewUserID(
		br.Config.Bridge.FormatUsername(fmt.Sprintf("%d.%s", receiver, id.EncodeUserLocalpart(uri.Identifier))),
		br.Config.Homeserver.Domain)
}

func (br *IMBridge) NewPuppet(dbPuppet *database.Puppet) *Puppet {
	mxid := br.FormatPuppetMXID(dbPuppet.Receiver, dbPuppet.URI)
	return &Puppet{
		Puppet: dbPuppet,
		bridge: br,
		user:   br.GetUserByRowID(dbPuppet.Receiver),
		log:    br.Log.Sub(fmt.Sprintf("Puppet/%s", dbPuppet.URI.Identifier)),
		zlog: br.ZLog.With().
			Str("puppet_id", dbPuppet.URI.String()).
			Int("puppet_receiver", dbPuppet.Receiver).
			Logger(),

		MXID:   mxid,
		Intent: br.AS.Intent(mxid),
	}
}

type Puppet struct {
	*database.Puppet

	bridge *IMBridge
	user   *User
	log    log.Logger
	zlog   zerolog.Logger

	MXID   id.UserID
	Intent *appservice.IntentAPI
}

var _ bridge.Ghost = (*Puppet)(nil)

var _ bridge.GhostWithProfile = (*Puppet)(nil)

func (puppet *Puppet) GetDisplayname() string {
	return puppet.Displayname
}

func (puppet *Puppet) GetAvatarURL() id.ContentURI {
	return puppet.AvatarURL
}

func (puppet *Puppet) ClearCustomMXID() {}

func (puppet *Puppet) CustomIntent() *appservice.IntentAPI {
	return nil
}

func (puppet *Puppet) SwitchCustomMXID(accessToken string, userID id.UserID) error {
	panic("Puppet.SwitchCustomMXID is not implemented")
}

func (puppet *Puppet) DefaultIntent() *appservice.IntentAPI {
	return puppet.Intent
}

func (puppet *Puppet) GetMXID() id.UserID {
	return puppet.MXID
}

func (puppet *Puppet) UpdateName(contact *imessage.Contact) bool {
	if puppet.Displayname != "" && !contact.HasName() {
		// Don't update displayname if there's no contact list name available
		return false
	}
	return puppet.UpdateNameDirect(contact.Name())
}

func (puppet *Puppet) UpdateNameDirect(name string) bool {
	if len(name) == 0 {
		// TODO format if phone numbers
		name = puppet.URI.Identifier
	}
	newName := puppet.bridge.Config.Bridge.FormatDisplayname(name)
	if puppet.Displayname != newName {
		err := puppet.Intent.SetDisplayName(newName)
		if err == nil {
			puppet.Displayname = newName
			go puppet.updatePortalName()
			return true
		} else {
			puppet.log.Warnln("Failed to set display name:", err)
		}
	}
	return false
}

func (puppet *Puppet) UpdateAvatar(contact *imessage.Contact) bool {
	if contact == nil {
		return false
	}
	return puppet.UpdateAvatarFromBytes(contact.Avatar)
}

func (puppet *Puppet) UpdateAvatarFromBytes(avatar []byte) bool {
	if avatar == nil {
		return false
	}
	avatarHash := sha256.Sum256(avatar)
	if puppet.AvatarHash == nil || *puppet.AvatarHash != avatarHash {
		puppet.AvatarHash = &avatarHash
		mimeTypeData := mimetype.Detect(avatar)
		resp, err := puppet.Intent.UploadBytesWithName(avatar, mimeTypeData.String(), "avatar"+mimeTypeData.Extension())
		if err != nil {
			puppet.AvatarHash = nil
			puppet.log.Warnln("Failed to upload avatar:", err)
			return false
		}
		return puppet.UpdateAvatarFromMXC(resp.ContentURI)
	}
	return false
}

func (puppet *Puppet) UpdateAvatarFromMXC(mxc id.ContentURI) bool {
	puppet.AvatarURL = mxc
	err := puppet.Intent.SetAvatarURL(puppet.AvatarURL)
	if err != nil {
		puppet.AvatarHash = nil
		puppet.log.Warnln("Failed to set avatar:", err)
		return false
	}
	go puppet.updatePortalAvatar()
	return true
}

func applyMeta(portal *Portal, meta func(portal *Portal)) {
	if portal == nil {
		return
	}
	portal.roomCreateLock.Lock()
	defer portal.roomCreateLock.Unlock()
	meta(portal)
}

func (puppet *Puppet) updatePortalMeta(meta func(portal *Portal)) {
	portal := puppet.user.GetPortalByURI(puppet.URI)
	applyMeta(portal, meta)
}

func (puppet *Puppet) updatePortalAvatar() {
	puppet.updatePortalMeta(func(portal *Portal) {
		if len(portal.MXID) > 0 && portal.shouldSetDMRoomMetadata() {
			_, err := portal.MainIntent().SetRoomAvatar(portal.MXID, puppet.AvatarURL)
			if err != nil {
				portal.log.Warnln("Failed to set avatar:", err)
			}
		}
		portal.AvatarURL = puppet.AvatarURL.CUString()
		portal.AvatarHash = puppet.AvatarHash
		portal.Update(context.TODO())
		portal.UpdateBridgeInfo()
	})
}

func (puppet *Puppet) updatePortalName() {
	puppet.updatePortalMeta(func(portal *Portal) {
		if len(portal.MXID) > 0 && portal.shouldSetDMRoomMetadata() {
			_, err := portal.MainIntent().SetRoomName(portal.MXID, puppet.Displayname)
			if err != nil {
				portal.log.Warnln("Failed to set name:", err)
			}
		}
		portal.Name = puppet.Displayname
		portal.Update(context.TODO())
		portal.UpdateBridgeInfo()
	})
}

func (puppet *Puppet) Sync() {
	err := puppet.Intent.EnsureRegistered()
	if err != nil {
		puppet.log.Errorln("Failed to ensure registered:", err)
	}
	update := false
	update = puppet.UpdateName(nil) || update
	update = puppet.UpdateAvatar(nil) || update
	update = puppet.UpdateContactInfo() || update
	if update {
		// TODO don't ignore errors
		puppet.Update(context.TODO())
	}
}

func (puppet *Puppet) UpdateContactInfo() bool {
	if puppet.bridge.Config.Homeserver.Software != bridgeconfig.SoftwareHungry {
		return false
	}
	if !puppet.ContactInfoSet {
		contactInfo := map[string]any{
			"com.beeper.bridge.remote_id":   puppet.URI.String(),
			"com.beeper.bridge.identifiers": []string{puppet.URI.String()},
			"com.beeper.bridge.service":     "imessagego",
			"com.beeper.bridge.network":     "imessage",
		}
		err := puppet.DefaultIntent().BeeperUpdateProfile(contactInfo)
		if err != nil {
			puppet.log.Warnln("Failed to store custom contact info in profile:", err)
			return false
		} else {
			puppet.ContactInfoSet = true
			return true
		}
	}
	return false
}
