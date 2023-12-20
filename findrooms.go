// mautrix-imessage - A Matrix-iMessage puppeting bridge.
// Copyright (C) 2021 Tulir Asokan
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
	"strings"
	"time"

	"github.com/google/uuid"
	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"

	"github.com/beeper/imessage/database"
	"github.com/beeper/imessage/imessage"
	"github.com/beeper/imessage/imessage/direct/util/uri"
)

// FindPortalsFromMatrix finds portal rooms that the bridge bot is in and puts them in the local database.
func (user *User) FindPortalsFromMatrix() error {
	user.log.Infoln("Finding portal rooms from Matrix...")
	resp, err := user.bridge.Bot.JoinedRooms()
	if err != nil {
		return fmt.Errorf("failed to get joined rooms: %w", err)
	}
	var foundPortals, existingPortals, tombedPortals, failedPortals int
	for _, roomID := range resp.JoinedRooms {
		var roomState mautrix.RoomStateMap
		// Bypass IntentAPI here, we don't want it to try to join any rooms.
		roomState, err = user.bridge.Bot.Client.State(roomID)
		if errors.Is(err, mautrix.MNotFound) || errors.Is(err, mautrix.MForbidden) {
			// Expected error, just debug log and skip
			user.log.Debugfln("Skipping %s: failed to get room state (%v)", roomID, err)
			failedPortals++
		} else if err != nil {
			// Unexpected error, log warning
			user.log.Warnfln("Skipping %s: unexpected error getting room state (%v)", roomID, err)
			failedPortals++
		} else {
			status := user.findPortal(roomID, roomState)
			switch status {
			case FindPortalStatusFound:
				foundPortals++
			case FindPortalStatusExisting:
				existingPortals++
			case FindPortalStatusTombstoned:
				tombedPortals++
			case FindPortalStatusFailed:
				failedPortals++
			}
		}
	}
	user.log.Infofln("Portal finding completed, found %d new portals, %d existing portals, %d failed", foundPortals, existingPortals, failedPortals)
	return nil
}

func (user *User) keyFromBridgeInfo(bridgeInfo *database.CustomBridgeInfoContent) *database.Key {
	if bridgeInfo == nil {
		user.log.Debugln("Skipping: bridge info is nil")
		return nil
	}
	parsedURI, err := uri.ParseIdentifier(bridgeInfo.Channel.ID, uri.ParseAnyChat)
	if err != nil {
		user.log.Infofln("Failed to parse URI %s: %s", bridgeInfo.Channel.ID, err)
		return nil
	}
	return &database.Key{
		URI:      parsedURI,
		Receiver: user.RowID,
	}
}

// FindPortalStatus enum
type FindPortalStatus int

const (
	// The portal was found and added to the database.
	FindPortalStatusFound FindPortalStatus = iota
	// The portal was already in the database.
	FindPortalStatusExisting
	// The portal has been tombstoned
	FindPortalStatusTombstoned
	// The portal was not found or failed to be added to the database.
	FindPortalStatusFailed
)

func (user *User) findPortal(roomID id.RoomID, state mautrix.RoomStateMap) FindPortalStatus {
	if existingPortal := user.bridge.GetPortalByMXID(roomID); existingPortal != nil {
		user.log.Debugfln("Skipping %s: room is already a registered portal", roomID)
		return FindPortalStatusExisting
	} else if _, ok := state[event.StateTombstone]; ok {
		user.log.Debugfln("Skipping %s: room has been tombstoned", roomID)
		return FindPortalStatusTombstoned
	} else if bridgeInfo, err := user.findBridgeInfo(state); err != nil {
		user.log.Debugfln("Skipping %s: %s", roomID, err)
		return FindPortalStatusFailed
	} else if err = user.checkMembers(state); err != nil {
		user.log.Debugfln("Skipping %s (to %s): %s", roomID, bridgeInfo.Channel.ID, err)
		return FindPortalStatusFailed
	} else if key := user.keyFromBridgeInfo(bridgeInfo); key == nil {
		user.log.Debugfln("Skipping %s (to %s): unable to parse identifier", roomID, bridgeInfo.Channel.ID)
		return FindPortalStatusFailed
	} else if portal := user.bridge.GetPortalByID(*key); len(portal.MXID) > 0 {
		user.log.Debugfln("Skipping %s (to %s): portal to chat already exists (%s)", roomID, portal.Key.URI, portal.MXID)
		return FindPortalStatusFailed
	} else {
		encryptionEvent, ok := state[event.StateEncryption][""]
		isEncrypted := ok && encryptionEvent.Content.AsEncryption().Algorithm == id.AlgorithmMegolmV1
		if !isEncrypted && user.bridge.Config.Bridge.Encryption.Default {
			user.log.Debugfln("Skipping %s (to %s): room is not encrypted, but encryption is enabled by default", roomID, portal.Key.URI)
			return FindPortalStatusFailed
		}

		// Note: this probably won't work, as this method
		// is currently called before IM.User is set
		if user.IM == nil || user.IM.User == nil {
			user.log.Warnfln("user.IM.User is nil")
		} else {
			// TODO: record handle in bridge info
			portal.OutgoingHandle = user.IM.User.DefaultHandle
		}
		portal.URI = key.URI
		portal.Receiver = user.RowID
		portal.Key = *key
		portal.Service = imessage.Service(bridgeInfo.Channel.Service)
		portal.Participants = uri.Sort(bridgeInfo.Channel.Participants)
		portal.MXID = roomID
		portal.Name = bridgeInfo.Channel.DisplayName
		portal.AvatarURL = bridgeInfo.Channel.AvatarURL
		portal.GroupID = strings.ToUpper(bridgeInfo.Channel.GroupID)
		portal.Encrypted = isEncrypted
		portal.Update(context.TODO())
		user.log.Infofln("Found portal %s to %s", roomID, portal.Key.URI)
		portal.findLastMessageTimestamp()
		return FindPortalStatusFound
	}
}

func (portal *Portal) findLastMessageTimestamp() {
	log := portal.zlog.With().Str("action", "find last message timestamp").Logger()
	log.Debug().Msg("Looking for last message timestamp in portal")
	evts, err := portal.MainIntent().Messages(portal.MXID, "", "", mautrix.DirectionBackward, &mautrix.FilterPart{
		Types: []event.Type{event.EventMessage, event.EventEncrypted, event.EventReaction},
	}, 50)
	if err != nil {
		log.Err(err).Msg("Failed to get messages in room")
		return
	}
	for _, evt := range evts.Chunk {
		if evt.Type != event.EventMessage && evt.Type != event.EventEncrypted && evt.Type != event.EventReaction {
			continue
		}
		log.Debug().
			Str("event_id", evt.ID.String()).
			Time("event_ts", time.UnixMilli(evt.Timestamp)).
			Msg("Found last message in room")
		dbMessage := portal.bridge.DB.Message.New()
		dbMessage.Portal = portal.Key
		dbMessage.ID = uuid.New()
		// Don't use original event ID because we don't have the real UUID either, just make something unique
		dbMessage.MXID = id.EventID("$fake-latestmsg-" + strings.TrimPrefix(evt.ID.String(), "$"))
		dbMessage.RoomID = portal.MXID
		dbMessage.Timestamp = evt.Timestamp
		err = dbMessage.Insert(context.TODO())
		if err != nil {
			log.Err(err).Msg("Failed to insert fake message into database")
		}
		return
	}
	log.Debug().Msg("Didn't find last message in room")
}

func (user *User) checkMembers(state mautrix.RoomStateMap) error {
	members, ok := state[event.StateMember]
	if !ok {
		return errors.New("didn't find member list")
	}
	bridgeBotMember, ok := members[user.bridge.Bot.UserID.String()]
	if !ok || bridgeBotMember.Content.AsMember().Membership != event.MembershipJoin {
		return fmt.Errorf("bridge bot %s is not joined", user.bridge.Bot.UserID)
	}
	userMember, ok := members[user.MXID.String()]
	if !ok || userMember.Content.AsMember().Membership != event.MembershipJoin {
		return fmt.Errorf("user %s is not joined", user.MXID)
	}
	return nil
}

func (user *User) findBridgeInfo(state mautrix.RoomStateMap) (*database.CustomBridgeInfoContent, error) {
	evts, ok := state[event.StateBridge]
	if !ok {
		return nil, errors.New("no bridge info events found")
	}
	var highestTs int64
	var foundEvt *event.Event
	for _, evt := range evts {
		// Check that the state key is somewhat expected
		if strings.HasPrefix(*evt.StateKey, bridgeInfoProto+"://") &&
			// Must be sent by the bridge bot or a ghost user
			user.isBridgeOwnedMXID(evt.Sender) &&
			// Theoretically we might want to change the state key, so get the one with the highest timestamp
			evt.Timestamp > highestTs {

			foundEvt = evt
			highestTs = evt.Timestamp
		}
	}
	if foundEvt == nil {
		return nil, errors.New("no valid bridge info event found")
	}
	content, ok := foundEvt.Content.Parsed.(*database.CustomBridgeInfoContent)
	if !ok {
		user.log.Debugfln("Content of %s: %s", foundEvt.ID, foundEvt.Content.VeryRaw)
		return nil, fmt.Errorf("bridge info event %s has unexpected content (%T)", foundEvt.ID, foundEvt.Content.Parsed)
	} else if content.BridgeBot != user.bridge.Bot.UserID {
		return nil, fmt.Errorf("bridge info event %s has unexpected bridge bot (%s)", foundEvt.ID, content.BridgeBot)
	} else if len(content.Channel.ID) == 0 {
		return nil, fmt.Errorf("bridge info event %s is missing the iMessage chat ID", foundEvt.ID)
	}
	return content, nil
}

func (user *User) isBridgeOwnedMXID(userID id.UserID) bool {
	if userID == user.bridge.Bot.UserID {
		return true
	}
	return user.bridge.IsGhost(userID)
}
