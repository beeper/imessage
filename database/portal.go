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

package database

import (
	"context"
	"database/sql"
	"errors"
	"reflect"
	"time"

	"github.com/rs/zerolog"
	"go.mau.fi/util/dbutil"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"

	"github.com/beeper/imessage/imessage"
	"github.com/beeper/imessage/imessage/direct/util/uri"
)

type Key struct {
	URI      uri.ParsedURI
	Receiver int
}

func (k Key) MarshalZerologObject(e *zerolog.Event) {
	e.Str("uri", k.URI.String()).Int("receiver", k.Receiver)
}

type PortalQuery struct {
	db *Database
}

func (pq *PortalQuery) getDB() *Database {
	return pq.db
}

func (pq *PortalQuery) New() *Portal {
	return &Portal{db: pq.db}
}

const (
	portalFields                       = `uri, receiver, service, group_id, participants, outgoing_handle, mxid, name, name_set, avatar_hash, avatar_guid, avatar_url, avatar_set, encrypted, in_space, properties_version`
	portalSelectClause                 = "SELECT " + portalFields + " FROM portal "
	getAllPortalsWithMXIDQuery         = portalSelectClause + "WHERE mxid<>''"
	getAllPortalsForUserQuery          = portalSelectClause + "WHERE receiver=$1"
	getPortalByMXIDQuery               = portalSelectClause + "WHERE mxid=$1"
	getPortalByURIQuery                = portalSelectClause + "WHERE uri=$1 AND receiver=$2"
	getPortalByParticipantsQuery       = portalSelectClause + "WHERE participants=$1 AND receiver=$2 LIMIT 1"
	findPortalsWithRecentMessagesQuery = `
		SELECT portal.uri, portal.receiver, portal.service, portal.group_id, portal.participants,
		       portal.outgoing_handle, portal.mxid, portal.name, portal.name_set,
		       portal.avatar_hash, portal.avatar_guid, portal.avatar_url, portal.avatar_set,
		       portal.encrypted, portal.in_space, portal.properties_version
		FROM message
		INNER JOIN portal ON message.portal_uri = portal.uri and message.portal_receiver = portal.receiver
		WHERE message.portal_receiver=$1 AND message.timestamp>=$2
		GROUP BY portal.uri, portal.receiver
	`
	insertPortalQuery = "INSERT INTO portal (" + portalFields + ") VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)"
	updatePortalQuery = `
		UPDATE portal
		SET service=$3, group_id=$4, participants=$5, outgoing_handle=$6, mxid=$7,
		    name=$8, name_set=$9, avatar_hash=$10, avatar_guid=$11,
			avatar_url=$12, avatar_set=$13, encrypted=$14, in_space=$15, properties_version=$16
		WHERE uri=$1 AND receiver=$2
	`
	deletePortalQuery = `DELETE FROM portal WHERE uri=$1 AND receiver=$2`
)

func (pq *PortalQuery) GetAllWithMXID(ctx context.Context) ([]*Portal, error) {
	return getAll[*Portal](pq, ctx, getAllPortalsWithMXIDQuery)
}

func (pq *PortalQuery) GetAllForUser(ctx context.Context, receiver int) ([]*Portal, error) {
	return getAll[*Portal](pq, ctx, getAllPortalsForUserQuery, receiver)
}

func (pq *PortalQuery) GetByURI(ctx context.Context, key Key) (*Portal, error) {
	return get[*Portal](pq, ctx, getPortalByURIQuery, key.URI, key.Receiver)
}

func (pq *PortalQuery) GetByParticipants(ctx context.Context, participants []uri.ParsedURI, receiver int) (*Portal, error) {
	return get[*Portal](pq, ctx, getPortalByParticipantsQuery, dbutil.JSON{Data: participants}, receiver)
}

func (pq *PortalQuery) FindWithRecentMessages(ctx context.Context, receiver int, interval time.Duration) ([]*Portal, error) {
	return getAll[*Portal](pq, ctx, findPortalsWithRecentMessagesQuery, receiver, time.Now().Add(-interval).UnixMilli())
}

func (pq *PortalQuery) GetByMXID(ctx context.Context, mxid id.RoomID) (*Portal, error) {
	return get[*Portal](pq, ctx, getPortalByMXIDQuery, mxid)
}

type Portal struct {
	db *Database

	Key
	Service        imessage.Service
	GroupID        string
	Participants   []uri.ParsedURI
	OutgoingHandle uri.ParsedURI

	MXID              id.RoomID
	Name              string
	NameSet           bool
	AvatarHash        *[32]byte
	AvatarGUID        *string
	AvatarURL         id.ContentURIString
	AvatarSet         bool
	Encrypted         bool
	InSpace           bool
	PropertiesVersion int
}

func (portal *Portal) IsPrivateChat() bool {
	return portal.URI.Scheme != uri.SchemeGroup && portal.URI.Scheme != uri.SchemeGroupParticipants
}

func (portal *Portal) Scan(row dbutil.Scannable) (*Portal, error) {
	var mxid, avatarGUID sql.NullString
	var avatarHashSlice []byte
	err := row.Scan(&portal.URI, &portal.Receiver, &portal.Service, &portal.GroupID, dbutil.JSON{Data: &portal.Participants}, &portal.OutgoingHandle, &mxid, &portal.Name, &portal.NameSet, &avatarHashSlice, &avatarGUID, &portal.AvatarURL, &portal.AvatarSet, &portal.Encrypted, &portal.InSpace, &portal.PropertiesVersion)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	portal.MXID = id.RoomID(mxid.String)
	if avatarGUID.Valid {
		portal.AvatarGUID = &avatarGUID.String
	}
	if avatarHashSlice != nil && len(avatarHashSlice) == 32 {
		portal.AvatarHash = (*[32]byte)(avatarHashSlice)
	}
	return portal, nil
}

func (portal *Portal) sqlVariables() []any {
	var mxid *id.RoomID
	var avatarGUID *string
	var avatarHashSlice []byte
	if len(portal.MXID) > 0 {
		mxid = &portal.MXID
	}
	if portal.AvatarGUID != nil {
		avatarGUID = portal.AvatarGUID
	}
	if portal.AvatarHash != nil {
		avatarHashSlice = (*portal.AvatarHash)[:]
	}
	return []any{portal.URI, portal.Receiver, portal.Service, portal.GroupID, dbutil.JSON{Data: portal.Participants}, portal.OutgoingHandle, mxid, portal.Name, portal.NameSet, avatarHashSlice, &avatarGUID, &portal.AvatarURL, portal.AvatarSet, portal.Encrypted, portal.InSpace, portal.PropertiesVersion}
}

func (portal *Portal) Insert(ctx context.Context) error {
	_, err := portal.db.Conn(ctx).ExecContext(ctx, insertPortalQuery, portal.sqlVariables()...)
	return err
}

func (portal *Portal) Update(ctx context.Context) error {
	_, err := portal.db.Conn(ctx).ExecContext(ctx, updatePortalQuery, portal.sqlVariables()...)
	return err
}

func (portal *Portal) Delete(ctx context.Context) error {
	_, err := portal.db.Conn(ctx).ExecContext(ctx, deletePortalQuery, portal.URI, portal.Receiver)
	return err
}

type CustomBridgeInfoSection struct {
	event.BridgeInfoSection

	Participants   []uri.ParsedURI `json:"com.beeper.imessage.participants,omitempty"`
	Service        string          `json:"com.beeper.imessage.service,omitempty"`
	GroupID        string          `json:"com.beeper.imessage.group_id,omitempty"`
	OutgoingHandle uri.ParsedURI   `json:"com.beeper.imessage.outgoing_handle,omitempty"`
}

type CustomBridgeInfoContent struct {
	event.BridgeEventContent
	Channel CustomBridgeInfoSection `json:"channel"`
}

func init() {
	event.TypeMap[event.StateBridge] = reflect.TypeOf(CustomBridgeInfoContent{})
	event.TypeMap[event.StateHalfShotBridge] = reflect.TypeOf(CustomBridgeInfoContent{})
}

func (portal *Portal) GetBridgeInfo() *CustomBridgeInfoContent {
	bridgeInfo := CustomBridgeInfoContent{
		BridgeEventContent: event.BridgeEventContent{
			Protocol: event.BridgeInfoSection{
				ID:          "imessagego",
				DisplayName: "iMessage",
				ExternalURL: "https://support.apple.com/messages",
			},
		},
		Channel: CustomBridgeInfoSection{
			BridgeInfoSection: event.BridgeInfoSection{
				ID:          portal.URI.Identifier,
				DisplayName: portal.Name,
				AvatarURL:   portal.AvatarURL,
			},
			Service:        portal.Service.String(),
			GroupID:        portal.GroupID,
			Participants:   portal.Participants,
			OutgoingHandle: portal.OutgoingHandle,
		},
	}
	if portal.Service == imessage.ServiceSMS {
		bridgeInfo.Protocol.ID = "imessagego-sms"
		bridgeInfo.Protocol.DisplayName = "iMessage (SMS)"
	}
	return &bridgeInfo
}
