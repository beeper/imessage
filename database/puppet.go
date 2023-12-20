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

package database

import (
	"context"
	"database/sql"
	"errors"

	"go.mau.fi/util/dbutil"
	"maunium.net/go/mautrix/id"
)

type PuppetQuery struct {
	db *Database
}

func (pq *PuppetQuery) getDB() *Database {
	return pq.db
}

func (pq *PuppetQuery) New() *Puppet {
	return &Puppet{db: pq.db}
}

const (
	getPuppetByURIQuery = `SELECT uri, receiver, displayname, avatar_hash, avatar_url, contact_info_set FROM puppet WHERE uri=$1 AND receiver=$2`
	insertPuppetQuery   = `INSERT INTO puppet (uri, receiver, displayname, avatar_hash, avatar_url, contact_info_set) VALUES ($1, $2, $3, $4, $5, $6)`
	updatePuppetQuery   = `UPDATE puppet SET displayname=$3, avatar_hash=$4, avatar_url=$5, contact_info_set=$6 WHERE uri=$1 AND receiver=$2`
)

func (pq *PuppetQuery) Get(ctx context.Context, key Key) (*Puppet, error) {
	return get[*Puppet](pq, ctx, getPuppetByURIQuery, key.URI, key.Receiver)
}

type Puppet struct {
	db *Database

	Key
	Displayname    string
	AvatarHash     *[32]byte
	AvatarURL      id.ContentURI
	ContactInfoSet bool
}

func (puppet *Puppet) avatarHashSlice() []byte {
	if puppet.AvatarHash == nil {
		return nil
	}
	return (*puppet.AvatarHash)[:]
}

func (puppet *Puppet) Scan(row dbutil.Scannable) (*Puppet, error) {
	var avatarHashSlice []byte
	err := row.Scan(&puppet.URI, &puppet.Receiver, &puppet.Displayname, &avatarHashSlice, &puppet.AvatarURL, &puppet.ContactInfoSet)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	if avatarHashSlice != nil && len(avatarHashSlice) == 32 {
		puppet.AvatarHash = (*[32]byte)(avatarHashSlice)
	}
	return puppet, nil
}

func (puppet *Puppet) sqlVariables() []any {
	var avatarHashSlice []byte
	if puppet.AvatarHash != nil {
		avatarHashSlice = (*puppet.AvatarHash)[:]
	}
	return []any{&puppet.URI, puppet.Receiver, puppet.Displayname, avatarHashSlice, &puppet.AvatarURL, puppet.ContactInfoSet}
}

func (puppet *Puppet) Insert(ctx context.Context) error {
	_, err := puppet.db.Conn(ctx).ExecContext(ctx, insertPuppetQuery, puppet.sqlVariables()...)
	return err
}

func (puppet *Puppet) Update(ctx context.Context) error {
	_, err := puppet.db.Conn(ctx).ExecContext(ctx, updatePuppetQuery, puppet.sqlVariables()...)
	return err
}
