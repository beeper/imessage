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

	"go.mau.fi/util/dbutil"
	"maunium.net/go/mautrix/id"

	"github.com/beeper/imessage/imessage/direct/ids"
)

type UserQuery struct {
	db *Database
}

func (uq *UserQuery) getDB() *Database {
	return uq.db
}

func (uq *UserQuery) New() *User {
	return &User{
		db: uq.db,
	}
}

const (
	getUsersWithAppleRegistration = `SELECT rowid, mxid, access_token, space_room, management_room, hide_read_receipts, apple_registration, secondary_apple_registration, fcm_push_token, registered_phone_numbers FROM "user" WHERE apple_registration IS NOT NULL`
	getUsersWithDoublePuppet      = `SELECT rowid, mxid, access_token, space_room, management_room, hide_read_receipts, apple_registration, secondary_apple_registration, fcm_push_token, registered_phone_numbers FROM "user" WHERE access_token<>''`
	getUserByMXIDQuery            = `SELECT rowid, mxid, access_token, space_room, management_room, hide_read_receipts, apple_registration, secondary_apple_registration, fcm_push_token, registered_phone_numbers FROM "user" WHERE mxid=$1`
	getUserByRowIDQuery           = `SELECT rowid, mxid, access_token, space_room, management_room, hide_read_receipts, apple_registration, secondary_apple_registration, fcm_push_token, registered_phone_numbers FROM "user" WHERE rowid=$1`
	insertUserQuery               = `
		INSERT INTO "user" (mxid, access_token, space_room, management_room, hide_read_receipts, apple_registration, secondary_apple_registration, fcm_push_token, registered_phone_numbers)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING rowid
	`
	updateUserQuery = `
		UPDATE "user" SET access_token=$2, space_room=$3, management_room=$4, hide_read_receipts=$5, apple_registration=$6, secondary_apple_registration=$7, fcm_push_token=$8, registered_phone_numbers=$9
		WHERE mxid=$1
	`
)

func (uq *UserQuery) GetAllWithAppleRegistration(ctx context.Context) ([]*User, error) {
	return getAll[*User](uq, ctx, getUsersWithAppleRegistration)
}

func (uq *UserQuery) GetAllWithDoublePuppet(ctx context.Context) ([]*User, error) {
	return getAll[*User](uq, ctx, getUsersWithDoublePuppet)
}

func (uq *UserQuery) GetByMXID(ctx context.Context, userID id.UserID) (*User, error) {
	return get[*User](uq, ctx, getUserByMXIDQuery, userID)
}

func (uq *UserQuery) GetByRowID(ctx context.Context, rowID int) (*User, error) {
	return get[*User](uq, ctx, getUserByRowIDQuery, rowID)
}

type User struct {
	db *Database

	RowID int
	MXID  id.UserID

	AccessToken string

	SpaceRoom      id.RoomID
	ManagementRoom id.RoomID

	HideReadReceipts bool

	FCMPushToken string

	AppleRegistration *ids.Config
	SecondaryReg      *ids.Config

	RegisteredPhoneNumbers []string
}

func (user *User) Scan(row dbutil.Scannable) (*User, error) {
	err := row.Scan(&user.RowID, &user.MXID, &user.AccessToken, &user.SpaceRoom, &user.ManagementRoom, &user.HideReadReceipts, dbutil.JSON{&user.AppleRegistration}, dbutil.JSON{&user.SecondaryReg}, &user.FCMPushToken, dbutil.JSON{&user.RegisteredPhoneNumbers})
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	return user, nil
}

func (user *User) sqlVariables() []any {
	var reg, secondaryReg any
	if user.AppleRegistration != nil {
		reg = user.AppleRegistration
	}
	if user.SecondaryReg != nil {
		secondaryReg = user.SecondaryReg
	}
	return []any{user.MXID, user.AccessToken, user.SpaceRoom, user.ManagementRoom, user.HideReadReceipts, dbutil.JSON{reg}, &dbutil.JSON{secondaryReg}, user.FCMPushToken, &dbutil.JSON{user.RegisteredPhoneNumbers}}
}

func (user *User) Insert(ctx context.Context) error {
	err := user.db.Conn(ctx).
		QueryRowContext(ctx, insertUserQuery, user.sqlVariables()...).
		Scan(&user.RowID)
	return err
}

func (user *User) Update(ctx context.Context) error {
	_, err := user.db.Conn(ctx).ExecContext(ctx, updateUserQuery, user.sqlVariables()...)
	return err
}
