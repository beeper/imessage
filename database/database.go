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

	_ "github.com/mattn/go-sqlite3"
	"go.mau.fi/util/dbutil"

	"github.com/beeper/imessage/database/upgrades"
)

type Database struct {
	*dbutil.Database

	User            *UserQuery
	Portal          *PortalQuery
	Puppet          *PuppetQuery
	Message         *MessageQuery
	Tapback         *TapbackQuery
	IDSCache        *IDSCacheQuery
	OutgoingCounter *OutgoingCounterQuery
	FileTransfer    *FileTransferQuery
	KV              *KeyValueQuery
	RerouteHistory  *RerouteHistoryQuery
}

func New(parent *dbutil.Database) *Database {
	db := &Database{
		Database: parent,
	}
	db.UpgradeTable = upgrades.Table

	db.User = &UserQuery{db: db}
	db.Portal = &PortalQuery{db: db}
	db.Puppet = &PuppetQuery{db: db}
	db.Message = &MessageQuery{db: db}
	db.Tapback = &TapbackQuery{db: db}
	db.IDSCache = &IDSCacheQuery{db: db}
	db.OutgoingCounter = &OutgoingCounterQuery{db: db}
	db.FileTransfer = &FileTransferQuery{db: db}
	db.KV = &KeyValueQuery{db: db}
	db.RerouteHistory = &RerouteHistoryQuery{db: db}
	return db
}

type dataStruct[T any] interface {
	Scan(row dbutil.Scannable) (T, error)
}

type queryStruct[T dataStruct[T]] interface {
	New() T
	getDB() *Database
}

func get[T dataStruct[T]](qs queryStruct[T], ctx context.Context, query string, args ...any) (T, error) {
	return qs.New().Scan(qs.getDB().Conn(ctx).QueryRowContext(ctx, query, args...))
}

func getAll[T dataStruct[T]](qs queryStruct[T], ctx context.Context, query string, args ...any) ([]T, error) {
	rows, err := qs.getDB().Conn(ctx).QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	items := make([]T, 0)
	defer func() {
		_ = rows.Close()
	}()
	for rows.Next() {
		item, err := qs.New().Scan(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}
