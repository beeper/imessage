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

package database

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"go.mau.fi/util/dbutil"

	"github.com/beeper/imessage/imessage/direct/util/uri"
)

type RerouteHistoryQuery struct {
	db *Database
}

func (rhq *RerouteHistoryQuery) getDB() *Database {
	return rhq.db
}

func (rhq *RerouteHistoryQuery) New() *RerouteHistoryEntry {
	return &RerouteHistoryEntry{db: rhq.db}
}

const (
	getRerouteHistory = `
		SELECT user_id, handle, timestamp
		FROM reroute_history WHERE user_id=$1 AND handle=$2
	`
	putRerouteHistory = `
		INSERT INTO reroute_history (user_id, handle, timestamp) VALUES ($1, $2, $3)
		ON CONFLICT (user_id, handle) DO UPDATE
		    SET timestamp=excluded.timestamp
	`
	deleteRerouteHistory = `DELETE FROM reroute_history WHERE user_id=$1 AND handle=$2`
)

func (rhq *RerouteHistoryQuery) Get(ctx context.Context, userID int, handle uri.ParsedURI) (*RerouteHistoryEntry, error) {
	return get[*RerouteHistoryEntry](rhq, ctx, getRerouteHistory, userID, handle)
}

func (rhq *RerouteHistoryQuery) Delete(ctx context.Context, userID int, handle uri.ParsedURI) {
	_, err := rhq.db.Conn(ctx).ExecContext(ctx, deleteRerouteHistory, userID, handle)
	if err != nil {
		panic(fmt.Errorf("failed to delete %s: %w", handle, err))
	}
}

func (rhq *RerouteHistoryQuery) Clear(ctx context.Context, userID int) error {
	_, err := rhq.db.Conn(ctx).ExecContext(ctx, `DELETE FROM reroute_history WHERE user_id=$1`, userID)
	return err
}

type RerouteHistory struct {
	Query  *RerouteHistoryQuery
	UserID int
}

func (rh *RerouteHistory) Get(ctx context.Context, handle uri.ParsedURI) (*time.Time, error) {
	entry, err := rh.Query.Get(ctx, rh.UserID, handle)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}
	return &entry.Timestamp, nil
}

func (rh *RerouteHistory) Put(ctx context.Context, handle uri.ParsedURI) error {
	entry := rh.Query.New()
	entry.UserID = rh.UserID
	entry.Handle = handle
	entry.Timestamp = time.Now()
	return entry.Upsert(ctx)
}

func (rh *RerouteHistory) Delete(ctx context.Context, handle uri.ParsedURI) error {
	_, err := rh.Query.db.Conn(ctx).ExecContext(ctx, deleteRerouteHistory, rh.UserID, handle)
	return err
}

func (rh *RerouteHistory) Clear(ctx context.Context) error {
	return rh.Query.Clear(ctx, rh.UserID)
}

type RerouteHistoryEntry struct {
	db *Database

	UserID    int
	Handle    uri.ParsedURI
	Timestamp time.Time
}

func (ft *RerouteHistoryEntry) sqlVariables() []any {
	return []any{ft.UserID, ft.Handle, ft.Timestamp.UnixMilli()}
}

func (ft *RerouteHistoryEntry) Scan(row dbutil.Scannable) (*RerouteHistoryEntry, error) {
	var timestamp int64
	err := row.Scan(&ft.UserID, &ft.Handle, &timestamp)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	ft.Timestamp = time.UnixMilli(timestamp)
	return ft, err
}

func (ft *RerouteHistoryEntry) Upsert(ctx context.Context) error {
	_, err := ft.db.Conn(ctx).ExecContext(ctx, putRerouteHistory, ft.sqlVariables()...)
	return err
}
