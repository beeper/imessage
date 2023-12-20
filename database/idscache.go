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
	"strings"
	"time"

	"go.mau.fi/util/dbutil"

	"github.com/beeper/imessage/imessage/direct/ids"
	"github.com/beeper/imessage/imessage/direct/util/uri"
)

type IDSCacheQuery struct {
	db *Database
}

func (iq *IDSCacheQuery) getDB() *Database {
	return iq.db
}

func (iq *IDSCacheQuery) New() *IDSCacheEntry {
	return &IDSCacheEntry{db: iq.db}
}

const (
	getIDSCacheEntryQuery = `
		SELECT user_id, our_uri, their_uri, timestamp, result, broadcasted
		FROM ids_cache WHERE user_id=$1 AND our_uri=$2 AND their_uri=$3
	`
	// language=postgresql
	getManyIDSCacheEntriesQueryPostgres = `
		SELECT user_id, our_uri, their_uri, timestamp, result, broadcasted
		FROM ids_cache WHERE user_id=$1 AND our_uri=$2 AND their_uri = ANY($3)
	`
	// language=sqlite
	getManyIDSCacheEntriesQuerySQLite = `
		SELECT user_id, our_uri, their_uri, timestamp, result, broadcasted
		FROM ids_cache WHERE user_id=?1 AND our_uri=?2 AND their_uri IN (?3)
	`
	// language=postgresql
	markBroadcastedQueryPostgres = `
		UPDATE ids_cache SET broadcasted=true WHERE user_id=$1 AND our_uri=$2 AND their_uri = ANY($3)
	`
	// language=sqlite
	markBroadcastedQuerySQLite = `
		UPDATE ids_cache SET broadcasted=true WHERE user_id=?1 AND our_uri=?2 AND their_uri IN (?3)
	`
	upsertIDSCacheEntryQuery = `
		INSERT INTO ids_cache (user_id, our_uri, their_uri, timestamp, result, broadcasted)
		VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (user_id, our_uri, their_uri)
		    DO UPDATE SET timestamp=excluded.timestamp, result=excluded.result
	`
	invalidateIDSCacheEntryQuery = `UPDATE ids_cache SET timestamp=MIN(timestamp, $4) WHERE user_id=$1 AND our_uri=$2 AND their_uri=$3`
	deleteIDSCacheEntryQuery     = `DELETE FROM ids_cache WHERE user_id=$1 AND our_uri=$2 AND their_uri=$3`
)

func (iq *IDSCacheQuery) Get(ctx context.Context, userID int, ourURI uri.ParsedURI, theirURI uri.ParsedURI) (*IDSCacheEntry, error) {
	return get[*IDSCacheEntry](iq, ctx, getIDSCacheEntryQuery, userID, ourURI, theirURI)
}

func makeSQLiteArrayParams[T any](dynamic []T, prefix ...any) (params []any, placeholders string) {
	params = make([]any, len(dynamic)+len(prefix))
	placeholderArr := make([]string, len(dynamic))
	copy(params, prefix)
	for i, value := range dynamic {
		params[i+len(prefix)] = value
		placeholderArr[i] = fmt.Sprintf("?%d", i+len(prefix)+1)
	}
	placeholders = strings.Join(placeholderArr, ", ")
	return
}

func (iq *IDSCacheQuery) GetMany(ctx context.Context, userID int, ourURI uri.ParsedURI, theirURIs []uri.ParsedURI) ([]*IDSCacheEntry, error) {
	if iq.db.Dialect == dbutil.Postgres {
		return getAll[*IDSCacheEntry](iq, ctx, getManyIDSCacheEntriesQueryPostgres, userID, ourURI, theirURIs)
	} else {
		params, placeholders := makeSQLiteArrayParams(theirURIs, userID, ourURI)
		query := strings.ReplaceAll(getManyIDSCacheEntriesQuerySQLite, "?3", placeholders)
		return getAll[*IDSCacheEntry](iq, ctx, query, params...)
	}
}

func (iq *IDSCacheQuery) MarkBroadcasted(ctx context.Context, userID int, ourURI uri.ParsedURI, theirURIs []uri.ParsedURI) (err error) {
	if iq.db.Dialect == dbutil.Postgres {
		_, err = iq.db.Conn(ctx).ExecContext(ctx, markBroadcastedQueryPostgres, userID, ourURI, theirURIs)
	} else {
		params, placeholders := makeSQLiteArrayParams(theirURIs, userID, ourURI)
		query := strings.ReplaceAll(markBroadcastedQuerySQLite, "?3", placeholders)
		_, err = iq.db.Conn(ctx).ExecContext(ctx, query, params...)
	}
	return
}

func (iq *IDSCacheQuery) Clear(ctx context.Context, userID int) error {
	_, err := iq.db.Conn(ctx).ExecContext(ctx, `DELETE FROM ids_cache WHERE user_id=$1`, userID)
	return err
}

type IDSCache struct {
	Query  *IDSCacheQuery
	UserID int
}

var _ ids.LookupCache = (*IDSCache)(nil)

func (ic *IDSCache) Get(ctx context.Context, ourURI, theirURI uri.ParsedURI) (*ids.LookupResult, error) {
	entry, err := ic.Query.Get(ctx, ic.UserID, ourURI, theirURI)
	if err != nil || entry == nil {
		return nil, err
	}
	return entry.Result, nil
}

func (ic *IDSCache) GetMany(ctx context.Context, ourURI uri.ParsedURI, theirURIs []uri.ParsedURI) (map[uri.ParsedURI]*ids.LookupResult, error) {
	entries, err := ic.Query.GetMany(ctx, ic.UserID, ourURI, theirURIs)
	if err != nil {
		return nil, err
	}
	results := make(map[uri.ParsedURI]*ids.LookupResult, len(entries))
	for _, entry := range entries {
		if entry == nil {
			continue
		}
		results[entry.TheirURI] = entry.Result
	}
	return results, nil
}

func (ic *IDSCache) MarkBroadcasted(ctx context.Context, handle uri.ParsedURI, broadcasted ...uri.ParsedURI) error {
	return ic.Query.MarkBroadcasted(ctx, ic.UserID, handle, broadcasted)
}

func (ic *IDSCache) Invalidate(ctx context.Context, ourURI, theirURI uri.ParsedURI) error {
	_, err := ic.Query.db.Conn(ctx).ExecContext(
		ctx, invalidateIDSCacheEntryQuery,
		ic.UserID, ourURI, theirURI,
		time.Now().Add(-ids.MinResultRefreshInterval).UnixMilli(),
	)
	return err
}

func (ic *IDSCache) Put(ctx context.Context, ourURI, theirURI uri.ParsedURI, result *ids.LookupResult) error {
	entry := ic.Query.New()
	entry.UserID = ic.UserID
	entry.OurURI = ourURI
	entry.TheirURI = theirURI
	entry.Result = result
	entry.Timestamp = result.Time
	entry.Broadcasted = result.Broadcasted
	if entry.Timestamp.IsZero() {
		entry.Timestamp = time.Now()
	}
	return entry.Upsert(ctx)
}

func (ic *IDSCache) Delete(ctx context.Context, ourURI, theirURI uri.ParsedURI) error {
	_, err := ic.Query.db.Conn(ctx).ExecContext(ctx, deleteIDSCacheEntryQuery, ic.UserID, ourURI, theirURI)
	return err
}

func (ic *IDSCache) Clear(ctx context.Context) error {
	return ic.Query.Clear(ctx, ic.UserID)
}

type IDSCacheEntry struct {
	db *Database

	UserID      int
	OurURI      uri.ParsedURI
	TheirURI    uri.ParsedURI
	Timestamp   time.Time
	Result      *ids.LookupResult
	Broadcasted bool
}

func (ice *IDSCacheEntry) Scan(row dbutil.Scannable) (*IDSCacheEntry, error) {
	var timestamp int64
	err := row.Scan(&ice.UserID, &ice.OurURI, &ice.TheirURI, &timestamp, dbutil.JSON{&ice.Result}, &ice.Broadcasted)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	ice.Timestamp = time.UnixMilli(timestamp)
	ice.Result.Time = ice.Timestamp
	ice.Result.Broadcasted = ice.Broadcasted
	return ice, nil
}

func (ice *IDSCacheEntry) sqlVariables() []any {
	return []any{ice.UserID, ice.OurURI, ice.TheirURI, ice.Timestamp.UnixMilli(), dbutil.JSON{Data: &ice.Result}, ice.Broadcasted}
}

func (ice *IDSCacheEntry) Upsert(ctx context.Context) error {
	_, err := ice.db.Conn(ctx).ExecContext(ctx, upsertIDSCacheEntryQuery, ice.sqlVariables()...)
	return err
}

func (ice *IDSCacheEntry) Delete(ctx context.Context) error {
	_, err := ice.db.Conn(ctx).ExecContext(ctx, deleteIDSCacheEntryQuery, ice.UserID, ice.OurURI, ice.TheirURI)
	return err
}
