// beeper-imessage - A Matrix-iMessage puppeting bridge.
// Copyright (C) 2022 Tulir Asokan
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
	"database/sql"
	"errors"
	"fmt"

	log "maunium.net/go/maulogger/v2"
)

type KeyValueQuery struct {
	db  *Database
	log log.Logger
}

const (
	KVLookedForPortals = "looked_for_portals"

	KVNACServToken = "nacserv_override_token"
	KVNACServURL   = "nacserv_override_url"

	KVHackyNACErrorPersistence = "hacky_nac_error_persistence"
)

func (kvq *KeyValueQuery) Get(key string) (value string) {
	err := kvq.db.QueryRow("SELECT value FROM kv_store WHERE key=$1", key).Scan(&value)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		panic(fmt.Errorf("failed to scan value for %s: %w", key, err))
	}
	return
}

func (kvq *KeyValueQuery) Set(key, value string) {
	_, err := kvq.db.Exec(`
		INSERT INTO kv_store (key, value) VALUES ($1, $2)
		ON CONFLICT (key) DO UPDATE SET value=excluded.value
	`, key, value)
	if err != nil {
		panic(fmt.Errorf("failed to insert %s: %w", key, err))
	}
}

func (kvq *KeyValueQuery) Delete(key string) {
	_, err := kvq.db.Exec("DELETE FROM kv_store WHERE key=$1", key)
	if err != nil {
		panic(fmt.Errorf("failed to delete %s: %w", key, err))
	}
}
