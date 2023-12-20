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

	"github.com/beeper/imessage/imessage/direct/ids"
	"github.com/beeper/imessage/imessage/direct/util/uri"
)

type OutgoingCounterQuery struct {
	db *Database
}

const (
	outgoingCounterIncrementAndReturn = `
		INSERT INTO outgoing_counter
		VALUES (?, ?, 1)
		ON CONFLICT (user_id, their_uri) DO UPDATE
			SET counter = outgoing_counter.counter + 1
		RETURNING counter
	`
)

func (q *OutgoingCounterQuery) IncrementAndGetNext(ctx context.Context, userID int, theirURI uri.ParsedURI) (uint32, error) {
	var counter uint32
	err := q.db.Conn(ctx).QueryRowContext(ctx, outgoingCounterIncrementAndReturn, userID, theirURI).Scan(&counter)
	return counter, err
}

type OutgoingCounter struct {
	query    *OutgoingCounterQuery
	userID   int
	theirURI uri.ParsedURI
}

func (c *OutgoingCounter) GetNext(ctx context.Context) (uint32, error) {
	return c.query.IncrementAndGetNext(ctx, c.userID, c.theirURI)
}

type OutgoingCounterStore struct {
	query  *OutgoingCounterQuery
	userID int

	cache map[uri.ParsedURI]ids.OutgoingCounter
}

func NewOutgoingCounterStore(query *OutgoingCounterQuery, userID int) *OutgoingCounterStore {
	return &OutgoingCounterStore{
		query:  query,
		userID: userID,
		cache:  make(map[uri.ParsedURI]ids.OutgoingCounter),
	}
}

func (s *OutgoingCounterStore) Get(ctx context.Context, theirURI uri.ParsedURI) (ids.OutgoingCounter, error) {
	if _, ok := s.cache[theirURI]; !ok {
		s.cache[theirURI] = &OutgoingCounter{
			query:    s.query,
			userID:   s.userID,
			theirURI: theirURI,
		}
	}
	return s.cache[theirURI], nil
}
