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

	"github.com/google/uuid"
	log "maunium.net/go/maulogger/v2"

	"go.mau.fi/util/dbutil"
	"maunium.net/go/mautrix/id"

	"github.com/beeper/imessage/imessage"
	"github.com/beeper/imessage/imessage/direct/util/uri"
)

type TapbackQuery struct {
	db *Database
}

func (mq *TapbackQuery) getDB() *Database {
	return mq.db
}

func (mq *TapbackQuery) New() *Tapback {
	return &Tapback{db: mq.db}
}

const (
	getTapbackByMessageIDQuery = `
		SELECT portal_uri, portal_receiver, message_id, message_part, sender_uri, type, id, mxid, receiving_handle
		FROM tapback WHERE portal_uri=$1 AND portal_receiver=$2 AND message_id=$3 AND message_part=$4 AND sender_uri=$5
	`
	getTapbackByIDQuery = `
		SELECT portal_uri, portal_receiver, message_id, message_part, sender_uri, type, id, mxid, receiving_handle
		FROM tapback WHERE portal_uri=$1 AND portal_receiver=$2 AND id=$3
	`
	getByTapbackIDWithoutChatQuery = `
		SELECT portal_uri, portal_receiver, message_id, message_part, sender_uri, type, id, mxid, receiving_handle
		FROM tapback WHERE portal_receiver=$1 AND id=$2
	`
	getTapbackByMXIDQuery = `
		SELECT portal_uri, portal_receiver, message_id, message_part, sender_uri, type, id, mxid, receiving_handle
		FROM tapback WHERE mxid=$1
	`
	insertTapbackQuery = `INSERT INTO tapback (portal_uri, portal_receiver, message_id, message_part, sender_uri, type, id, mxid, receiving_handle) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`
	updateTapbackQuery = `UPDATE tapback SET type=$6, id=$7, mxid=$8, receiving_handle=$9 WHERE portal_uri=$1 AND portal_receiver=$2 AND message_id=$3 AND message_part=$4 AND sender_uri=$5`
	deleteTapbackQuery = `DELETE FROM tapback WHERE portal_uri=$1 AND portal_receiver=$2 AND message_id=$3 AND message_part=$4 AND sender_uri=$5`
)

func (mq *TapbackQuery) GetByID(ctx context.Context, chat Key, messageID uuid.UUID, part int, tapbackSender uri.ParsedURI) (*Tapback, error) {
	return get[*Tapback](mq, ctx, getTapbackByMessageIDQuery, chat.URI, chat.Receiver, messageID, part, tapbackSender)
}

func (mq *TapbackQuery) GetByTapbackID(ctx context.Context, chat Key, tapbackID uuid.UUID) (*Tapback, error) {
	return get[*Tapback](mq, ctx, getTapbackByIDQuery, chat.URI, chat.Receiver, tapbackID)
}

func (tq *TapbackQuery) GetByTapbackIDWithoutChat(ctx context.Context, receiver int, id uuid.UUID) (*Tapback, error) {
	return get[*Tapback](tq, ctx, getByTapbackIDWithoutChatQuery, receiver, id)
}

func (mq *TapbackQuery) GetByMXID(ctx context.Context, mxid id.EventID) (*Tapback, error) {
	return get[*Tapback](mq, ctx, getTapbackByMXIDQuery, mxid)
}

type Tapback struct {
	db  *Database
	log log.Logger

	Portal          Key
	MessageID       uuid.UUID
	MessagePart     int
	Sender          uri.ParsedURI
	Type            imessage.TapbackType
	ID              uuid.UUID
	MXID            id.EventID
	ReceivingHandle uri.ParsedURI
}

func (tapback *Tapback) Scan(row dbutil.Scannable) (*Tapback, error) {
	err := row.Scan(&tapback.Portal.URI, &tapback.Portal.Receiver, &tapback.MessageID, &tapback.MessagePart, &tapback.Sender, &tapback.Type, &tapback.ID, &tapback.MXID, &tapback.ReceivingHandle)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	return tapback, nil
}

func (tapback *Tapback) sqlVariables() []any {
	return []any{tapback.Portal.URI, tapback.Portal.Receiver, tapback.MessageID, tapback.MessagePart, tapback.Sender, tapback.Type, tapback.ID, tapback.MXID, tapback.ReceivingHandle}
}

func (tapback *Tapback) Insert(ctx context.Context) error {
	_, err := tapback.db.Conn(ctx).ExecContext(ctx, insertTapbackQuery, tapback.sqlVariables()...)
	return err
}

func (tapback *Tapback) Update(ctx context.Context) error {
	_, err := tapback.db.Conn(ctx).ExecContext(ctx, updateTapbackQuery, tapback.sqlVariables()...)
	return err
}

func (tapback *Tapback) Delete(ctx context.Context) error {
	_, err := tapback.db.Conn(ctx).ExecContext(ctx, deleteTapbackQuery, tapback.Portal.URI, tapback.Portal.Receiver, tapback.MessageID, tapback.MessagePart, tapback.Sender)
	return err
}
