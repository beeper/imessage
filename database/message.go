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
	"time"

	"github.com/google/uuid"
	log "maunium.net/go/maulogger/v2"

	"go.mau.fi/util/dbutil"
	"maunium.net/go/mautrix/id"

	"github.com/beeper/imessage/imessage"
	"github.com/beeper/imessage/imessage/direct/util/uri"
)

type MessageQuery struct {
	db  *Database
	log log.Logger
}

func (mq *MessageQuery) getDB() *Database {
	return mq.db
}

func (mq *MessageQuery) New() *Message {
	return &Message{
		db:  mq.db,
		log: mq.log,
	}
}

const (
	getPortalURIByMessageIDQuery = `
		SELECT portal_uri FROM message WHERE id=$1 AND portal_receiver=$2
		UNION ALL
		SELECT portal_uri FROM tapback WHERE id=$1 AND portal_receiver=$2
		LIMIT 1
	`
	getLastMessagePartByIDQuery = `
		SELECT portal_uri, portal_receiver, id, part, start_index, length, mxid, mx_room, sender_uri, timestamp, receiving_handle, reply_to_id, reply_to_part
		FROM message WHERE portal_uri=$1 AND portal_receiver=$2 AND id=$3 ORDER BY part DESC LIMIT 1
	`
	getLastMessagePartByIDWithoutChatQuery = `
		SELECT portal_uri, portal_receiver, id, part, start_index, length, mxid, mx_room, sender_uri, timestamp, receiving_handle, reply_to_id, reply_to_part
		FROM message WHERE portal_receiver=$1 AND id=$2 ORDER BY part DESC LIMIT 1
	`
	getLastMessageInThreadQuery = `
		SELECT portal_uri, portal_receiver, id, part, start_index, length, mxid, mx_room, sender_uri, timestamp, receiving_handle, reply_to_id, reply_to_part
		FROM message WHERE portal_uri=$1 AND portal_receiver=$2 AND reply_to_id=$3 AND reply_to_part=$4 ORDER BY timestamp DESC, part DESC LIMIT 1
	`
	getMessagePartByIDQuery = `
		SELECT portal_uri, portal_receiver, id, part, start_index, length, mxid, mx_room, sender_uri, timestamp, receiving_handle, reply_to_id, reply_to_part
		FROM message WHERE portal_uri=$1 AND portal_receiver=$2 AND id=$3 AND part=$4
	`
	getMessagePartByIDWithoutChatQuery = `
		SELECT portal_uri, portal_receiver, id, part, start_index, length, mxid, mx_room, sender_uri, timestamp, receiving_handle, reply_to_id, reply_to_part
		FROM message WHERE portal_receiver=$1 AND id=$2 AND part=$3
	`
	getAllMessagesForIDQuery = `
		SELECT portal_uri, portal_receiver, id, part, start_index, length, mxid, mx_room, sender_uri, timestamp, receiving_handle, reply_to_id, reply_to_part
		FROM message WHERE portal_uri=$1 AND portal_receiver=$2 AND id=$3
	`
	getAllMessagesForIDWithoutChatQuery = `
		SELECT portal_uri, portal_receiver, id, part, start_index, length, mxid, mx_room, sender_uri, timestamp, receiving_handle, reply_to_id, reply_to_part
		FROM message WHERE portal_receiver=$1 AND id=$2
	`
	getMessageByMXIDQuery = `
		SELECT portal_uri, portal_receiver, id, part, start_index, length, mxid, mx_room, sender_uri, timestamp, receiving_handle, reply_to_id, reply_to_part
		FROM message WHERE mxid=$1
	`
	getLastMessageInChatQuery = `
		SELECT portal_uri, portal_receiver, id, part, start_index, length, mxid, mx_room, sender_uri, timestamp, receiving_handle, reply_to_id, reply_to_part
		FROM message WHERE portal_uri=$1 AND portal_receiver=$2 ORDER BY timestamp DESC LIMIT 1
	`
	getFirstMessageInChatQuery = `
		SELECT portal_uri, portal_receiver, id, part, start_index, length, mxid, mx_room, sender_uri, timestamp, receiving_handle, reply_to_id, reply_to_part
		FROM message WHERE portal_uri=$1 AND portal_receiver=$2 ORDER BY timestamp ASC LIMIT 1
	`
	insertMessageQuery = `
		INSERT INTO message (portal_uri, portal_receiver, id, part, start_index, length, mxid, mx_room, sender_uri, timestamp, receiving_handle, reply_to_id, reply_to_part)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
	`
	deleteMessageQuery = `
		DELETE FROM message WHERE portal_uri=$1 AND portal_receiver=$2 AND id=$3
	`
)

func (mq *MessageQuery) GetPortalURIByID(ctx context.Context, id uuid.UUID, receiver int) (uri uri.ParsedURI, err error) {
	err = mq.db.Conn(ctx).QueryRowContext(ctx, getPortalURIByMessageIDQuery, id, receiver).Scan(&uri)
	if errors.Is(err, sql.ErrNoRows) {
		err = nil
	}
	return
}

func (mq *MessageQuery) GetLastPartByID(ctx context.Context, chat Key, id uuid.UUID) (*Message, error) {
	return get[*Message](mq, ctx, getLastMessagePartByIDQuery, chat.URI, chat.Receiver, id)
}

func (mq *MessageQuery) GetLastPartByIDWithoutChat(ctx context.Context, receiver int, id uuid.UUID) (*Message, error) {
	return get[*Message](mq, ctx, getLastMessagePartByIDWithoutChatQuery, receiver, id)
}

func (mq *MessageQuery) GetByID(ctx context.Context, chat Key, id uuid.UUID, part int) (*Message, error) {
	return get[*Message](mq, ctx, getMessagePartByIDQuery, chat.URI, chat.Receiver, id, part)
}

func (mq *MessageQuery) GetByIDWithoutChat(ctx context.Context, receiver int, id uuid.UUID, part int) (*Message, error) {
	return get[*Message](mq, ctx, getMessagePartByIDWithoutChatQuery, receiver, id, part)
}

func (mq *MessageQuery) GetLastMessageInThread(ctx context.Context, chat Key, id uuid.UUID, part int) (*Message, error) {
	return get[*Message](mq, ctx, getLastMessageInThreadQuery, chat.URI, chat.Receiver, id, part)
}

func (mq *MessageQuery) GetAllMessagesForID(ctx context.Context, chat Key, id uuid.UUID) ([]*Message, error) {
	return getAll[*Message](mq, ctx, getAllMessagesForIDQuery, chat.URI, chat.Receiver, id)
}

func (mq *MessageQuery) GetAllMessagesForIDWithoutChat(ctx context.Context, receiver int, id uuid.UUID) ([]*Message, error) {
	return getAll[*Message](mq, ctx, getAllMessagesForIDWithoutChatQuery, receiver, id)
}

func (mq *MessageQuery) GetByMXID(ctx context.Context, mxid id.EventID) (*Message, error) {
	return get[*Message](mq, ctx, getMessageByMXIDQuery, mxid)
}

func (mq *MessageQuery) GetLastInChat(ctx context.Context, chat Key) (*Message, error) {
	return get[*Message](mq, ctx, getLastMessageInChatQuery, chat.URI, chat.Receiver)
}

func (mq *MessageQuery) GetFirstInChat(ctx context.Context, chat Key) (*Message, error) {
	return get[*Message](mq, ctx, getFirstMessageInChatQuery, chat.URI, chat.Receiver)
}

func (mq *MessageQuery) GetEarliestTimestampInChat(chat string) (int64, error) {
	row := mq.db.QueryRow("SELECT MIN(timestamp) FROM message WHERE portal_uri=$1", chat)
	var timestamp sql.NullInt64
	if err := row.Scan(&timestamp); err != nil {
		return -1, err
	} else if !timestamp.Valid {
		return -1, nil
	} else {
		return timestamp.Int64, nil
	}
}

type Message struct {
	db  *Database
	log log.Logger

	Portal          Key
	ID              uuid.UUID
	Part            int
	StartIndex      int
	Length          int
	MXID            id.EventID
	RoomID          id.RoomID
	SenderURI       uri.ParsedURI
	Timestamp       int64
	ReceivingHandle uri.ParsedURI

	ReplyToID   uuid.UUID
	ReplyToPart int
}

func (msg *Message) PartInfo() imessage.MessagePartInfo {
	return imessage.MessagePartInfo{
		PartID:     msg.Part,
		StartIndex: msg.StartIndex,
		Length:     msg.Length,
	}
}

func (msg *Message) Time() time.Time {
	return time.UnixMilli(msg.Timestamp)
}

func (msg *Message) Scan(row dbutil.Scannable) (*Message, error) {
	var replyToID uuid.NullUUID
	var replyToPart sql.NullInt32
	err := row.Scan(
		&msg.Portal.URI, &msg.Portal.Receiver, &msg.ID, &msg.Part, &msg.StartIndex, &msg.Length,
		&msg.MXID, &msg.RoomID, &msg.SenderURI, &msg.Timestamp, &msg.ReceivingHandle, &replyToID, &replyToPart,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	msg.ReplyToID = replyToID.UUID
	msg.ReplyToPart = int(replyToPart.Int32)
	return msg, nil
}

func (msg *Message) sqlVariables() []any {
	var replyToID uuid.NullUUID
	var replyToPart sql.NullInt32
	if msg.ReplyToID != uuid.Nil {
		replyToID = uuid.NullUUID{UUID: msg.ReplyToID, Valid: true}
		replyToPart = sql.NullInt32{Int32: int32(msg.ReplyToPart), Valid: true}
	}
	return []any{msg.Portal.URI, msg.Portal.Receiver, msg.ID, msg.Part, msg.StartIndex, msg.Length, msg.MXID, &msg.RoomID, msg.SenderURI, msg.Timestamp, msg.ReceivingHandle, replyToID, replyToPart}
}

func (msg *Message) Insert(ctx context.Context) error {
	_, err := msg.db.Conn(ctx).ExecContext(ctx, insertMessageQuery, msg.sqlVariables()...)
	return err
}

func (msg *Message) Delete(ctx context.Context) error {
	_, err := msg.db.Conn(ctx).ExecContext(ctx, deleteMessageQuery, msg.Portal.URI, msg.Portal.Receiver, msg.ID)
	return err
}
