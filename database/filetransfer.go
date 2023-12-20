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

	"go.mau.fi/util/dbutil"
	"maunium.net/go/mautrix/id"

	"github.com/beeper/imessage/imessage/direct/ids"
)

type FileTransferQuery struct {
	db *Database
}

func (ftq *FileTransferQuery) New() *FileTransfer {
	return &FileTransfer{db: ftq.db}
}

func (ftq *FileTransferQuery) getDB() *Database {
	return ftq.db
}

const (
	getFileTransfer = `
		SELECT user_id, identifier, mxc_uri, temp_path, error, state
		FROM file_transfer WHERE user_id=$1 AND identifier=$2
	`
	getAllPendingFileTransfers = `
		SELECT user_id, identifier, mxc_uri, temp_path, error, state
		FROM file_transfer WHERE user_id=$1 AND state<>'null' AND error=''
	`
	insertFileTransfer = `
		INSERT INTO file_transfer (user_id, identifier, mxc_uri, temp_path, error, state) VALUES ($1, $2, $3, $4, $5, $6)
	`
	updateFileTransfer = `
		UPDATE file_transfer SET error=$5, state=$6 WHERE user_id=$1 AND identifier=$2
	`
)

func (ftq *FileTransferQuery) Get(ctx context.Context, userID int, identifier string) (*FileTransfer, error) {
	return get[*FileTransfer](ftq, ctx, getFileTransfer, userID, identifier)
}

func (ftq *FileTransferQuery) GetAllPending(ctx context.Context, userID int) ([]*FileTransfer, error) {
	return getAll[*FileTransfer](ftq, ctx, getAllPendingFileTransfers, userID)
}

type FileTransfer struct {
	db *Database

	UserID     int
	Identifier string
	State      *ids.AttachmentDownloader
	MXC        id.ContentURIString
	TempPath   string
	Error      string
}

func (ft *FileTransfer) sqlVariables() []any {
	return []any{ft.UserID, ft.Identifier, ft.MXC, ft.TempPath, ft.Error, dbutil.JSON{ft.State}}
}

func (ft *FileTransfer) Scan(row dbutil.Scannable) (*FileTransfer, error) {
	err := row.Scan(&ft.UserID, &ft.Identifier, &ft.MXC, &ft.TempPath, &ft.Error, dbutil.JSON{&ft.State})
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	return ft, err
}

func (ft *FileTransfer) Insert(ctx context.Context) error {
	_, err := ft.db.Conn(ctx).ExecContext(ctx, insertFileTransfer, ft.sqlVariables()...)
	return err
}

func (ft *FileTransfer) Update(ctx context.Context) error {
	_, err := ft.db.Conn(ctx).ExecContext(ctx, updateFileTransfer, ft.sqlVariables()...)
	return err
}
