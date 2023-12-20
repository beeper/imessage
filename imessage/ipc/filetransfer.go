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

package main

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"go.mau.fi/util/exsync"
	"maunium.net/go/mautrix/id"

	"github.com/beeper/imessage/database"
	"github.com/beeper/imessage/imessage"
	"github.com/beeper/imessage/imessage/direct/ids"
	"github.com/beeper/imessage/msgconv"
)

func getPath(uri id.ContentURIString) (string, error) {
	parsed, err := url.Parse(string(uri))
	if err != nil {
		return "", fmt.Errorf("failed to parse uri: %w", err)
	} else if parsed.Scheme != "file" {
		return "", fmt.Errorf("only file:// URIs are supported")
	}
	return parsed.Path, nil
}

func getTempPath(path string) string {
	fileName := filepath.Base(path)
	return filepath.Join(filepath.Dir(path), "."+fileName+".tmp")
}

func (imc *IMContext) getAttachmentPath(fileName string) string {
	return filepath.Join(imc.Cfg.AttachmentDir, strings.ReplaceAll(fileName, "/", "_"))
}

func makeFileContentURIString(path string) id.ContentURIString {
	return id.ContentURIString((&url.URL{
		Scheme: "file",
		Path:   path,
	}).String())
}

var qftOnce = new(sync.Once)
var inProgressTransfers = exsync.NewSet[string]()

func DoAllQueuedFileTransfers() {
	log := global.Log.With().Str("action", "do queued file transfers").Logger()
	ctx := log.WithContext(global.Ctx)
	transfers, err := global.DB.FileTransfer.GetAllPending(ctx, global.DBUser.RowID)
	if err != nil {
		log.Err(err).Msg("Failed to get pending file transfers")
		return
	}
	if len(transfers) == 0 {
		log.Info().Msg("No pending file transfers")
		return
	}
	log.Info().Int("transfer_count", len(transfers)).Msg("Doing pending file transfers")
	for _, transfer := range transfers {
		(&QueuedFileTransfer{
			FileTransfer: transfer,
			User:         global.IM.User,
		}).Do(ctx)
	}
	log.Info().Int("transfer_count", len(transfers)).Msg("Finished pending file transfers")
}

type QueuedFileTransfer struct {
	*database.FileTransfer
	User *ids.User
}

var _ msgconv.ExtendedPortalMethods = (*IMContext)(nil)

func (imc *IMContext) QueueFileTransfer(ctx context.Context, msgID uuid.UUID, partInfo imessage.MessagePartInfo, fileName string, ad *ids.AttachmentDownloader) (id.ContentURIString, error) {
	fileName = fmt.Sprintf("%s.%d-%s", msgID, partInfo.PartID, fileName)
	attachmentPath := imc.getAttachmentPath(fileName)
	path := getTempPath(attachmentPath)
	ft := imc.DB.FileTransfer.New()
	ft.UserID = imc.DBUser.RowID
	ft.MXC = makeFileContentURIString(attachmentPath)
	ft.TempPath = path
	ft.State = ad
	ft.Identifier = messageToMXID(msgID, partInfo).String()
	err := ft.Insert(ctx)
	if err != nil {
		log := zerolog.Ctx(ctx)
		existingFT, getErr := imc.DB.FileTransfer.Get(ctx, imc.DBUser.RowID, ft.Identifier)
		if getErr != nil {
			log.Error().
				AnErr("insert_error", err).
				AnErr("fetch_error", getErr).
				Msg("Inserting file transfer failed, and fetching existing file transfer also failed")
		} else if existingFT == nil {
			log.Err(err).Msg("Inserting file transfer failed and existing transfer doesn't exist")
		} else if existingFT.Error != "" {
			log.Error().
				AnErr("insert_error", err).
				Str("existing_error", existingFT.Error).
				Msg("Inserting file transfer failed, but existing transfer exists with error")
		} else {
			log.Warn().
				AnErr("insert_error", err).
				Bool("existing_complete", existingFT.State == nil).
				Msg("Inserting file transfer failed, but existing transfer exists, ignoring error")
			if existingFT.MXC != ft.MXC || existingFT.TempPath != ft.TempPath {
				log.Warn().
					Str("existing_mxc", string(existingFT.MXC)).
					Str("existing_temp_path", existingFT.TempPath).
					Str("new_mxc", string(ft.MXC)).
					Str("new_temp_path", ft.TempPath).
					Msg("Existing file transfer has different MXC or temp path")
			}
			return existingFT.MXC, nil
		}
		return "", err
	}
	qft := &QueuedFileTransfer{
		FileTransfer: ft,
		User:         imc.IM.User,
	}
	go qft.Do(ctx)
	return ft.MXC, nil
}

func (qft *QueuedFileTransfer) Do(ctx context.Context) {
	log := zerolog.Ctx(ctx).With().
		Str("transfer_id", qft.Identifier).
		Str("mxc", string(qft.MXC)).
		Logger()
	if !inProgressTransfers.Add(qft.Identifier) {
		log.Warn().Msg("Transfer is already in progress, not restarting")
		return
	}
	defer inProgressTransfers.Remove(qft.Identifier)

	destPath, err := getPath(qft.MXC)
	if err != nil {
		log.Err(err).Msg("Failed to parse mxc")
		return
	}
	if _, err = os.Stat(destPath); err == nil {
		log.Debug().Msg("Destination file already exists, marking file transfer as completed")
		qft.State = nil
		_ = global.IPC.Send(CmdFileTransferProgress, &ReqFileTransferProgress{
			EventID:  qft.Identifier,
			Path:     qft.MXC,
			Progress: 100,
			Done:     true,
		})
		err = qft.Update(ctx)
		if err != nil {
			log.Err(err).Msg("Failed to save already-completed file transfer state")
		}
		return
	}

	log.Debug().Msg("Downloading file")
	var lastProgress time.Time
	err = qft.State.DownloadFile(ctx, qft.User, qft.TempPath, func(progress *ids.DownloadProgress, save bool) {
		//log.Trace().Any("progress", progress).Msg("File transfer progress updated")
		if save {
			err = qft.Update(ctx)
			if err != nil {
				log.Err(err).Msg("Failed to save in-progress file transfer state")
			}
		}
		if time.Since(lastProgress) > 50*time.Millisecond {
			lastProgress = time.Now()
			_ = global.IPC.Send(CmdFileTransferProgress, &ReqFileTransferProgress{
				EventID:  qft.Identifier,
				Path:     qft.MXC,
				Progress: progress.Percent(),
			})
		}
	})
	if err != nil {
		if ctx.Err() != nil {
			log.Err(err).
				AnErr("ctx_error", ctx.Err()).
				Msg("File download failed, but context is also canceled")
			return
		}
		log.Err(err).Msg("File download failed, marking file transfer as errored")
		qft.Error = err.Error()
		_ = os.Remove(qft.TempPath)
		_ = global.IPC.Send(CmdFileTransferProgress, &ReqFileTransferProgress{
			EventID: qft.Identifier,
			Path:    qft.MXC,
			Error:   qft.Error,
		})
	} else {
		log.Debug().Msg("File download successful, marking file transfer as completed")
		qft.State = nil
		err = os.Rename(qft.TempPath, destPath)
		if err != nil {
			log.Err(err).Msg("Failed to move temp file to destination path")
			return
		}
		_ = global.IPC.Send(CmdFileTransferProgress, &ReqFileTransferProgress{
			EventID:  qft.Identifier,
			Path:     qft.MXC,
			Progress: 100,
			Done:     true,
		})
	}
	log.Debug().Msg("Saving file transfer state")
	err = qft.Update(ctx)
	if err != nil {
		log.Err(err).Msg("Failed to save file transfer state")
		return
	}
	return
}

func (imc *IMContext) UploadMatrixMedia(ctx context.Context, data []byte, fileName, contentType string) (id.ContentURIString, error) {
	absPath := imc.getAttachmentPath(fileName)
	file, err := os.OpenFile(absPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return "", fmt.Errorf("failed to open file for writing: %w", err)
	}
	_, err = file.Write(data)
	if err != nil {
		return "", fmt.Errorf("failed to write file: %w", err)
	}
	err = file.Close()
	if err != nil {
		return "", fmt.Errorf("failed to close file: %w", err)
	}
	mxc := makeFileContentURIString(absPath)
	_ = global.IPC.Send(CmdFileTransferProgress, &ReqFileTransferProgress{
		//EventID:  not available here,
		Path:     mxc,
		Progress: 100,
		Done:     true,
	})
	return mxc, nil
}

func (imc *IMContext) DownloadMatrixMedia(ctx context.Context, uri id.ContentURIString) ([]byte, error) {
	path, err := getPath(uri)
	if err != nil {
		return nil, err
	}
	return os.ReadFile(path)
}
