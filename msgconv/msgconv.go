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

package msgconv

import (
	"context"

	"github.com/google/uuid"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"

	"github.com/beeper/imessage/database"
	"github.com/beeper/imessage/imessage"
	"github.com/beeper/imessage/imessage/direct"
	"github.com/beeper/imessage/imessage/direct/ids"
	"github.com/beeper/imessage/imessage/direct/util/uri"
)

type PortalMethods interface {
	UploadMatrixMedia(ctx context.Context, data []byte, fileName, contentType string) (id.ContentURIString, error)
	DownloadMatrixMedia(ctx context.Context, uri id.ContentURIString) ([]byte, error)
	GetMatrixReply(ctx context.Context, msg *imessage.Message) (threadRoot, replyFallback id.EventID)
	GetiMessageThreadRoot(ctx context.Context, content *event.MessageEventContent) string

	GetIM() *direct.Connector
	GetData(ctx context.Context) *database.Portal
}

type ExtendedPortalMethods interface {
	QueueFileTransfer(ctx context.Context, msgID uuid.UUID, partInfo imessage.MessagePartInfo, fileName string, ad *ids.AttachmentDownloader) (id.ContentURIString, error)
}

type MessageConverter struct {
	PortalMethods

	ConvertHEIF bool
	ConvertTIFF bool
	ConvertMOV  bool
	ConvertCAF  bool
	MaxFileSize int64
	AsyncFiles  bool
	Threads     bool
}

func (mc *MessageConverter) IsPrivateChat(ctx context.Context) bool {
	u := mc.GetData(ctx).URI
	return u.Scheme != uri.SchemeGroup && u.Scheme != uri.SchemeGroupParticipants
}
