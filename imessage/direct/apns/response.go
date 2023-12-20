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

package apns

import (
	"github.com/google/uuid"
)

func (c *Connection) WaitResponseUUID(requestID uuid.UUID) <-chan *SendMessagePayload {
	ch := make(chan *SendMessagePayload, 1)
	if c == nil {
		close(ch)
		return ch
	}
	c.responseWaitersLock.Lock()
	c.responseWaitersUUID[requestID] = ch
	c.responseWaitersLock.Unlock()
	return ch
}

func (c *Connection) CancelResponseUUID(requestID uuid.UUID) {
	if c == nil {
		return
	}
	c.responseWaitersLock.Lock()
	delete(c.responseWaitersUUID, requestID)
	c.responseWaitersLock.Unlock()
}

func (c *Connection) WaitResponseID(requestID uint32) <-chan *SendMessagePayload {
	ch := make(chan *SendMessagePayload, 1)
	if c == nil {
		close(ch)
		return ch
	}
	c.responseWaitersLock.Lock()
	c.responseWaitersID[requestID] = ch
	c.responseWaitersLock.Unlock()
	return ch
}

func (c *Connection) CancelResponseID(requestID uint32) {
	if c == nil {
		return
	}
	c.responseWaitersLock.Lock()
	delete(c.responseWaitersID, requestID)
	c.responseWaitersLock.Unlock()
}

func (c *Connection) receiveResponse(data *SendMessagePayload) bool {
	if !data.MessageUUID.IsValid() && data.MessageID == 0 {
		return false
	}
	c.responseWaitersLock.Lock()
	var ch chan<- *SendMessagePayload
	var ok bool
	if data.MessageUUID.IsValid() {
		ch, ok = c.responseWaitersUUID[data.MessageUUID.UUID()]
		if ok {
			ch <- data
			delete(c.responseWaitersUUID, data.MessageUUID.UUID())
		}
	} else {
		ch, ok = c.responseWaitersID[data.MessageID]
		if ok {
			ch <- data
			delete(c.responseWaitersID, data.MessageID)
		}
	}
	c.responseWaitersLock.Unlock()
	return ok
}
