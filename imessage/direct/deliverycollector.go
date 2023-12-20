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

package direct

import (
	"time"

	"github.com/google/uuid"

	"github.com/beeper/imessage/imessage/direct/apns"
	"github.com/beeper/imessage/imessage/direct/util/uri"
)

func (dc *Connector) handleDelivered(payload *apns.SendMessagePayload) {
	if payload.SenderID == nil || len(payload.Token) != 32 {
		// meow?
		return
	}
	dc.deliveryCollectorsLock.Lock()
	defer dc.deliveryCollectorsLock.Unlock()

	messageID := payload.MessageUUID.UUID()
	dec, ok := dc.deliveryCollectors[messageID]
	if !ok {
		dec = dc.newDeliveryCollector(messageID)
	}
	dec.end.Reset(deliveryWait)
	dec.deliveredTo[*payload.SenderID] = append(dec.deliveredTo[*payload.SenderID], *(*pushToken)(payload.Token))
}

func (dc *Connector) newDeliveryCollector(messageID uuid.UUID) *deliveryCollector {
	dec := &deliveryCollector{
		dc:          dc,
		id:          messageID,
		deliveredTo: make(map[uri.ParsedURI][]pushToken),
	}
	dec.end = time.AfterFunc(deliveryWait, dec.finishDeliveries)
	dc.deliveryCollectors[messageID] = dec
	return dec
}

func (dec *deliveryCollector) finishDeliveries() {
	dec.dc.deliveryCollectorsLock.Lock()
	defer dec.dc.deliveryCollectorsLock.Unlock()

	delete(dec.dc.deliveryCollectors, dec.id)
	dec.dc.EventHandler(&MessageDelivered{
		ID: dec.id,
		To: dec.deliveredTo,
	})
}

type MessageDelivered struct {
	ID uuid.UUID
	To map[uri.ParsedURI][]pushToken
}

type deliveryCollector struct {
	dc          *Connector
	id          uuid.UUID
	end         *time.Timer
	deliveredTo map[uri.ParsedURI][]pushToken
}

const deliveryWait = 1 * time.Second
