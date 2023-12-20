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
	"context"
	"encoding/base64"
	"fmt"
	"sync"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"go.mau.fi/util/exzerolog"

	"github.com/beeper/imessage/imessage/direct/apns"
	"github.com/beeper/imessage/imessage/direct/ids/types"
	"github.com/beeper/imessage/imessage/direct/util/uri"
)

func (dc *Connector) handleAck(ctx context.Context, payload *apns.SendMessagePayload) {
	dc.ackWaitersLock.Lock()
	aw, ok := dc.ackWaiters[payload.MessageUUID.UUID()]
	dc.ackWaitersLock.Unlock()
	if ok {
		aw.Receive(ctx, payload)
	} else {
		zerolog.Ctx(ctx).Warn().
			Stringer("status", payload.ResponseStatus).
			Str("message_id", payload.MessageUUID.String()).
			Str("push_token", base64.StdEncoding.EncodeToString(payload.Token)).
			Msg("Unexpected APNs ack (no waiter)")
	}
}

type pushToken [32]byte

func (pt pushToken) String() string {
	return base64.StdEncoding.EncodeToString(pt[:])
}

type ackWaiterPayload struct {
	*apns.SendMessagePayload
	Destination uri.ParsedURI
}

type ackWaiter struct {
	payloads   map[pushToken]*ackWaiterPayload
	ackedUsers map[uri.ParsedURI]bool
	lock       sync.Mutex
	closed     bool
	cancelled  bool
	wg         sync.WaitGroup
	userWG     sync.WaitGroup
	onceDone   sync.Once
	onDone     func()

	errorChan   chan struct{}
	serverError types.IDSStatus
}

func (dc *Connector) newAckWaiter(size int, messageUUID uuid.UUID) *ackWaiter {
	aw := &ackWaiter{
		payloads:   make(map[pushToken]*ackWaiterPayload, size),
		ackedUsers: make(map[uri.ParsedURI]bool),
		errorChan:  make(chan struct{}),
	}
	aw.onDone = func() {
		dc.finishAckWaiting(messageUUID, aw)
	}
	dc.ackWaitersLock.Lock()
	dc.ackWaiters[messageUUID] = aw
	dc.ackWaitersLock.Unlock()
	return aw
}

func (dc *Connector) finishAckWaiting(messageUUID uuid.UUID, aw *ackWaiter) {
	dc.ackWaitersLock.Lock()
	if dc.ackWaiters[messageUUID] == aw {
		delete(dc.ackWaiters, messageUUID)
	}
	dc.ackWaitersLock.Unlock()
}

// Cancel marks the ack waiter as cancelled, but keeps collecting acks to ensure they're properly logged.
func (aw *ackWaiter) Cancel() {
	aw.lock.Lock()
	aw.cancelled = true
	aw.lock.Unlock()
}

func (aw *ackWaiter) ErrorChan() <-chan struct{} {
	return aw.errorChan
}

func (aw *ackWaiter) ServerError() types.IDSStatus {
	return aw.serverError
}

// Close closes the ack waiter entirely and stops it from collecting new acks.
func (aw *ackWaiter) Close() {
	aw.lock.Lock()
	aw.closed = true
	for _, payload := range aw.payloads {
		if payload.SendMessagePayload == nil {
			aw.wg.Done()
		}
	}
	for dest, userHasAcked := range aw.ackedUsers {
		if !userHasAcked {
			aw.userWG.Done()
		}
		aw.ackedUsers[dest] = true
	}
	aw.lock.Unlock()
}

func (aw *ackWaiter) Wait() chan struct{} {
	waitChan := make(chan struct{})
	go func() {
		aw.wg.Wait()
		aw.onceDone.Do(aw.onDone)
		close(waitChan)
	}()
	return waitChan
}

func (aw *ackWaiter) WaitForUsers() chan struct{} {
	waitChan := make(chan struct{})
	go func() {
		aw.userWG.Wait()
		close(waitChan)
	}()
	return waitChan
}

func (aw *ackWaiter) CompileError() *SendMessageError {
	aw.lock.Lock()
	defer aw.lock.Unlock()
	return newSendMessageError(aw.payloads, aw.ackedUsers)
}

func (aw *ackWaiter) Receive(ctx context.Context, ack *apns.SendMessagePayload) {
	log := zerolog.Ctx(ctx).With().
		Stringer("status", ack.ResponseStatus).
		Str("message_id", ack.MessageUUID.String()).
		Str("push_token", base64.StdEncoding.EncodeToString(ack.Token)).
		Logger()
	aw.lock.Lock()
	defer aw.lock.Unlock()
	if len(ack.Token) == 0 && ack.ResponseStatus != types.IDSStatusSuccess {
		if aw.serverError == 0 {
			log.Warn().
				Str("raw_apns_data", base64.StdEncoding.EncodeToString(ack.Raw)).
				Msg("Got error status in IDS server ack")
			close(aw.errorChan)
			aw.serverError = ack.ResponseStatus
		} else {
			log.Warn().
				Str("raw_apns_data", base64.StdEncoding.EncodeToString(ack.Raw)).
				Str("previous_error", aw.serverError.String()).
				Msg("Got duplicate error status in IDS server ack")
		}
		return
	} else if len(ack.Token) != 32 {
		log.Warn().Msg("Unexpected push token length in ack")
		return
	}
	tokenArr := *(*pushToken)(ack.Token)
	payload, ok := aw.payloads[tokenArr]
	if !ok {
		log.Warn().Msg("Got ack for message from unexpected push token")
		return
	}
	log = log.With().
		Str("destination_id", payload.Destination.String()).
		Bool("waiter_cancelled", aw.cancelled).
		Logger()
	if aw.closed {
		log.Warn().Msg("Got ack for message after waiter was closed")
		return
	}
	if payload.SendMessagePayload == nil {
		var logEvt *zerolog.Event
		if ack.ResponseStatus != types.IDSStatusSuccess {
			logEvt = log.Warn()
		} else {
			logEvt = log.Debug()
		}
		logEvt.Msg("Got ack for message")
		payload.SendMessagePayload = ack
		aw.wg.Done()
		if ack.ResponseStatus == types.IDSStatusSuccess {
			userHasAcked, ok := aw.ackedUsers[payload.Destination]
			if !ok {
				log.Warn().Msg("Ack is from unexpected user (not in ackedUsers map)")
			} else if !userHasAcked {
				aw.userWG.Done()
				aw.ackedUsers[payload.Destination] = true
			}
		}
	} else {
		log.Debug().
			Stringer("prev_status", payload.SendMessagePayload.ResponseStatus).
			Msg("Got duplicate ack for message")
	}
}

type UserErrorCounts struct {
	Missing []pushToken
	Failed  map[pushToken]types.IDSStatus
	Success []pushToken
	Total   int
}

func (uec *UserErrorCounts) MarshalZerologObject(evt *zerolog.Event) {
	evt.Int("total", uec.Total).Int("success", len(uec.Success))
	if len(uec.Missing) > 0 {
		evt.Array("missing", exzerolog.ArrayOfStringers(uec.Missing))
	}
	if len(uec.Failed) > 0 {
		failed := zerolog.Dict()
		for pt, status := range uec.Failed {
			failed.Str(pt.String(), status.String())
		}
		evt.Dict("failed", failed)
	}
}

type UserErrorCountsMap map[uri.ParsedURI]*UserErrorCounts

func (uecm UserErrorCountsMap) MarshalZerologObject(evt *zerolog.Event) {
	for dest, uec := range uecm {
		evt.Object(dest.String(), uec)
	}
}

type SendMessageError struct {
	DestinationTokenCount int
	DestinationUserCount  int
	SuccessCount          int
	MissingCount          int
	ErrorCount            int

	StatusByUser     UserErrorCountsMap
	CountByErrorType map[types.IDSStatus]int
	UniqueErrorTypes []types.IDSStatus
	MissingUsers     []uri.ParsedURI
}

func newSendMessageError(payloads map[pushToken]*ackWaiterPayload, users map[uri.ParsedURI]bool) *SendMessageError {
	sme := &SendMessageError{
		CountByErrorType:      make(map[types.IDSStatus]int),
		StatusByUser:          make(UserErrorCountsMap, len(users)),
		DestinationUserCount:  len(users),
		DestinationTokenCount: len(payloads),
	}
	for user, acked := range users {
		if !acked {
			sme.MissingUsers = append(sme.MissingUsers, user)
		}
	}
	for pt, payload := range payloads {
		uec, ok := sme.StatusByUser[payload.Destination]
		if !ok {
			uec = &UserErrorCounts{
				Failed: make(map[pushToken]types.IDSStatus),
			}
			sme.StatusByUser[payload.Destination] = uec
		}
		uec.Total++
		if payload.SendMessagePayload == nil {
			sme.MissingCount++
			uec.Missing = append(uec.Missing, pt)
		} else if payload.ResponseStatus == types.IDSStatusSuccess {
			sme.SuccessCount++
			uec.Success = append(uec.Success, pt)
		} else {
			uec.Failed[pt] = payload.ResponseStatus
			sme.CountByErrorType[payload.ResponseStatus]++
			sme.ErrorCount++
		}
	}
	if len(sme.CountByErrorType) > 0 {
		sme.UniqueErrorTypes = make([]types.IDSStatus, 0, len(sme.CountByErrorType))
		for errorType := range sme.CountByErrorType {
			sme.UniqueErrorTypes = append(sme.UniqueErrorTypes, errorType)
		}
	}
	return sme
}

func (sme *SendMessageError) hasError() bool {
	if sme == nil || sme.ErrorCount == 0 {
		return false
	}
	if len(sme.UniqueErrorTypes) == 1 && sme.UniqueErrorTypes[0] == types.IDSStatusMessageRemoved {
		for _, uec := range sme.StatusByUser {
			if len(uec.Success) == 0 {
				// One of the recipients didn't receive the message on any device, so don't ignore the error
				return true
			}
		}
		// Ignore MessageRemoved if all users received the message (ignore individual devices not receiving)
		return false
	}
	return true
}

func formatUserList(list []uri.ParsedURI) string {
	switch len(list) {
	case 0:
		return ""
	case 1:
		return list[0].Identifier
	case 2:
		return fmt.Sprintf("%s and %s", list[0].Identifier, list[1].Identifier)
	case 3:
		return fmt.Sprintf("%s, %s, and %s", list[0].Identifier, list[1].Identifier, list[2].Identifier)
	default:
		return fmt.Sprintf("%s, %s, and %d others", list[0].Identifier, list[1].Identifier, len(list)-2)
	}
}

func (sme *SendMessageError) Error() string {
	if sme.ErrorCount > 0 {
		var errorTypesString string
		if len(sme.UniqueErrorTypes) == 1 {
			errorTypesString = fmt.Sprintf("error %s", sme.UniqueErrorTypes[0])
		} else if len(sme.UniqueErrorTypes) > 1 {
			errorTypesString = fmt.Sprintf("errors: %v", sme.UniqueErrorTypes)
		}
		var erroredUserList []uri.ParsedURI
		for dest, uec := range sme.StatusByUser {
			if len(uec.Failed) > 0 {
				erroredUserList = append(erroredUserList, dest)
			}
		}
		// All users failed, show total destination device count, omit user identifiers
		if len(erroredUserList) == sme.DestinationUserCount {
			return fmt.Sprintf("sending to %d/%d devices failed with %s", sme.ErrorCount, sme.DestinationTokenCount, errorTypesString)
		} else if len(erroredUserList) == 1 {
			// Only one user failed, show total device count of that user
			errorCount := len(sme.StatusByUser[erroredUserList[0]].Failed)
			totalCount := sme.StatusByUser[erroredUserList[0]].Total
			return fmt.Sprintf("sending to %d/%d devices of %s failed with %s", errorCount, totalCount, erroredUserList[0].Identifier, errorTypesString)
		} else {
			// More than one user failed, don't show total device count
			return fmt.Sprintf(
				"sending to %d devices of %s failed with %s",
				sme.ErrorCount,
				formatUserList(erroredUserList),
				errorTypesString,
			)
		}
	} else if sme.SuccessCount == 0 && sme.MissingCount > 0 {
		return fmt.Sprintf("%d/%d destinations didn't respond", sme.MissingCount, sme.DestinationTokenCount)
	} else if len(sme.MissingUsers) > 0 {
		return fmt.Sprintf("sending to all devices of %s failed with no response", formatUserList(sme.MissingUsers))
	} else if sme.DestinationTokenCount == 0 {
		return "no destinations"
	}
	return "success"
}
