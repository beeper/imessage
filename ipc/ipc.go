// beeper-imessage - A Matrix-iMessage puppeting bridge.
// Copyright (C) 2021 Tulir Asokan
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

package ipc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"runtime/debug"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rs/zerolog"
)

const (
	CommandResponse Command = "response"
	CommandError    Command = "error"
	CommandLog      Command = "log"
)

var (
	ErrIPCTimeout        = errors.New("ipc request timeout")
	ErrUnknownCommand    = Error{"unknown-command", "Unknown command"}
	ErrSizeLimitExceeded = Error{Code: "size_limit_exceeded"}
	ErrTimeoutError      = Error{Code: "timeout"}
	ErrUnsupportedError  = Error{Code: "unsupported"}
	ErrNotFound          = Error{Code: "not_found"}
)

type Command string

type Message struct {
	Command    Command         `json:"command"`
	ResponseTo Command         `json:"response_to,omitempty"`
	ID         int             `json:"id,omitempty"`
	Data       json.RawMessage `json:"data,omitempty"`
}

type OutgoingMessage struct {
	Command    Command `json:"command"`
	ResponseTo Command `json:"response_to,omitempty"`
	ID         int     `json:"id,omitempty"`
	Data       any     `json:"data,omitempty"`
}

type Error struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func (err Error) Error() string {
	return fmt.Sprintf("%s: %s", err.Code, err.Message)
}

func (err Error) Is(other error) bool {
	otherErr, ok := other.(Error)
	if !ok {
		otherErrPtr, ok := other.(*Error)
		if !ok || otherErrPtr == nil {
			return false
		}
		otherErr = *otherErrPtr
	}
	return otherErr.Code == err.Code
}

type HandlerFunc func(ctx context.Context, message json.RawMessage) any

type LockedWriter struct {
	lock sync.Mutex
	json *json.Encoder
	byte io.Writer
}

func NewLockedWriter(wr io.Writer) *LockedWriter {
	return &LockedWriter{
		json: json.NewEncoder(wr),
		byte: wr,
	}
}

var _ zerolog.LevelWriter = (*LockedWriter)(nil)

func (ls *LockedWriter) Encode(msg any) error {
	ls.lock.Lock()
	defer ls.lock.Unlock()
	return ls.json.Encode(msg)
}

func (ls *LockedWriter) Write(data []byte) (int, error) {
	return len(data), ls.Encode(Message{Command: CommandLog, Data: data})
}

func (ls *LockedWriter) WriteLevel(_ zerolog.Level, msg []byte) (n int, err error) {
	return ls.Write(msg)
}

type Processor struct {
	log *zerolog.Logger
	out *LockedWriter
	in  *json.Decoder

	handlers   map[Command]HandlerFunc
	waiters    map[int]chan<- *Message
	waiterLock sync.Mutex
	reqID      int32
}

func NewProcessor(lw *LockedWriter, input io.Reader, logger *zerolog.Logger) *Processor {
	return &Processor{
		log:      logger,
		out:      lw,
		in:       json.NewDecoder(input),
		handlers: make(map[Command]HandlerFunc),
		waiters:  make(map[int]chan<- *Message),
	}
}

func (ipc *Processor) Loop() {
	for {
		var msg Message
		err := ipc.in.Decode(&msg)
		if err == io.EOF {
			ipc.log.Debug().Msg("Standard input closed, ending IPC loop")
			break
		} else if err != nil {
			ipc.log.Err(err).Msg("Failed to read input")
			break
		}
		log := ipc.log.With().
			Str("ipc_command", string(msg.Command)).
			Int("ipc_request_id", msg.ID).
			Logger()
		ctx := log.WithContext(context.Background())

		if msg.Command == CommandResponse || msg.Command == CommandError {
			ipc.waiterLock.Lock()
			waiter, ok := ipc.waiters[msg.ID]
			if !ok {
				log.Warn().Msg("Nothing waiting for IPC response")
			} else {
				delete(ipc.waiters, msg.ID)
				waiter <- &msg
			}
			ipc.waiterLock.Unlock()
		} else {
			handler, ok := ipc.handlers[msg.Command]
			if !ok {
				ipc.respond(ctx, msg.ID, msg.Command, ErrUnknownCommand)
			} else {
				go ipc.callHandler(ctx, &msg, handler)
			}
		}
	}
}

func (ipc *Processor) Send(cmd Command, data any) error {
	return ipc.out.Encode(OutgoingMessage{Command: cmd, Data: data})
}

func (ipc *Processor) RequestAsync(cmd Command, data any) (<-chan *Message, int, error) {
	respChan := make(chan *Message, 1)
	reqID := int(atomic.AddInt32(&ipc.reqID, 1))
	ipc.waiterLock.Lock()
	ipc.waiters[reqID] = respChan
	ipc.waiterLock.Unlock()
	err := ipc.out.Encode(OutgoingMessage{Command: cmd, ID: reqID, Data: data})
	if err != nil {
		panic(fmt.Errorf("error sending IPC command: %w", err))
	}
	return respChan, reqID, err
}

func (ipc *Processor) Request(ctx context.Context, cmd Command, reqData any, respData any) error {
	respChan, reqID, err := ipc.RequestAsync(cmd, reqData)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	hardTimeout := time.After(5 * time.Minute)
	for {
		select {
		case rawData := <-respChan:
			if rawData.Command == "error" {
				var respErr Error
				err = json.Unmarshal(rawData.Data, &respErr)
				if err != nil {
					return fmt.Errorf("failed to parse error response: %w", err)
				}
				return respErr
			}
			if respData != nil {
				err = json.Unmarshal(rawData.Data, &respData)
				if err != nil {
					return fmt.Errorf("failed to parse response: %w", err)
				}
			}
			return nil
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(5 * time.Second):
			ipc.log.Debug().
				Str("command", string(cmd)).
				Int("request_id", reqID).
				Msg("Still waiting for response")
		case <-hardTimeout:
			ipc.log.Warn().
				Str("command", string(cmd)).
				Int("request_id", reqID).
				Msg("Didn't get response after 5 minutes, giving up")
			return ErrIPCTimeout
		}
	}
}

func (ipc *Processor) callHandler(ctx context.Context, msg *Message, handler HandlerFunc) {
	defer func() {
		err := recover()
		if err != nil {
			zerolog.Ctx(ctx).Error().
				Str(zerolog.ErrorStackFieldName, string(debug.Stack())).
				Interface(zerolog.ErrorFieldName, err).
				Msg("Panic in IPC handler handler")
			ipc.respond(ctx, msg.ID, msg.Command, Error{Code: "panic", Message: fmt.Sprintf("%v", err)})
		}
	}()
	resp := handler(ctx, msg.Data)
	ipc.respond(ctx, msg.ID, msg.Command, resp)
}

func (ipc *Processor) respond(ctx context.Context, id int, command Command, response any) {
	if id == 0 {
		return
	}
	resp := OutgoingMessage{Command: CommandResponse, ResponseTo: command, ID: id, Data: response}
	respErr, isError := response.(error)
	if isError {
		_, isRealError := respErr.(Error)
		if isRealError {
			resp.Data = respErr
		} else {
			resp.Data = Error{
				Code:    "error",
				Message: respErr.Error(),
			}
		}
		resp.Command = CommandError
	}
	err := ipc.out.Encode(resp)
	if err != nil {
		zerolog.Ctx(ctx).Err(err).Int("request_id", id).Msg("Failed to encode IPC response")
	}
}

func (ipc *Processor) SetHandler(command Command, handler HandlerFunc) {
	ipc.handlers[command] = handler
}

func NoDataHandler(fn func(ctx context.Context) any) HandlerFunc {
	return func(ctx context.Context, message json.RawMessage) any {
		return fn(ctx)
	}
}

func TypedHandler[T any](fn func(ctx context.Context, req T) any) HandlerFunc {
	return func(ctx context.Context, message json.RawMessage) any {
		var data T
		err := json.Unmarshal(message, &data)
		if err != nil {
			return Error{Code: "json-error", Message: err.Error()}
		}
		return fn(ctx, data)
	}
}
