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
	"bytes"
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"runtime/debug"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"go.mau.fi/util/random"
	"golang.org/x/net/proxy"
	"howett.net/plist"

	"github.com/beeper/imessage/imessage/direct/util/appletls"
	"github.com/beeper/imessage/imessage/direct/util/nonce"
)

type Connection struct {
	log *zerolog.Logger

	privateKey *rsa.PrivateKey
	deviceCert *x509.Certificate
	conn       net.Conn
	token      []byte

	responseWaitersLock sync.Mutex
	responseWaitersUUID map[uuid.UUID]chan<- *SendMessagePayload
	responseWaitersID   map[uint32]chan<- *SendMessagePayload

	MaxMessageSize      int
	MaxLargeMessageSize int

	sendLock      sync.Mutex
	sendAckWaiter chan<- *SendMessageAckCommand

	NoAutoFlush bool
	// Don't run anything in unchecked background goroutines
	NoAsyncWork bool

	CourierHostnameOverride string
	courierHostname         string

	MessageHandler      func(ctx context.Context, payload *SendMessagePayload) (bool, error)
	ConnectHandler      func(ctx context.Context)
	ConnectErrorHandler func(ctx context.Context, status []byte)

	socksProxyAddr string
	socksProxyAuth *proxy.Auth
}

func NewConnection(log *zerolog.Logger, privateKey *rsa.PrivateKey, deviceCert *x509.Certificate) *Connection {
	return &Connection{
		log:        log,
		privateKey: privateKey,
		deviceCert: deviceCert,

		sendAckWaiter: make(chan<- *SendMessageAckCommand),

		MessageHandler:      func(ctx context.Context, payload *SendMessagePayload) (bool, error) { return false, nil },
		ConnectHandler:      func(ctx context.Context) {},
		ConnectErrorHandler: func(ctx context.Context, status []byte) {},

		MaxMessageSize:      4 * 1024,
		MaxLargeMessageSize: 15 * 1024,

		responseWaitersUUID: make(map[uuid.UUID]chan<- *SendMessagePayload),
		responseWaitersID:   make(map[uint32]chan<- *SendMessagePayload),
	}
}

func (c *Connection) SetPushKey(key *rsa.PrivateKey, cert *x509.Certificate) {
	c.privateKey = key
	c.deviceCert = cert
}

func (c *Connection) GetConnection() net.Conn {
	return c.conn
}

func (c *Connection) GetCourierHostname() string {
	return c.courierHostname
}

func (c *Connection) GetToken() []byte {
	return c.token
}

func (c *Connection) Close() error {
	if c == nil {
		return nil
	}
	if conn := c.conn; conn != nil {
		return conn.Close()
	}
	return nil
}

func (c *Connection) SetSocksProxy(proxyUrl string) error {
	parsed, err := url.Parse(proxyUrl)
	if err != nil {
		return err
	}

	if parsed.Scheme != "socks5" {
		return errors.New("invalid proxy: not a socks5 URL")
	}

	c.socksProxyAddr = parsed.Hostname() + ":" + parsed.Port()

	password, _ := parsed.User.Password()
	c.socksProxyAuth = &proxy.Auth{
		User:     parsed.User.Username(),
		Password: password,
	}

	return nil
}

func (c *Connection) write(data []byte) error {
	conn := c.conn
	if conn == nil {
		return ErrNotConnectedToAPNS
	}
	_ = conn.SetWriteDeadline(time.Now().Add(1 * time.Minute))
	_, err := conn.Write(data)
	return err
}

func (c *Connection) Connect(ctx context.Context, root bool, token []byte) error {
	host, port, err := GetCourierHostPort(ctx)
	if err != nil {
		return fmt.Errorf("failed to get courier address: %w", err)
	}
	if c.CourierHostnameOverride != "" {
		host = c.CourierHostnameOverride
	}
	c.courierHostname = host

	tlsConfig := &tls.Config{
		ServerName: apnsCourierHostname,
		NextProtos: []string{"apns-security-v3"},
		RootCAs:    appletls.CertPool,
	}

	addr := fmt.Sprintf("%s:%d", host, port)

	if c.socksProxyAddr != "" {
		c.log.Info().
			Str("url", c.socksProxyAddr).
			Msg("Using SOCKS5 proxy for APNs")
		proxyDialer, err := proxy.SOCKS5("tcp", c.socksProxyAddr, c.socksProxyAuth, proxy.Direct)
		if err != nil {
			return err
		}
		conn, err := proxyDialer.Dial("tcp", addr)
		if err != nil {
			return err
		}
		c.conn = tls.Client(conn, tlsConfig)
	} else {
		dialer := &tls.Dialer{Config: tlsConfig}
		c.conn, err = dialer.DialContext(ctx, "tcp", addr)
		if err != nil {
			return err
		}
	}

	c.token = token
	flags := BaseConnectionFlags
	if root {
		flags |= RootConnection
	}

	nonce := nonce.Generate()
	nonce[0] = 0
	sum := sha1.Sum(nonce)
	signature, err := rsa.SignPKCS1v15(nil, c.privateKey, crypto.SHA1, sum[:])
	if err != nil {
		return err
	}
	payload, err := Marshal(&ConnectCommand{
		DeviceToken: token,
		State:       []byte{1},
		Flags:       flags,

		Cert:      c.deviceCert.Raw,
		Nonce:     nonce,
		Signature: append([]byte{0x1, 0x1}, signature...),
	})
	if err != nil {
		return err
	}
	return c.write(payload)
}

func (c *Connection) Filter(topics ...Topic) error {
	sha1Topics := make([][]byte, len(topics))
	for i, topic := range topics {
		hashed := sha1.Sum([]byte(topic))
		sha1Topics[i] = hashed[:]
	}
	payload, err := Marshal(&FilterTopicsCommand{
		Token:  c.token,
		Topics: sha1Topics,
	})
	if err != nil {
		return err
	}
	return c.write(payload)
}

var (
	ErrResponseChannelClosed = errors.New("response channel closed")
	ErrNilConnection         = errors.New("nil connection")
	ErrNotConnectedToAPNS    = errors.New("not connected to APNS")
)

type UnexpectedAPNSAckError struct {
	Code []byte
}

func (e *UnexpectedAPNSAckError) Error() string {
	return fmt.Sprintf("unexpected apns ack status: 0x%x", e.Code)
}

var (
	ErrAPNSAckTooLarge error = &UnexpectedAPNSAckError{Code: []byte{0x03}}
	ErrAPNSAckTooEarly error = &UnexpectedAPNSAckError{Code: []byte{0x80}}
)

func (e *UnexpectedAPNSAckError) Is(other error) bool {
	var otherAck *UnexpectedAPNSAckError
	if !errors.As(other, &otherAck) {
		return false
	}
	return bytes.Equal(e.Code, otherAck.Code)
}

func (c *Connection) SendMessage(topic Topic, payload, id []byte) error {
	if c == nil {
		return ErrNilConnection
	}
	if len(id) == 0 {
		id = random.Bytes(4)
	}
	retryCount := 0
	for {
		err := c.sendMessageNoRetry(topic, payload, id)
		if err == nil || retryCount >= 5 {
			return err
		} else if respErr := (&UnexpectedAPNSAckError{}); errors.As(err, &respErr) && !bytes.Equal(respErr.Code, []byte{0x80}) {
			// Code 0x80 seems to mean we sent data too early (before SetState/Filter), so just retry if that happens.
			// Don't retry other codes though, they might be more fatal errors (e.g. 0x03 happens for too long messages).
			return err
		}
		retryCount++
		sleepTime := time.Duration(retryCount*5) * time.Second
		c.log.Warn().
			Err(err).
			Dur("retry_in", sleepTime).
			Hex("message_id", id).
			Msg("Failed to send APNS message, retrying")
		time.Sleep(sleepTime)
	}
}

func (c *Connection) sendMessageNoRetry(topic Topic, payload, id []byte) error {
	hash := sha1.Sum([]byte(topic))
	sendMessageCommand := OutgoingSendMessageCommand{
		Topic:     hash[:],
		Token:     c.token,
		Payload:   payload,
		MessageID: id,
	}
	c.log.Trace().Any("cmd", sendMessageCommand).Msg("Sending message")
	payload, err := Marshal(&sendMessageCommand)
	if err != nil {
		return err
	}
	c.sendLock.Lock()
	defer c.sendLock.Unlock()
	ch := make(chan *SendMessageAckCommand, 1)
	c.sendAckWaiter = ch
	err = c.write(payload)
	if err != nil {
		return err
	}
	resp := <-ch
	if resp == nil {
		return ErrResponseChannelClosed
	}
	c.sendAckWaiter = nil
	if len(resp.NullByte) != 1 || resp.NullByte[0] != 0 {
		return &UnexpectedAPNSAckError{Code: resp.NullByte}
	}
	return nil
}

func (c *Connection) SetState(state uint8) error {
	payload, err := Marshal(&SetStateCommand{
		State:    state,
		FieldTwo: 0x7FFFFFFF,
	})
	if err != nil {
		return err
	}
	return c.write(payload)
}

func (c *Connection) SendAck(id []byte) {
	log := c.log.With().Str("message_id", base64.StdEncoding.EncodeToString(id)).Logger()
	payload, err := Marshal(&SendMessageAckCommand{
		Token:     c.token,
		MessageID: id,
		NullByte:  []byte{0},
	})
	if err != nil {
		log.Err(err).Msg("Failed to marshal ack for APNS message")
		return
	}
	err = c.write(payload)
	if err != nil {
		log.Err(err).Msg("Failed to send ack for APNS message")
	} else {
		log.Trace().Msg("Sent ack")
	}
}

func (c *Connection) flushQueue() error {
	payload, err := plist.Marshal(&SendMessagePayload{
		Command: MessageTypeFlushQueue,
	}, plist.BinaryFormat)
	if err != nil {
		return err
	}

	return c.SendMessage(TopicMadrid, payload, random.Bytes(4))
}

type readPayload struct {
	Payload

	err error
}

func (c *Connection) Run(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	readChan := make(chan *readPayload)
	messageChan := make(chan *SendMessagePayload, 128)
	var wg sync.WaitGroup
	wg.Add(2)

	const keepaliveRate = 1 * time.Minute

	go func() {
		defer wg.Done()
		conn := c.conn
		for {
			var p readPayload
			_ = conn.SetReadDeadline(time.Now().Add(keepaliveRate * 4))
			p.err = p.UnmarshalBinaryStream(conn)

			select {
			case readChan <- &p:
			case <-ctx.Done():
				close(readChan)
				return
			}

			if p.err != nil {
				close(readChan)
				return
			}
		}
	}()

	var filterAckReceived atomic.Bool
	go func() {
		defer wg.Done()
		handlerDoneChan := make(chan struct{})
		const handlerTickInterval = 10 * time.Second
		ticker := time.NewTicker(handlerTickInterval)
		defer ticker.Stop()
		for data := range messageChan {
			logWith := c.log.With().
				Uint32("apns_message_id", binary.BigEndian.Uint32(data.APNSMessageID)).
				Str("command", data.Command.String())
			if data.MessageUUID.IsValid() {
				logWith = logWith.Str("message_uuid", data.MessageUUID.String())
			}
			if data.Command == MessageTypeFlushQueue {
				filterAckReceived.Store(true)
			}
			log := logWith.Logger()
			go func() {
				defer func() {
					if err := recover(); err != nil {
						log.Error().
							Bytes(zerolog.ErrorStackFieldName, debug.Stack()).
							Interface(zerolog.ErrorFieldName, err).
							Msg("APNs message handler panicked")
					}
					handlerDoneChan <- struct{}{}
				}()
				if ack, err := c.MessageHandler(log.WithContext(ctx), data); err != nil {
					log.Err(err).Msg("Error in message handler")
				} else if ack {
					if c.NoAsyncWork {
						c.SendAck(data.APNSMessageID)
					} else {
						go c.SendAck(data.APNSMessageID)
					}
				}
			}()
			ticker.Reset(handlerTickInterval)
			// Flush the ticker so that we don't get a warning log if the previous message was over 10 seconds ago.
			select {
			case <-ticker.C:
			default:
			}
		Loop:
			for {
				select {
				case <-handlerDoneChan:
					break Loop
				case <-ticker.C:
					log.Warn().
						Bool("context_done", ctx.Err() != nil).
						Msg("Message is still being handled")
				}
			}
		}
	}()

	var err error
	keepaliveTicker := time.NewTicker(keepaliveRate)
	firstKeepalive := time.After(5 * time.Second)
	filterAckWaiter := time.After(10 * time.Second)
	lastRead := time.Now()
Loop:
	for {
		select {
		case p := <-readChan:
			if p == nil {
				if ctx.Err() != nil {
					err = ctx.Err()
				} else {
					err = fmt.Errorf("readChan closed unexpectedly")
				}
				break Loop
			}
			if p.err != nil {
				err = p.err
				break Loop
			}
			commandData, err := p.toStructAuto()
			if err != nil {
				c.log.Err(err).Msg("Failed to parse APNS command payload into struct")
				continue
			}
			if p.ID == CommandFilterTopicsAck {
				filterAckReceived.Store(true)
			}
			c.handlePayload(ctx, &p.Payload, commandData, messageChan)

			// track last time we got something over the socket and suppress keepalive
			lastRead = time.Now()
			keepaliveTicker.Reset(keepaliveRate)
		case <-ctx.Done():
			err = ctx.Err()
			break Loop
		case <-firstKeepalive:
			payload := Payload{ID: CommandKeepAlive}
			err = c.write(payload.ToBytes())
			if err != nil {
				c.log.Err(err).Msg("Failed to send first keepalive")
				break Loop
			}
			c.log.Debug().Msg("Sent first keepalive")
		case <-filterAckWaiter:
			if !filterAckReceived.Load() {
				c.log.Warn().Time("last_read", lastRead).Msg("Filter ack not received after 10 seconds")
			}
		case <-keepaliveTicker.C:
			if time.Since(lastRead) >= keepaliveRate*3 {
				c.log.Error().Msg("Keepalive timeout, disconnecting")
				break Loop
			}

			payload := Payload{ID: CommandKeepAlive}
			err = c.write(payload.ToBytes())
			if err != nil {
				c.log.Err(err).Msg("Failed to send keepalive")
				break Loop
			}
			c.log.Debug().Msg("Sent keepalive")
		}
	}
	cancel()

	if closeErr := c.Close(); closeErr != nil && !errors.Is(err, context.Canceled) {
		c.log.Warn().Err(err).Msg("Failed to close connection after loop returned")
	}
	keepaliveTicker.Stop()
	close(messageChan)
	wg.Wait()
	if c.sendAckWaiter != nil {
		close(c.sendAckWaiter)
		c.sendAckWaiter = nil
	}

	return err
}

func (c *Connection) handlePayload(ctx context.Context, p *Payload, commandData any, messageChan chan<- *SendMessagePayload) {
	switch p.ID {
	case CommandKeepAliveAck:
		c.log.Debug().Msg("Received keepalive ack")
	case CommandConnectAck:
		connectAckData := commandData.(*ConnectAckCommand)
		c.log.Info().Any("data", connectAckData).Msg("Received connect ack")
		if connectAckData.Token != nil {
			c.log.Info().Str("push_token", base64.StdEncoding.EncodeToString(connectAckData.Token)).Msg("Received new APNs token")
			c.token = connectAckData.Token
		}
		if !bytes.Equal(connectAckData.Status, []byte{0}) {
			c.log.Warn().Bytes("status", connectAckData.Status).Msg("Received non-zero connect ack status")
			go c.ConnectErrorHandler(ctx, connectAckData.Status)
			return
		}
		if connectAckData.MaxMessageSize != 0 {
			c.MaxMessageSize = int(connectAckData.MaxMessageSize)
		}
		if connectAckData.LargeMessageSize != 0 {
			c.MaxLargeMessageSize = int(connectAckData.LargeMessageSize)
		}
		go c.ConnectHandler(ctx)
	case CommandSendMessage:
		commandSendMessageData := commandData.(*IncomingSendMessageCommand)

		var topic Topic
		if len(commandSendMessageData.Topic) == 20 {
			topic = TopicHashMap[*(*[20]byte)(commandSendMessageData.Topic)]
		}
		if topic == TopicIDS {
			go c.SendAck(commandSendMessageData.MessageID)
			logEvt := c.log.Debug().
				Str("raw_bytes", base64.StdEncoding.EncodeToString(commandSendMessageData.Payload))
			if json.Valid(commandSendMessageData.Payload) {
				logEvt = logEvt.RawJSON("raw_json", commandSendMessageData.Payload)
			}
			logEvt.Msg("Received IDS message")
			return
		}

		// DEBUG
		var rawData map[string]any
		_, err := plist.Unmarshal(commandSendMessageData.Payload, &rawData)
		if err != nil {
			c.log.Warn().Err(err).Msg("Failed to parse raw message payload")
		} else {
			c.log.Trace().Any("raw", rawData).Msg("DEBUG: Parsed raw IDS payload")
		}
		// END DEBUG

		var data SendMessagePayload
		_, err = plist.Unmarshal(commandSendMessageData.Payload, &data)
		if err != nil {
			c.log.Err(err).Msg("Failed to parse struct message payload")
		}

		data.APNSTopic = topic
		data.APNSMessageID = commandSendMessageData.MessageID
		logEvt := c.log.Debug().
			Uint32("apns_message_id", binary.BigEndian.Uint32(data.APNSMessageID)).
			Str("command", data.Command.String())
		if data.MessageUUID.IsValid() {
			logEvt.Str("message_uuid", data.MessageUUID.String())
		}
		logEvt.Msg("Received APNS message")

		c.log.Trace().
			Any("parsed", data).
			Str("topic", string(data.APNSTopic)).
			Hex("topic_hash", commandSendMessageData.Topic).
			Msg("DEBUG: Parsed IDS payload into struct")
		// Only set this after logging to avoid spamming the logs while debugging things (the raw payload is logged separately earlier)
		data.Raw = commandSendMessageData.Payload

		if c.receiveResponse(&data) {
			go c.SendAck(data.APNSMessageID)
		} else {
			select {
			case messageChan <- &data:
			default:
				c.log.Warn().Msg("APNS message channel is full")
				if c.NoAsyncWork {
					messageChan <- &data
				} else {
					go func() {
						messageChan <- &data
					}()
				}
			}
		}

		if !c.NoAutoFlush && data.Command == MessageTypeFlushQueue {
			c.log.Info().Msg("Received c:160, flushing queue")
			go func() {
				if err := c.flushQueue(); err != nil {
					c.log.Warn().Err(err).Msg("Failed to flush queue from APNS")
				}
			}()
		}
	case CommandSendMessageAck:
		commandSendMessageAckData := commandData.(*SendMessageAckCommand)
		c.log.Info().Any("ack_data", commandSendMessageAckData).Msg("Received send message ack")
		if ch := c.sendAckWaiter; ch != nil {
			c.sendAckWaiter = nil
			select {
			case ch <- commandSendMessageAckData:
			default:
				c.log.Warn().Msg("Send ack channel didn't accept data")
			}
		} else {
			c.log.Warn().Msg("Received unexpected send message ack")
		}
	case CommandFilterTopicsAck:
		c.log.Info().Msg("Got filter topics ack with nothing in queue")
		if !c.NoAutoFlush {
			c.log.Info().Msg("Flushing queue anyway because APNS is sometimes weird")
			go func() {
				if err := c.flushQueue(); err != nil {
					c.log.Warn().Err(err).Msg("Failed to flush queue from APNS")
				}
			}()
		}
	default:
		c.log.Warn().Any("command_data", commandData).Uint8("command", uint8(p.ID)).Msg("Received unknown payload")
	}
}
