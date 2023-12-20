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
	"encoding/xml"
	"fmt"
	"time"
	"unicode/utf16"

	"github.com/beeper/imessage/imessage"
	"github.com/beeper/imessage/imessage/direct/util/plisttime"
	"github.com/beeper/imessage/imessage/direct/util/plistuuid"
	"github.com/beeper/imessage/imessage/direct/util/uri"
)

type BaloonPayloadDownloadInfo struct {
	DecryptionKey []byte `plist:"e"`
	FileSize      int    `plist:"f"`
	MMCSOwner     string `plist:"o"`
	MMCSURL       string `plist:"r"`
	MMCSSignature []byte `plist:"s"`
}

type EffectID string

// Screen effects
const (
	EffectEcho          EffectID = "com.apple.messages.effect.CKEchoEffect"
	EffectSpotlight     EffectID = "com.apple.messages.effect.CKSpotlightEffect"
	EffectBalloons      EffectID = "com.apple.messages.effect.CKHappyBirthdayEffect"
	EffectConfetti      EffectID = "com.apple.messages.effect.CKConfettiEffect"
	EffectLove          EffectID = "com.apple.messages.effect.CKHeartEffect"
	EffectLasers        EffectID = "com.apple.messages.effect.CKLasersEffect"
	EffectFireworks     EffectID = "com.apple.messages.effect.CKFireworksEffect"
	EffectCelebration   EffectID = "com.apple.messages.effect.CKSparklesEffect"
	EffectShootingStars EffectID = "com.apple.messages.effect.CKShootingStarEffect"
)

// Bubble effects
const (
	EffectSlam         EffectID = "com.apple.MobileSMS.expressivesend.impact"
	EffectLoud         EffectID = "com.apple.MobileSMS.expressivesend.loud"
	EffectGentle       EffectID = "com.apple.MobileSMS.expressivesend.gentle"
	EffectInvisibleInk EffectID = "com.apple.MobileSMS.expressivesend.invisibleink"
)

func (ei EffectID) IsValid() bool {
	switch ei {
	case EffectEcho, EffectSpotlight, EffectBalloons, EffectConfetti, EffectLove,
		EffectLasers, EffectFireworks, EffectCelebration, EffectShootingStars,
		EffectSlam, EffectLoud, EffectGentle, EffectInvisibleInk:
		return true
	default:
		return false
	}
}

type BalloonID string

const (
	BalloonURL     BalloonID = "com.apple.messages.URLBalloonProvider"
	BalloonYouTube BalloonID = "com.apple.messages.MSMessageExtensionBalloonPlugin:EQHXZ8M8AV:com.google.ios.youtube.MessagesExtension"
)

type AMSummaryInfo struct {
	ContentType AMContentType `plist:"amc"`
	// When type is text, the quoted text. When type is custom, the type of message.
	SourceText string `plist:"ams,omitempty"`
	// Balloon type when type is custom and target is a balloon provider thing
	BalloonType string `plist:"amb,omitempty"`
}

type AMContentType int

const (
	AMContentTypeAttachment   AMContentType = 0
	AMContentTypeText         AMContentType = 1
	AMContentTypeAudioMessage AMContentType = 2
	AMContentTypeImage        AMContentType = 3
	AMContentTypeContact      AMContentType = 4
	AMContentTypeEvent        AMContentType = 5
	AMContentTypeLocation     AMContentType = 6
	AMContentTypeMovie        AMContentType = 7
	AMContentTypeWalletPass   AMContentType = 8
	AMContentTypeCustom       AMContentType = 9
)

func (ams *AMSummaryInfo) String() string {
	switch ams.ContentType {
	case AMContentTypeAttachment:
		return "an attachment"
	case AMContentTypeText:
		return fmt.Sprintf("“%s”", ams.SourceText)
	case AMContentTypeAudioMessage:
		return "an audio message"
	case AMContentTypeImage:
		return "an image"
	case AMContentTypeContact:
		return "a contact"
	case AMContentTypeEvent:
		return "an event"
	case AMContentTypeLocation:
		return "a location"
	case AMContentTypeMovie:
		return "a movie"
	case AMContentTypeWalletPass:
		return "a wallet pass"
	case AMContentTypeCustom:
		return ams.SourceText
	default:
		return "an attachment"
	}
}

func TextLen(text string) int {
	return len(utf16.Encode([]rune(text)))
}

const CurrentGroupVersion = "8"
const CurrentProtocolVersion = "1"

type IMessage struct {
	AttachmentCount int `plist:"-" json:"-"`

	Subject      string          `plist:"s,omitempty" json:",omitempty"`
	Text         string          `plist:"t"`
	XML          string          `plist:"x,omitempty" json:",omitempty"`
	Participants []uri.ParsedURI `plist:"p"`

	// Message ID, this should be the same as MessageUUID in the apns.SendMessagePayload
	// (but that one is encoded as a big endian integer)
	PreviousMessageID *plistuuid.UUID `plist:"r,omitempty"`

	GroupID  string   `plist:"gid,omitempty"`
	EffectID EffectID `plist:"iid,omitempty" json:",omitempty"`

	// This seems to be a base64-encoded gzipped NSKeyedArchiver plist (related to attachments?)
	ATI []byte `plist:"ati,omitempty" json:",omitempty"`

	// Tapback type as per imessage/tapback.go
	TapbackType int `plist:"amt,omitempty" json:",omitempty"`
	// This is formatted as p:0/UUID where 0 is the same as amrlc and UUID is the message ID (tapbacks don't have their own ids)
	TapbackTargetFullID     string `plist:"amk,omitempty" json:",omitempty"`
	TapbackTargetStartIndex *int   `plist:"amrlc,omitempty" json:",omitempty"`
	TapbackTargetLength     int    `plist:"amrln,omitempty" json:",omitempty"`
	// base64-encoded plist that contains "ams" with the original message that was tapbacked? (also amc: 1)
	// but sometimes not base64-encoded, maybe when sending from mac?
	TapbackMessageSummaryInfo []byte `plist:"msi,omitempty" json:",omitempty"`

	// See ParsedThreadRoot for the format
	ThreadRoot string `plist:"tg,omitempty" json:",omitempty"`

	GroupName string `plist:"n,omitempty" json:",omitempty"`

	BalloonID      BalloonID                  `plist:"bid,omitempty" json:",omitempty"`
	BalloonPayload []byte                     `plist:"bp,omitempty" json:",omitempty"`
	BalloonInfo    *BaloonPayloadDownloadInfo `plist:"bpdi,omitempty" json:",omitempty"`

	// Inline Attachments
	InlineAttachment0 []byte `plist:"ia-0,omitempty" json:",omitempty"`

	GroupVersion      string `plist:"gv,omitempty" json:",omitempty"` // always "8"?
	PropertiesVersion int    `plist:"pv" json:",omitempty"`           // 0 for DM, 1 for group?
	ProtocolVersion   string `plist:"v,omitempty" json:",omitempty"`  // always "1"?
	Arc               string `plist:"arc,omitempty" json:",omitempty"`
	Are               string `plist:"are,omitempty" json:",omitempty"`

	// These two seem to be present in profile shares and location shares too?
	// They're base64 strings and/or raw bytes
	//CloudKitDecryptionRecordKey string `plist:"CloudKitDecryptionRecordKey,omitempty" json:",omitempty"`
	//CloudKitRecordKey           string `plist:"CloudKitRecordKey,omitempty" json:",omitempty"`

	IsAudioMessage      bool `plist:"a,omitempty" json:",omitempty"`
	AudioMessageExpires bool `plist:"e,omitempty" json:",omitempty"`

	GPRU *plisttime.UnixNano `plist:"gpru,omitempty" json:",omitempty"`
}

func (im *IMessage) GetInlineAttachment(name string) []byte {
	// TODO other inline attachments
	if name == "ia-0" {
		return im.InlineAttachment0
	}
	return nil
}

type SMSChunk struct {
	Data []byte `plist:"data"`
	Type string `plist:"type"`

	// Only for MMS
	ContentLocation string `plist:"content-location,omitempty"`
	// Same as ContentLocation, but wrapped in < >?
	ContentID string `plist:"content-id,omitempty"`
}

type SMSRecipient struct {
	IntlPhone string `plist:"id"`
	// Local phone number, relative to own country code
	// If the phone is not in the same country, this is the same as IntlPhone
	LocalPhone string `plist:"uID,omitempty"`
	// Own country code
	CountryCode string `plist:"n,omitempty"`
}

type AsyncMessage struct {
	ObjectID     string `plist:"mmcs-owner"`
	SignatureHex string `plist:"mmcs-signature-hex"`
	DownloadURL  string `plist:"mmcs-url"`
}

type IncomingMMS struct {
	EncryptionKey []byte `plist:"eK"`
	OFS           int    `plist:"oFS"`
	ObjectID      string `plist:"oID"`
	DownloadURL   string `plist:"rUS"`
	Signature     []byte `plist:"sg"`
}

type SMS struct {
	Receiver    string         `plist:"co"`
	Sender      string         `plist:"h"`
	MessageUUID plistuuid.UUID `plist:"g"`
	Timestamp   time.Time      `plist:"w"`
	Content     []SMSChunk     `plist:"k"`

	// Only for MMS
	Subject     string   `plist:"a"`
	ContentType string   `plist:"b"`
	Recipients  []string `plist:"re"` // list of recipient phone numbers for MMS

	SC  int            `plist:"_sc"`  // 0
	SSC int            `plist:"_ssc"` // 0
	CS  plistuuid.UUID `plist:"cs"`   // not present?
	IC  int            `plist:"ic"`   // not present?
	L   int            `plist:"l"`    // 0
	M   string         `plist:"m"`    // "sms" or "mms"
	N   string         `plist:"n"`    // always "244"?
	R   bool           `plist:"r"`    // true
	SV  string         `plist:"sV"`   // 1
}

type ReflectedSMSData struct {
	GUID plistuuid.UUID `plist:"guid"`
	// International phone number
	Handle              string          `plist:"handle"`
	PlainBody           string          `plist:"plain-body"`
	Subject             string          `plist:"subject,omitempty"`
	XHTML               string          `plist:"xhtml,omitempty"`
	PreviousMessageGUID *plistuuid.UUID `plist:"replyToGUID,omitempty"`
	Service             string          `plist:"service"` // "SMS"
	SV                  string          `plist:"sV"`      // "1"
}

type ReflectedSMS struct {
	ChatStyle  string           `plist:"chat-style"` // "im" for DMs and "chat" for group chats?
	Recipients []SMSRecipient   `plist:"re"`
	Data       ReflectedSMSData `plist:"mD"`

	FR bool `plist:"fR,omitempty"` // true
	IC int  `plist:"ic"`           // 0
}

func (im *ReflectedSMS) GetInlineAttachment(name string) []byte {
	// TODO do reflected smses have inline attachments?
	return nil
}

type SMSOutgoingStatus struct {
	GUID plistuuid.UUID `plist:"g"`
}

type IMFileTransferLocalUserInfoKey struct {
	DecryptionKey    string `plist:"decryption-key"`
	FileSize         string `plist:"file-size"`
	MMCSOwner        string `plist:"mmcs-owner"`
	MMCSSignatureHex string `plist:"mmcs-signature-hex"`
	MMCSURL          string `plist:"mmcs-url"`

	//RefreshDate time.Time `plist:"refresh-date"`
}

type IMFileTransfer struct {
	IMFileTransferCreatedDate float64 `plist:"IMFileTransferCreatedDate"`
	IMFileTransferFilenameKey string  `plist:"IMFileTransferFilenameKey"`
	// at_0_GUID
	IMFileTransferGUID             string                         `plist:"IMFileTransferGUID"`
	IMFileTransferLocalUserInfoKey IMFileTransferLocalUserInfoKey `plist:"IMFileTransferLocalUserInfoKey"`
	IMFileTransferMessageGUID      *plistuuid.UUID                `plist:"IMFileTransferMessageGUID"`
}

type GroupMetaChangeType string

const (
	GroupMetaChangeName         GroupMetaChangeType = "n"
	GroupMetaChangeAvatar       GroupMetaChangeType = "v"
	GroupMetaChangeParticipants GroupMetaChangeType = "p"
	GroupMetaChangeVR           GroupMetaChangeType = "vr" // ???
)

type IMessageGroupMetaChange struct {
	GroupID           string              `plist:"gid,omitempty"`
	GroupVersion      string              `plist:"gv,omitempty" json:",omitempty"`
	PropertiesVersion int                 `plist:"pv" json:",omitempty"` // 1 for pictures, not there for group names?
	Type              GroupMetaChangeType `plist:"type,omitempty" json:",omitempty"`

	NewGroupAvatar *IMFileTransfer `plist:"tv,omitempty" json:",omitempty"`

	Participants       []string `plist:"sp"`
	TargetParticipants []string `plist:"tp,omitempty" json:",omitempty"`

	GroupName    string `plist:"n,omitempty" json:",omitempty"`
	NewGroupName string `plist:"nn,omitempty" json:",omitempty"`
	OldGroupName string `plist:"old,omitempty" json:",omitempty"`
}

type BalloonPayload struct {
	Attachments [][]byte `plist:"__attachments__"`
	Payload     []byte   `plist:"__payload__"`
}

type EditType int

const (
	EditTypeEdit   EditType = 1
	EditTypeUnsend EditType = 2
)

func (et EditType) String() string {
	switch et {
	case EditTypeEdit:
		return "Edit"
	case EditTypeUnsend:
		return "Unsend"
	default:
		return fmt.Sprintf("EditType(%d)", et)
	}
}

type IMessageEdit struct {
	EditMessageID   plistuuid.UUID `plist:"emg"`
	EditXML         string         `plist:"epb,omitempty"`
	EditPartIndex   int            `plist:"epi"`          // Part being edited or unsent. Can be -1 if unsending the subject part.
	EditType        EditType       `plist:"et"`           // 1 for edit, 2 for unsend?
	RS              bool           `plist:"rs,omitempty"` // true for unsend, omit for edit?
	ProtocolVersion string         `plist:"v"`            // "1"
}

// IMessageEditDetails should only be used for encoding edit XML.
type IMessageEditDetails struct {
	XMLName xml.Name               `xml:"html"`
	Edits   []imessage.MessagePart `xml:"body>span"`
}

type SMSForwardingEnableRequestCode struct {
	Code int `plist:"ak"`
}

type SMSForwardingToggled struct {
	// enabled successfully? -> {"ar": true, "wc": false}
	// after canceling enable? -> {"ar": false, "wc": true}
	// sometimes the above also happens after successfully enabling???
	// clicking enable with the wrong code? -> {"ar": false, "wc": false}
	// disabled -> {"ue": true}

	AR bool `plist:"ar"`
	WC bool `plist:"wc"`

	UE bool `plist:"ue"`

	UD bool            `plist:"ud"`
	G  *plistuuid.UUID `plist:"g"`
}

type DeletedChat struct {
	GroupID plistuuid.UUID `plist:"groupID"`
	GUID    string         `plist:"guid"` // This is a legacy style iMessage;-; identifier

	WasReportedAsJunk bool `plist:"wasReportedAsJunk,omitempty"`
}

type KeepMessagesConfig struct {
	ID              int  `plist:"ID"`
	Days            int  `plist:"days"`
	ResetPreference bool `plist:"resetPreference"`
}

type DeleteSync struct {
	IsPermanentDelete     bool             `plist:"isPermanentDelete,omitempty"`
	RecoverableDeleteDate time.Time        `plist:"recoverableDeleteDate,omitempty"`
	Message               []plistuuid.UUID `plist:"message,omitempty"`
	Chat                  []DeletedChat    `plist:"chat,omitempty"`

	PermanentChatMeta []DeletedChat `plist:"permanentDeleteChatMetadataArray,omitempty"`

	KeepMessages *KeepMessagesConfig `plist:"KeepMessages,omitempty"`
}

type UndeleteSync struct {
	Chat []DeletedChat `plist:"recoverChatMetadataArray,omitempty"`
}

type SettingValue struct {
	ReadReceipts       bool `plist:"gR,omitempty" json:",omitempty"` // true -> send read receipts, false -> don't
	ReadReceiptVersion int  `plist:"gV,omitempty" json:",omitempty"` // number of times the setting has been toggled

	ChatReadReceipts       bool `plist:"eR,omitempty" json:",omitempty"`
	ChatReadReceiptVersion int  `plist:"vR,omitempty" json:",omitempty"`

	ProfileSharedVersion   int      `plist:"nBWV,omitempty" json:",omitempty"`
	ProfileSharedWhitelist []string `plist:"nWL,omitempty" json:",omitempty"`
	ProfileSharedBlacklist []string `plist:"nBL,omitempty" json:",omitempty"` // uncertain
}

type SettingsCode int

const (
	SettingsCodeReadReceiptsEnabled    SettingsCode = 60001
	SettingsCodeProfileSharedWithUsers SettingsCode = 70000
)

type Settings struct {
	// These same fields also seem to be in the unencrypted body? not sure if the encrypted or unencrypted body is better

	SettingID SettingsCode `plist:"gC"`
	Value     SettingValue `plist:"pID"`

	// When toggling per-chat settings, like read receipts, this is the chat GUID
	ChatGUID string `plist:"cID"` // This is a legacy style iMessage;-; identifier
}

type MarkUnread struct {
	MessageID plistuuid.UUID `plist:"uG"`
}
