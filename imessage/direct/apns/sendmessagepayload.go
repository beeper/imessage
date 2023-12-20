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
	"fmt"

	"github.com/beeper/imessage/imessage/direct/ids/types"
	"github.com/beeper/imessage/imessage/direct/util/plisttime"
	"github.com/beeper/imessage/imessage/direct/util/plistuuid"
	"github.com/beeper/imessage/imessage/direct/util/uri"
)

type MessageType uint64

func (mt MessageType) MarshalJSON() ([]byte, error) {
	// This is only for nicer zerolog output
	return []byte(`"` + mt.String() + `"`), nil
}

func (mt MessageType) String() string {
	switch mt {
	case MessageTypeIDSReregister:
		return "IDSReregister"
	case MessageTypeIDSDevicesUpdated:
		return "IDSDevicesUpdated"
	case MessageTypeIDSHandlesUpdated:
		return "IDSHandlesUpdated"
	case MessageTypeIDSError:
		return "IDSError"
	case MessageTypeHTTPRequest:
		return "HTTPRequest"
	case MessageTypeHTTPResponse:
		return "HTTPResponse"
	case MessageTypeIMessage:
		return "IMessage"
	case MessageTypeDeliveryReceipt:
		return "DeliveryReceipt"
	case MessageTypeReadReceipt:
		return "ReadReceipt"
	case MessageTypeIMessageAsync:
		return "IMessageAsync"
	case MessageTypePlayedReceipt:
		return "PlayedReceipt"
	case MessageTypeSavedReceipt:
		return "SavedReceipt"
	case MessageTypeReflectedDelivery:
		return "ReflectedDelivery"
	case MessageTypeCertifiedDelivery:
		return "CertifiedDelivery"
	case MessageTypeMarkUnread:
		return "MarkUnread"
	case MessageTypeUnknown112:
		return "Unknown112"
	case MessageTypeUnknown116:
		return "Unknown116"
	case MessageTypeIMessageEdit:
		return "IMessageEdit"
	case MessageTypeDeliveryFailure:
		return "DeliveryFailure"
	case MessageTypePeerCacheInvalidate:
		return "PeerCacheInvalidate"
	case MessageTypeProfileShare:
		return "ProfileShare"
	case MessageTypeIncomingSMS:
		return "IncomingSMS"
	case MessageTypeIncomingMMS:
		return "IncomingMMS"
	case MessageTypeSMSEnableRequestCode:
		return "SMSEnableRequestCode"
	case MessageTypeReflectedSMS:
		return "ReflectedSMS"
	case MessageTypeReflectedMMS:
		return "ReflectedMMS"
	case MessageTypeSMSForwardingToggled:
		return "SMSForwardingToggled"
	case MessageTypeSMSSuccess:
		return "SMSSuccess"
	case MessageTypeSMSRead:
		return "SMSRead"
	case MessageTypeSMSFailed:
		return "SMSFailed"
	case MessageTypeMMCSUpload:
		return "MMCSUpload"
	case MessageTypeMMCSDownload:
		return "MMCSDownload"
	case MessageTypeFlushQueue:
		return "FlushQueue"
	case MessageTypeSettings:
		return "Settings"
	case MessageTypeDeleteSync:
		return "DeleteSync"
	case MessageTypeUndeleteSync:
		return "UndeleteSync"
	case MessageTypeIMessageGroupMeta:
		return "IMessageGroupMeta"
	case MessageTypeLinkPreviewEdit:
		return "LinkPreviewEdit"
	case MessageTypeIMessageAck:
		return "IMessageAck"
	default:
		return fmt.Sprintf("MessageType(%d)", mt)
	}
}

const (
	MessageTypeIDSReregister        MessageType = 32
	MessageTypeIDSDevicesUpdated    MessageType = 34
	MessageTypeIDSHandlesUpdated    MessageType = 66
	MessageTypeIDSError             MessageType = 92 // Sent via the IDS topic, contains at least iMessage activation error descriptions
	MessageTypeHTTPRequest          MessageType = 96
	MessageTypeHTTPResponse         MessageType = 97
	MessageTypeIMessage             MessageType = 100
	MessageTypeDeliveryReceipt      MessageType = 101
	MessageTypeReadReceipt          MessageType = 102
	MessageTypeIMessageAsync        MessageType = 104
	MessageTypePlayedReceipt        MessageType = 105
	MessageTypeSavedReceipt         MessageType = 106
	MessageTypeReflectedDelivery    MessageType = 107
	MessageTypeCertifiedDelivery    MessageType = 109
	MessageTypeMarkUnread           MessageType = 111
	MessageTypeUnknown112           MessageType = 112 // seen in the wild, haven't seen locally so no idea about the content
	MessageTypeUnknown116           MessageType = 116
	MessageTypeIMessageEdit         MessageType = 118
	MessageTypeDeliveryFailure      MessageType = 120
	MessageTypePeerCacheInvalidate  MessageType = 130
	MessageTypeProfileShare         MessageType = 131
	MessageTypeIncomingSMS          MessageType = 140
	MessageTypeIncomingMMS          MessageType = 141
	MessageTypeSMSEnableRequestCode MessageType = 142
	MessageTypeReflectedSMS         MessageType = 143
	MessageTypeReflectedMMS         MessageType = 144
	MessageTypeSMSForwardingToggled MessageType = 145
	MessageTypeSMSSuccess           MessageType = 146
	MessageTypeSMSRead              MessageType = 147
	MessageTypeSMSFailed            MessageType = 149
	MessageTypeMMCSUpload           MessageType = 150
	MessageTypeMMCSDownload         MessageType = 151
	MessageTypeFlushQueue           MessageType = 160 // officially known as OfflineMessagePendingStorageCheck
	MessageTypeSettings             MessageType = 180
	MessageTypeDeleteSync           MessageType = 181
	MessageTypeUndeleteSync         MessageType = 182
	MessageTypeIMessageGroupMeta    MessageType = 190
	MessageTypeLinkPreviewEdit      MessageType = 196
	MessageTypeIMessageAck          MessageType = 255
)

type EncryptionType string

const (
	EncryptionTypePair   EncryptionType = "pair"
	EncryptionTypePairEC EncryptionType = "pair-ec"
)

type IDSMessagePayload struct {
	Command MessageType `json:"c,omitempty"`
	Message string      `json:"m,omitempty"`
	Type    string      `json:"t,omitempty"`
}

type SendMessagePayload struct {
	Raw           []byte `plist:"-" json:"-"`
	APNSMessageID []byte `plist:"-" json:"-"`
	APNSTopic     Topic  `plist:"-" json:"-"`

	HTTPURL          string            `plist:"u,omitempty" json:",omitempty"`
	HTTPBody         []byte            `plist:"b,omitempty" json:",omitempty"`
	HTTPContentType  string            `plist:"cT,omitempty" json:",omitempty"`
	HTTPHeaders      map[string]string `plist:"h,omitempty" json:",omitempty"`
	HTTPStatus       int               `plist:"hs,omitempty" json:",omitempty"`
	HTTPErrorMessage string            `plist:"hr,omitempty" json:",omitempty"`
	ResponseStatus   types.IDSStatus   `plist:"s,omitempty" json:",omitempty"`

	MMCSOwnerID       string `plist:"mO,omitempty" json:",omitempty"`
	MMCSFileSignature []byte `plist:"mS,omitempty" json:",omitempty"`
	MMCSFileLength    int    `plist:"mL,omitempty" json:",omitempty"`
	MMCSAuthToken     string `plist:"mA,omitempty" json:",omitempty"`
	MMCSAuthURL       string `plist:"mR,omitempty" json:",omitempty"`
	MMCSAuthID        string `plist:"mU,omitempty" json:",omitempty"`

	ContentVersion int    `plist:"cV,omitempty" json:",omitempty"`
	ContentHeaders string `plist:"cH,omitempty" json:",omitempty"`
	ContentBody    []byte `plist:"cB,omitempty" json:",omitempty"`

	EncryptionType    EncryptionType      `plist:"E,omitempty" json:",omitempty"`
	Payload           []byte              `plist:"P,omitempty" json:",omitempty"`
	MessageID         uint32              `plist:"i,omitempty" json:",omitempty"`
	MessageUUID       plistuuid.ByteUUID  `plist:"U,omitempty" json:",omitempty"`
	Command           MessageType         `plist:"c,omitempty" json:",omitempty"`
	OriginalCommand   MessageType         `plist:"oC,omitempty" json:",omitempty"`
	Timestamp         *plisttime.UnixNano `plist:"e,omitempty" json:",omitempty"`
	IsTrustedSender   bool                `plist:"htu,omitempty" json:",omitempty"`
	SenderID          *uri.ParsedURI      `plist:"sP,omitempty" json:",omitempty"`
	Token             []byte              `plist:"t,omitempty" json:",omitempty"`
	SessionToken      []byte              `plist:"sT,omitempty" json:",omitempty"`
	DestinationID     *uri.ParsedURI      `plist:"tP,omitempty" json:",omitempty"`
	Version           int                 `plist:"v,omitempty" json:",omitempty"`
	DeliveryStatus    *bool               `plist:"D,omitempty" json:",omitempty"`
	ExpirationSeconds *int                `plist:"eX,omitempty" json:",omitempty"`
	NoResponseNeeded  *bool               `plist:"nr,omitempty" json:",omitempty"`

	CertifiedDeliveryVersion int    `plist:"cdv,omitempty" json:",omitempty"`
	CertifiedDeliveryRts     []byte `plist:"cdr,omitempty" json:",omitempty"`

	UserAgent string `plist:"ua,omitempty" json:",omitempty"`

	FanoutChunkNumber int `plist:"fcn,omitempty" json:",omitempty"`

	DTL []SendMessagePayload `plist:"dtl,omitempty" json:",omitempty"` // dstIdTokenList?

	// Failures
	FailText                   string              `plist:"aDI,omitempty" json:",omitempty"` // uncertain
	FailReason                 int                 `plist:"fR,omitempty" json:",omitempty"`
	FailMessageID              *plistuuid.ByteUUID `plist:"fU,omitempty" json:",omitempty"`
	FailMessageIDString        *plistuuid.UUID     `plist:"fM,omitempty" json:",omitempty"`
	FailReasonMessage          string              `plist:"fRM,omitempty" json:",omitempty"`
	FailDownloadAttachmentSize int                 `plist:"fFS,omitempty" json:",omitempty"`
	FailUploadAttachmentSize   int                 `plist:"fS,omitempty" json:",omitempty"`
	//FailTimeElapsed            any                 `plist:"fT,omitempty" json:",omitempty"`
}
