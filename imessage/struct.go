// beeper-imessage - A Matrix-iMessage puppeting bridge.
// Copyright (C) 2022 Tulir Asokan
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

package imessage

import (
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/beeper/imessage/imessage/direct/ids"
	"github.com/beeper/imessage/imessage/direct/util/uri"
)

type IMessageWithSender interface {
	GetSender() uri.ParsedURI
	GetIsFromMe() bool
}

type MessagePartInfo struct {
	PartID     int `json:"part_id"`
	StartIndex int `json:"start_idx"`
	Length     int `json:"length"`
}

type GroupInfoChange struct {
	ID                uuid.UUID
	PropertiesVersion int

	GroupID  string
	Chat     uri.ParsedURI
	Sender   uri.ParsedURI
	IsFromMe bool
	Time     time.Time

	OldName string
	NewName string

	RemoveAvatar           bool
	AvatarFileTransferGUID *string
	NewAvatar              *ids.AttachmentDownloader

	OldParticipants []uri.ParsedURI
	NewParticipants []uri.ParsedURI
}

type ChatDeleted struct {
	Chat uri.ParsedURI
}

type MarkUnread struct {
	MessageID uuid.UUID
}

func (g *GroupInfoChange) GetSender() uri.ParsedURI {
	return g.Sender
}

func (g *GroupInfoChange) GetIsFromMe() bool {
	return g.IsFromMe
}

type ParsedThreadRoot struct {
	MessagePartInfo
	ID uuid.UUID `json:"uuid"`
}

func (ptr ParsedThreadRoot) String() string {
	return fmt.Sprintf("r:%d:%d:%d:%s", ptr.PartID, ptr.StartIndex, ptr.Length, strings.ToUpper(ptr.ID.String()))
}

func ParseThreadRoot(tr string) (ptr ParsedThreadRoot, err error) {
	var id string
	_, err = fmt.Sscanf(tr, "r:%d:%d:%d:%s", &ptr.PartID, &ptr.StartIndex, &ptr.Length, &id)
	if err != nil {
		return
	}
	ptr.ID, err = uuid.Parse(id)
	return
}

type Message struct {
	GroupID  string           `json:"group_id,omitempty"`
	ID       uuid.UUID        `json:"id"`
	Time     time.Time        `json:"-"`
	Subject  string           `json:"subject"`
	Text     string           `json:"text"`
	HTML     string           `json:"html"`
	TextPart *MessagePartInfo `json:"text_part"`
	Chat     uri.ParsedURI    `json:"chat"`
	Sender   uri.ParsedURI    `json:"-"`

	EffectID string `json:"-"`

	Receiver uri.ParsedURI `json:"-"`

	Service Service `json:"service"`

	IsFromMe       bool `json:"is_from_me"`
	IsAudioMessage bool `json:"is_audio_message"`

	ThreadRoot *ParsedThreadRoot `json:"thread_originator,omitempty"`
	Tapback    *Tapback          `json:"associated_message,omitempty"`

	Attachments []*Attachment `json:"attachments,omitempty"`

	GroupName    string
	Participants []uri.ParsedURI `json:"participants,omitempty"`

	RichLink *RichLinkMetadata `json:"rich_link,omitempty"`
}

func (m *Message) GetIsFromMe() bool {
	return m.IsFromMe
}

func (m *Message) GetSender() uri.ParsedURI {
	return m.Sender
}

func (msg *Message) SenderText() string {
	if msg.IsFromMe {
		return "self"
	}
	return msg.Sender.Identifier
}

type MessagePart struct {
	PartIdx int    `xml:"message-part,attr"`
	Value   string `xml:",innerxml"`
}

type MessageEdit struct {
	Sender        uri.ParsedURI
	IsFromMe      bool
	Timestamp     time.Time
	EditMessageID uuid.UUID
	EditPartIndex int
	Text          string
	EditID        uuid.UUID
	RichLink      *RichLinkMetadata
}

func (m *MessageEdit) GetIsFromMe() bool {
	return m.IsFromMe
}

func (m *MessageEdit) GetSender() uri.ParsedURI {
	return m.Sender
}

type MessageUnsend struct {
	Sender          uri.ParsedURI
	IsFromMe        bool
	Timestamp       time.Time
	UnsendMessageID uuid.UUID
	UnsendPartIndex int
	UnsendID        uuid.UUID
}

func (m *MessageUnsend) GetIsFromMe() bool {
	return m.IsFromMe
}

func (m *MessageUnsend) GetSender() uri.ParsedURI {
	return m.Sender
}

type GroupActionType int

const (
	GroupActionAddUser    GroupActionType = 0
	GroupActionRemoveUser GroupActionType = 1

	GroupActionSetAvatar    GroupActionType = 1
	GroupActionRemoveAvatar GroupActionType = 2
)

type ItemType int

const (
	ItemTypeMessage ItemType = iota
	ItemTypeMember
	ItemTypeName
	ItemTypeAvatar
)

type Contact struct {
	FirstName string   `json:"first_name,omitempty"`
	LastName  string   `json:"last_name,omitempty"`
	Nickname  string   `json:"nickname,omitempty"`
	Avatar    []byte   `json:"avatar,omitempty"`
	Phones    []string `json:"phones,omitempty"`
	Emails    []string `json:"emails,omitempty"`
	UserGUID  string   `json:"user_guid,omitempty"`

	PrimaryIdentifier string `json:"primary_identifier,omitempty"`
}

func (contact *Contact) HasName() bool {
	return contact != nil && (len(contact.FirstName) > 0 || len(contact.LastName) > 0 || len(contact.Nickname) > 0)
}

func (contact *Contact) Name() string {
	if contact == nil {
		return ""
	}
	if len(contact.FirstName) > 0 {
		if len(contact.LastName) > 0 {
			return fmt.Sprintf("%s %s", contact.FirstName, contact.LastName)
		} else {
			return contact.FirstName
		}
	} else if len(contact.LastName) > 0 {
		return contact.LastName
	} else if len(contact.Nickname) > 0 {
		return contact.Nickname
	} else if len(contact.Emails) > 0 {
		return contact.Emails[0]
	} else if len(contact.Phones) > 0 {
		return contact.Phones[0]
	}
	return ""
}

type Attachment struct {
	PartInfo   MessagePartInfo
	Downloader *ids.AttachmentDownloader
	InlineData []byte
	FileSize   int
	FileName   string
	MimeType   string
	UTIType    string
}

type ChatIdentifier struct {
	ChatGUID string `json:"chat_guid"`
	GroupID  string `json:"group_id,omitempty"`
}

type ChatInfo struct {
	JSONChatGUID string `json:"chat_guid"`
	Identifier   `json:"-"`
	DisplayName  string    `json:"title"`
	Members      []string  `json:"members"`
	NoCreateRoom bool      `json:"no_create_room"`
	GroupID      uuid.UUID `json:"group_id,omitempty"`
	Delete       bool      `json:"delete,omitempty"`
}

type Service string

const (
	ServiceIMessage Service = "iMessage"
	ServiceSMS      Service = "SMS"
)

func (s Service) String() string {
	return string(s)
}

type Identifier struct {
	LocalID string
	Service string

	IsGroup bool
}

func ParseIdentifier(guid string) Identifier {
	if len(guid) == 0 {
		return Identifier{}
	}
	parts := strings.Split(guid, ";")
	return Identifier{
		Service: parts[0],
		IsGroup: parts[1] == "+",
		LocalID: parts[2],
	}
}

func (id Identifier) String() string {
	if len(id.LocalID) == 0 {
		return ""
	}
	typeChar := '-'
	if id.IsGroup {
		typeChar = '+'
	}
	return fmt.Sprintf("%s;%c;%s", id.Service, typeChar, id.LocalID)
}

type RichLinkAsset struct {
	MimeType string               `json:"mime_type,omitempty"`
	Source   *RichLinkAssetSource `json:"source,omitempty"`
	Size     *RichLinkAssetSize   `json:"size,omitempty"`
}

type RichLinkAssetSource struct {
	URL  string `json:"url,omitempty"`
	Data []byte `json:"data,omitempty"`
}

type RichLinkAssetSize struct {
	Width  int `json:"width"`
	Height int `json:"height"`
}

type RichLinkMetadata struct {
	OriginalURL  string         `json:"original_url,omitempty"`
	URL          string         `json:"url,omitempty"`
	Title        string         `json:"title,omitempty"`
	Summary      string         `json:"summary,omitempty"`
	SelectedText string         `json:"selected_text,omitempty"`
	ItemType     string         `json:"item_type,omitempty"`
	Icon         *RichLinkAsset `json:"icon,omitempty"`
	Image        *RichLinkAsset `json:"image,omitempty"`
}

type SendMessageStatus struct {
	GUID       uuid.UUID
	Sender     uri.ParsedURI
	Status     string
	Service    Service
	Message    string
	StatusCode string
	Timestamp  time.Time
}

type ReadReceipt struct {
	Sender   uri.ParsedURI
	IsFromMe bool
	ReadUpTo uuid.UUID
	ReadAt   time.Time
}

type TypingNotification struct {
	Chat   uri.ParsedURI `json:"chat_guid"`
	Typing bool          `json:"typing"`
}
