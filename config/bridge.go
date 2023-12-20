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

package config

import (
	"bytes"
	"errors"
	"strings"
	"text/template"

	"maunium.net/go/mautrix/bridge/bridgeconfig"
	"maunium.net/go/mautrix/id"
)

type BridgeConfig struct {
	UsernameTemplate    string `yaml:"username_template"`
	DisplaynameTemplate string `yaml:"displayname_template"`

	NACValidationDataURL   string `yaml:"nac_validation_data_url"`
	NACValidationDataToken string `yaml:"nac_validation_data_token"`
	NACValidationIsRelay   bool   `yaml:"nac_validation_is_relay"`

	DoublePuppetConfig bridgeconfig.DoublePuppetConfig `yaml:",inline"`

	PersonalFilteringSpaces  bool   `yaml:"personal_filtering_spaces"`
	DeliveryReceipts         bool   `yaml:"delivery_receipts"`
	MessageStatusEvents      bool   `yaml:"message_status_events"`
	SendErrorNotices         bool   `yaml:"send_error_notices"`
	EnableBridgeNotices      bool   `yaml:"enable_bridge_notices"`
	UnimportantBridgeNotices bool   `yaml:"unimportant_bridge_notices"`
	MaxHandleSeconds         int    `yaml:"max_handle_seconds"`
	ConvertHEIF              bool   `yaml:"convert_heif"`
	ConvertTIFF              bool   `yaml:"convert_tiff"`
	ConvertMOV               bool   `yaml:"convert_mov"`
	CommandPrefix            string `yaml:"command_prefix"`
	FederateRooms            bool   `yaml:"federate_rooms"`
	PrivateChatPortalMeta    string `yaml:"private_chat_portal_meta"`
	MatrixThreads            bool   `yaml:"matrix_threads"`

	Encryption bridgeconfig.EncryptionConfig `yaml:"encryption"`

	Provisioning struct {
		Prefix         string `yaml:"prefix"`
		SharedSecret   string `yaml:"shared_secret"`
		DebugEndpoints bool   `yaml:"debug_endpoints"`
	} `yaml:"provisioning"`

	Permissions bridgeconfig.PermissionConfig `yaml:"permissions"`

	usernameTemplate    *template.Template `yaml:"-"`
	displaynameTemplate *template.Template `yaml:"-"`
}

func (bc BridgeConfig) GetDoublePuppetConfig() bridgeconfig.DoublePuppetConfig {
	return bc.DoublePuppetConfig
}

func (bc BridgeConfig) GetResendBridgeInfo() bool {
	return false
}

func (bc BridgeConfig) GetManagementRoomTexts() bridgeconfig.ManagementRoomTexts {
	return bridgeconfig.ManagementRoomTexts{
		Welcome:            "Hello, I'm an iMessage bridge bot.",
		WelcomeConnected:   "Use `help` for help.",
		WelcomeUnconnected: "",
		AdditionalHelp:     "",
	}
}

func boolToInt(val bool) int {
	if val {
		return 1
	}
	return 0
}

func (bc BridgeConfig) Validate() error {
	_, hasExampleDomain := bc.Permissions["example.com"]
	_, hasExampleUser := bc.Permissions["@admin:example.com"]
	exampleLen := boolToInt(hasExampleUser) + boolToInt(hasExampleDomain)
	if len(bc.Permissions) == 0 || len(bc.Permissions) <= exampleLen {
		return errors.New("bridge.permissions not configured")
	}
	return nil
}

func (bc BridgeConfig) GetEncryptionConfig() bridgeconfig.EncryptionConfig {
	return bc.Encryption
}

func (bc BridgeConfig) EnableMessageStatusEvents() bool {
	return bc.MessageStatusEvents
}

func (bc BridgeConfig) EnableMessageErrorNotices() bool {
	return bc.SendErrorNotices
}

func (bc BridgeConfig) GetCommandPrefix() string {
	return bc.CommandPrefix
}

type umBridgeConfig BridgeConfig

func (bc *BridgeConfig) UnmarshalYAML(unmarshal func(interface{}) error) error {
	err := unmarshal((*umBridgeConfig)(bc))
	if err != nil {
		return err
	}

	bc.usernameTemplate, err = template.New("username").Parse(bc.UsernameTemplate)
	if err != nil {
		return err
	}

	bc.displaynameTemplate, err = template.New("displayname").Parse(bc.DisplaynameTemplate)
	if err != nil {
		return err
	}

	return nil
}

type UsernameTemplateArgs struct {
	UserID id.UserID
}

func (bc BridgeConfig) FormatDisplayname(name string) string {
	var buf strings.Builder
	_ = bc.displaynameTemplate.Execute(&buf, name)
	return buf.String()
}

func (bc BridgeConfig) FormatUsername(username string) string {
	var buf bytes.Buffer
	_ = bc.usernameTemplate.Execute(&buf, username)
	return buf.String()
}
