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

package ids

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/beeper/imessage/imessage/direct/util/ec"
	"github.com/beeper/imessage/imessage/direct/util/uri"
)

type SMSForwarding struct {
	Token  []byte        `json:"token"`
	Handle uri.ParsedURI `json:"handle"`
}

func (sf *SMSForwarding) GetHandle() uri.ParsedURI {
	if sf == nil {
		return uri.EmptyURI
	}
	return sf.Handle
}

func (sf *SMSForwarding) GetToken() []byte {
	if sf == nil {
		return nil
	}
	return sf.Token
}

type Versions struct {
	HardwareVersion string `json:"hardware_version"`
	SoftwareName    string `json:"software_name"`
	SoftwareVersion string `json:"software_version"`
	SoftwareBuildID string `json:"software_build_id"`
	SerialNumber    string `json:"serial_number,omitempty"`
	UniqueDeviceID  string `json:"unique_device_id,omitempty"`
}

func (v *Versions) MarshalZerologObject(e *zerolog.Event) {
	e.Str("hardware_version", v.HardwareVersion).
		Str("software_name", v.SoftwareName).
		Str("software_version", v.SoftwareVersion).
		Str("software_build_id", v.SoftwareBuildID)
}

var defaultVersions = Versions{
	HardwareVersion: "Macmini9,1",
	SoftwareName:    "macOS",
	SoftwareVersion: "13.5",
	SoftwareBuildID: "22G74",
}

func (v *Versions) DefaultIfEmpty() {
	if v.HardwareVersion == "" {
		*v = defaultVersions
	}
}

func (v *Versions) IDSOSVersion() string {
	v.DefaultIfEmpty()
	return fmt.Sprintf("%s,%s,%s", v.SoftwareName, v.SoftwareVersion, v.SoftwareBuildID)
}

func (v *Versions) CombinedVersion() string {
	v.DefaultIfEmpty()
	return fmt.Sprintf("[%s,%s,%s,%s]", v.SoftwareName, v.SoftwareVersion, v.SoftwareBuildID, v.HardwareVersion)
}

func (v *Versions) MMEClientInfo() string {
	v.DefaultIfEmpty()
	// TODO unhardcode the icloud content version?
	return fmt.Sprintf("<%s> <%s;%s;%s> <com.apple.icloud.content/1950.19 (com.apple.Messenger/1.0)>", v.HardwareVersion, v.SoftwareName, v.SoftwareVersion, v.SoftwareBuildID)
}

func (v *Versions) IMTransferUserAgent() string {
	// TODO don't hardcode?
	return "IMTransferAgent/1000 CFNetwork/1406.0.4 Darwin/22.4.0"
}

type AuthIDCertPair struct {
	Added    time.Time
	AuthCert *x509.Certificate
	IDCert   *x509.Certificate

	RefreshNeeded bool
}

type Config struct {
	ProfileID      string
	AuthPrivateKey *rsa.PrivateKey

	AuthIDCertPairs map[string]*AuthIDCertPair
	IDRegisteredAt  time.Time

	PushKey   *rsa.PrivateKey
	PushCert  *x509.Certificate
	PushToken []byte

	PushGenVersion int
	PushGenRetried bool

	IDSEncryptionKey *rsa.PrivateKey
	IDSSigningKey    *ecdsa.PrivateKey

	NGMDeviceKey *ec.CompactPrivateKey
	NGMPreKey    *ec.CompactPrivateKey

	Handles         []uri.ParsedURI
	DefaultHandle   uri.ParsedURI
	PreferredHandle uri.ParsedURI

	SMSForwarding *SMSForwarding

	Versions

	DeviceUUID uuid.UUID

	// WARNING: This is being used to determine if the user logged in at a time
	// when pair-ec registration was enabled. If this is zero, then we know
	// that the user might have been registered before pair-ec was enabled.
	LoggedInAt      time.Time
	LastLoginTestAt time.Time
}

func (c *Config) MarshalJSON() ([]byte, error) {
	return json.Marshal(c.ToJSONConfig())
}

func (c *Config) ToJSONConfig() *JSONConfig {
	var cfg JSONConfig

	cfg.AuthKey.PrivateKey = c.AuthPrivateKey
	cfg.ProfileID = c.ProfileID

	cfg.AuthIDCertPairs = map[string]*JSONAuthIDCertPair{}
	for profileID, pair := range c.AuthIDCertPairs {
		var jsonPair JSONAuthIDCertPair
		jsonPair.Added = pair.Added
		jsonPair.AuthCert.Certificate = pair.AuthCert
		jsonPair.IDCert.Certificate = pair.IDCert
		jsonPair.RefreshNeeded = pair.RefreshNeeded
		cfg.AuthIDCertPairs[profileID] = &jsonPair
	}
	cfg.RegisteredAt = c.IDRegisteredAt

	cfg.Push.Key.PrivateKey = c.PushKey
	cfg.Push.Cert.Certificate = c.PushCert
	cfg.Push.Token = c.PushToken
	cfg.Push.Version = c.PushGenVersion
	cfg.Push.Retried = c.PushGenRetried

	cfg.DeviceUUID = c.DeviceUUID
	cfg.Handles = make([]string, len(c.Handles))
	for i, handle := range c.Handles {
		cfg.Handles[i] = handle.String()
	}
	cfg.DefaultHandle = c.DefaultHandle.String()
	cfg.PreferredHandle = c.PreferredHandle.String()

	cfg.SMSForwarding = c.SMSForwarding
	cfg.Versions = c.Versions
	cfg.Versions.DefaultIfEmpty()
	cfg.Versions.SerialNumber = ""
	cfg.Versions.UniqueDeviceID = ""

	cfg.Encryption.RSAKey.PrivateKey = c.IDSEncryptionKey
	cfg.Encryption.ECKey.PrivateKey = c.IDSSigningKey
	if c.NGMDeviceKey != nil {
		cfg.Encryption.NGMDeviceKey.PrivateKey = c.NGMDeviceKey.PrivateKey
	}
	if c.NGMPreKey != nil {
		cfg.Encryption.NGMPreKey.PrivateKey = c.NGMPreKey.PrivateKey
	}

	cfg.LoggedInAt = c.LoggedInAt
	cfg.LastLoginTestAt = c.LastLoginTestAt

	return &cfg
}

func (c *Config) UnmarshalJSON(data []byte) error {
	var jsonConfig JSONConfig
	err := json.Unmarshal(data, &jsonConfig)
	if err != nil {
		return err
	}
	*c = *jsonConfig.ToConfig()
	return nil
}

func (c *JSONConfig) ToConfig() *Config {
	var config Config

	config.ProfileID = c.ProfileID
	config.AuthPrivateKey = c.AuthKey.Unwrap()
	config.AuthIDCertPairs = map[string]*AuthIDCertPair{}
	for k, v := range c.AuthIDCertPairs {
		config.AuthIDCertPairs[k] = &AuthIDCertPair{
			Added:    v.Added,
			AuthCert: v.AuthCert.Unwrap(),
			IDCert:   v.IDCert.Unwrap(),

			RefreshNeeded: v.RefreshNeeded,
		}
	}
	config.IDRegisteredAt = c.RegisteredAt

	config.PushKey = c.Push.Key.Unwrap()
	config.PushCert = c.Push.Cert.Unwrap()
	config.PushToken = c.Push.Token
	config.PushGenVersion = c.Push.Version
	config.PushGenRetried = c.Push.Retried

	config.DeviceUUID = c.DeviceUUID

	config.Handles = make([]uri.ParsedURI, len(c.Handles))
	for i, handle := range c.Handles {
		config.Handles[i], _ = uri.ParseURI(handle)
	}
	if c.DefaultHandle != "" {
		config.DefaultHandle, _ = uri.ParseURI(c.DefaultHandle)
	}
	if c.PreferredHandle != "" {
		config.PreferredHandle, _ = uri.ParseURI(c.PreferredHandle)
	}

	config.SMSForwarding = c.SMSForwarding
	config.Versions = c.Versions

	config.IDSEncryptionKey = c.Encryption.RSAKey.Unwrap()
	config.IDSSigningKey = c.Encryption.ECKey.Unwrap()
	if ngmDeviceKey := c.Encryption.NGMDeviceKey.Unwrap(); ngmDeviceKey != nil {
		config.NGMDeviceKey = &ec.CompactPrivateKey{PrivateKey: ngmDeviceKey}
	}
	if ngmPreKey := c.Encryption.NGMPreKey.Unwrap(); ngmPreKey != nil {
		config.NGMPreKey = &ec.CompactPrivateKey{PrivateKey: ngmPreKey}
	}

	config.LoggedInAt = c.LoggedInAt
	config.LastLoginTestAt = c.LastLoginTestAt

	return &config
}

type JSONRSAPrivateKey struct {
	*rsa.PrivateKey
}

func (k *JSONRSAPrivateKey) MarshalJSON() ([]byte, error) {
	if k == nil || k.PrivateKey == nil {
		return json.Marshal(nil)
	}
	return json.Marshal(string(pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(k.PrivateKey),
	})))
}

func (k *JSONRSAPrivateKey) UnmarshalJSON(data []byte) error {
	var pkeyPEM string
	err := json.Unmarshal(data, &pkeyPEM)
	if err != nil {
		return err
	}
	if len(pkeyPEM) == 0 {
		return nil
	}
	block, _ := pem.Decode([]byte(pkeyPEM))
	pkey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return err
	}
	k.PrivateKey = pkey
	return nil
}

func (k *JSONRSAPrivateKey) Sha256Fingerprint() []byte {
	hash := sha256.Sum256(x509.MarshalPKCS1PublicKey(&k.PublicKey))
	return hash[:]
}

func (k *JSONRSAPrivateKey) Unwrap() *rsa.PrivateKey {
	return k.PrivateKey
}

type JSONECPrivateKey struct {
	*ecdsa.PrivateKey
}

func (k *JSONECPrivateKey) MarshalJSON() ([]byte, error) {
	if k == nil || k.PrivateKey == nil {
		return json.Marshal(nil)
	}
	keyBytes, err := x509.MarshalECPrivateKey(k.PrivateKey)
	if err != nil {
		return nil, err
	}
	return json.Marshal(string(pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: keyBytes,
	})))
}

func (k *JSONECPrivateKey) UnmarshalJSON(data []byte) error {
	var pkeyPEM string
	err := json.Unmarshal(data, &pkeyPEM)
	if err != nil {
		return err
	}
	if len(pkeyPEM) == 0 {
		return nil
	}
	block, _ := pem.Decode([]byte(pkeyPEM))
	k.PrivateKey, err = x509.ParseECPrivateKey(block.Bytes)
	return err
}

func (k *JSONECPrivateKey) Unwrap() *ecdsa.PrivateKey {
	return k.PrivateKey
}

type JSONCertificate struct {
	*x509.Certificate
}

func (c *JSONCertificate) MarshalJSON() ([]byte, error) {
	if c == nil || c.Certificate == nil {
		return json.Marshal(nil)
	}
	return json.Marshal(string(pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: c.Certificate.Raw,
	})))
}

func (c *JSONCertificate) UnmarshalJSON(data []byte) error {
	var certPEM string
	err := json.Unmarshal(data, &certPEM)
	if err != nil {
		return err
	}
	if len(certPEM) == 0 {
		return nil
	}
	block, _ := pem.Decode([]byte(certPEM))
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return err
	}
	c.Certificate = cert
	return nil
}

func (c *JSONCertificate) Sha256Fingerprint() []byte {
	hash := sha256.Sum256(c.Raw)
	return hash[:]
}

func (c *JSONCertificate) Unwrap() *x509.Certificate {
	return c.Certificate
}

type JSONAuthIDCertPair struct {
	Added    time.Time       `json:"added"`
	AuthCert JSONCertificate `json:"auth"`
	IDCert   JSONCertificate `json:"id"`

	RefreshNeeded bool `json:"refresh_needed"`
}

type JSONConfig struct {
	Encryption struct {
		RSAKey       JSONRSAPrivateKey `json:"rsa_key"`
		ECKey        JSONECPrivateKey  `json:"ec_key"`
		NGMDeviceKey JSONECPrivateKey  `json:"ngm_device_key"`
		NGMPreKey    JSONECPrivateKey  `json:"ngm_pre_key"`
	} `json:"encryption"`

	DeviceUUID      uuid.UUID `json:"device_uuid"`
	Handles         []string  `json:"handles"`
	DefaultHandle   string    `json:"default_handle"`
	PreferredHandle string    `json:"preferred_handle"`

	AuthKey   JSONRSAPrivateKey `json:"auth_key"`
	ProfileID string            `json:"profile_id,omitempty"`

	AuthIDCertPairs map[string]*JSONAuthIDCertPair `json:"auth_id_cert_pairs"`
	RegisteredAt    time.Time                      `json:"registered_at"`

	Push struct {
		Token   []byte            `json:"token"`
		Key     JSONRSAPrivateKey `json:"key"`
		Cert    JSONCertificate   `json:"cert"`
		Version int               `json:"version"`
		Retried bool              `json:"retried,omitempty"`
	} `json:"push"`

	SMSForwarding *SMSForwarding `json:"sms_forwarding,omitempty"`
	Versions      Versions       `json:"versions"`

	LoggedInAt      time.Time `json:"logged_in_at"`
	LastLoginTestAt time.Time `json:"last_login_test_at"`
}
