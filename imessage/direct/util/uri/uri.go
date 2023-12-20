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

package uri

import (
	"bytes"
	"cmp"
	"database/sql/driver"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/nyaruka/phonenumbers"
	"github.com/rs/zerolog"
)

type PlainURI string

func (uri PlainURI) Parse() (ParsedURI, error) {
	return ParseURI(string(uri))
}

var uuidRe = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
var base64SHA256Re = regexp.MustCompile(`^[0-9a-zA-Z_-]{43}$`)
var numberRe = regexp.MustCompile(`^\+?[0-9]+$`)

type Scheme string

func (s Scheme) Order() int {
	switch s {
	case SchemeTel:
		return 0
	case SchemeMailto:
		return 1
	case SchemeGroup:
		return 2
	case SchemeGroupParticipants:
		return 3
	default:
		return 4
	}
}

const (
	SchemeTel               Scheme = "tel"
	SchemeMailto            Scheme = "mailto"
	SchemeGroup             Scheme = "group"
	SchemeGroupParticipants Scheme = "group-participants"
)

func IsOnlyNumbers(s string) bool {
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func isValidAlphanumericSender(s string) bool {
	// Limits based on https://www.twilio.com/docs/glossary/what-alphanumeric-sender-id, hopefully it's accurate everywhere
	if len(s) > 11 {
		return false
	}
	var hasLetters bool
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || r == ' ' || r == '-' || r == '_' || r == '&' || r == '+' {
			hasLetters = true
		} else if r < '0' || r > '9' {
			// Not letter, number or space -> not valid
			return false
		}
	}
	if !hasLetters {
		// Only consists of numbers -> not valid
		return false
	}
	return true
}

type ParsingOption uint

func (po ParsingOption) allow(opt ParsingOption) bool {
	return po&opt > 0
}

const (
	POIntlNumber ParsingOption = 1 << iota
	POAlphanumericSenderID
	POShortcodes
	POEmail
	PONationalNumber
	POGroupUUID
	POGroupParticipantHash

	// ParseIncomingSMSForward allows parsing user identifiers that are valid senders of incoming SMS.
	ParseIncomingSMSForward = POIntlNumber | POAlphanumericSenderID | POShortcodes | POEmail
	// ParseOutgoingSMSForward allows parsing user identifiers that can be sent SMS. Emails are intentionally excluded.
	ParseOutgoingSMSForward = POIntlNumber | POShortcodes
	// ParseiMessageDM allows parsing user identifiers that can be sent messages on iMessage.
	ParseiMessageDM = POIntlNumber | POEmail
	// ParseiMessageGroup allows parsing iMessage group identifiers.
	ParseiMessageGroup = POGroupUUID | POGroupParticipantHash
	// ParseAnyChat parses any reasonably normal identifier in a chat,
	// i.e. all parsing options except international without prefix
	ParseAnyChat = ParseiMessageDM | ParseiMessageGroup | POAlphanumericSenderID | POShortcodes
)

func ParseIdentifier(identifier string, opts ParsingOption) (ParsedURI, error) {
	if opts&PONationalNumber > 0 {
		return EmptyURI, fmt.Errorf("can't parse national numbers without specifying region")
	}
	return parseIdentifier(identifier, opts, "")
}

func ParseIdentifierWithLocalNumbers(identifier string, opts ParsingOption, nationalNumberRegion string) (ParsedURI, error) {
	return parseIdentifier(identifier, opts|PONationalNumber, nationalNumberRegion)
}

func parseIdentifier(identifier string, opts ParsingOption, nationalNumberRegion string) (ParsedURI, error) {
	if parsed, err := ParseURI(identifier); !errors.Is(err, ErrMissingColon) {
		if err != nil {
			return parsed, err
		}
		switch {
		case parsed.Scheme == SchemeMailto && !opts.allow(POEmail):
			return EmptyURI, fmt.Errorf("mailto: URIs are not allowed here (opts: %d)", opts)
		case parsed.Scheme == SchemeGroup && !opts.allow(POGroupUUID):
			return EmptyURI, fmt.Errorf("group: URIs are not allowed here (opts: %d)", opts)
		case parsed.Scheme == SchemeGroupParticipants && !opts.allow(POGroupParticipantHash):
			return EmptyURI, fmt.Errorf("group-participants: URIs are not allowed here (opts: %d)", opts)
			// TODO check shortcodes/alphanumeric sender IDs?
		case parsed.Scheme == SchemeTel:
			switch {
			case parsed.Identifier[0] == '+' && IsOnlyNumbers(parsed.Identifier[1:]) && len(parsed.Identifier) > 7:
				if !opts.allow(POIntlNumber) {
					return EmptyURI, fmt.Errorf("international phone numbers are not allowed here (opts: %d)", opts)
				}
			case len(parsed.Identifier) <= 6 && IsOnlyNumbers(parsed.Identifier):
				if !opts.allow(POShortcodes) {
					return ParsedURI{}, fmt.Errorf("shortcodes are not allowed here (opts: %d)", opts)
				}
			case isValidAlphanumericSender(parsed.Identifier):
				if !opts.allow(POAlphanumericSenderID) {
					return EmptyURI, fmt.Errorf("alphanumeric sender IDs are not allowed here (opts: %d)", opts)
				}
			// Fully formed URIs should always have the +, so don't allow omitting it
			default:
				return EmptyURI, fmt.Errorf("invalid tel: URI (parse options: %d)", opts)
			}
		}
		return parsed, nil
	}
	switch {
	case opts.allow(POGroupUUID) && uuidRe.MatchString(identifier):
		// Note: this does not match all possible group identifiers, because some are not UUIDs
		return ParsedURI{Scheme: SchemeGroup, Identifier: strings.ToUpper(identifier)}, nil
	case opts.allow(POGroupParticipantHash) && base64SHA256Re.MatchString(identifier):
		return ParsedURI{Scheme: SchemeGroupParticipants, Identifier: identifier}, nil
	case opts.allow(POEmail) && strings.ContainsRune(identifier, '@'):
		return ParsedURI{Scheme: SchemeMailto, Identifier: strings.ToLower(identifier)}, nil
	case // Normal international phone number
		opts.allow(POIntlNumber) && len(identifier) > 7 && identifier[0] == '+' && IsOnlyNumbers(identifier[1:]),
		// Short code
		opts.allow(POShortcodes) && len(identifier) <= 6 && IsOnlyNumbers(identifier),
		// Alphanumeric sender ID
		opts.allow(POAlphanumericSenderID) && isValidAlphanumericSender(identifier):
		// In the three preceding cases, just use the identifier as-is
		return ParsedURI{Scheme: SchemeTel, Identifier: identifier}, nil
	case opts.allow(PONationalNumber) && len(identifier) > 6 && IsOnlyNumbers(identifier):
		parsed, err := phonenumbers.Parse(identifier, nationalNumberRegion)
		if err != nil {
			return EmptyURI, fmt.Errorf("failed to parse national number: %w", err)
		}
		return ParsedURI{Scheme: SchemeTel, Identifier: phonenumbers.Format(parsed, phonenumbers.E164)}, nil
	default:
		return EmptyURI, fmt.Errorf("invalid URI (parse options: %d)", opts)
	}
}

var EmptyURI ParsedURI

type ParsedURI struct {
	Scheme     Scheme
	Identifier string
}

func validateURI(scheme Scheme, identifier string) (ret ParsedURI, err error) {
	ret = ParsedURI{Scheme: scheme, Identifier: identifier}
	if len(identifier) == 0 {
		err = fmt.Errorf("invalid URI (empty identifier)")
		return
	}
	switch scheme {
	case SchemeTel:
		switch {
		// TODO checking length here would break scanning some existing invalid rows in databases
		case identifier[0] == '+' && IsOnlyNumbers(identifier[1:]) /*&& len(identifier) > 7*/ :
			// international number
		case len(identifier) <= 6 && IsOnlyNumbers(identifier):
			// shortcode
		case isValidAlphanumericSender(identifier):
			// alphanumeric sender
		default:
			return ParsedURI{}, fmt.Errorf("invalid phone number in URI")
		}
	case SchemeMailto:
		atIndex := strings.IndexRune(identifier, '@')
		if atIndex < 1 || atIndex == len(identifier)-1 {
			err = fmt.Errorf("invalid email address in URI")
		}
	case SchemeGroup:
		// turns out group ids don't have any rules even though most of them look like uuids 😿
	case SchemeGroupParticipants:
		if !base64SHA256Re.MatchString(identifier) {
			err = fmt.Errorf("invalid base64 hash in participant list group URI")
		}
	case "urn":
	default:
		err = fmt.Errorf("invalid URI (unknown scheme %q)", scheme)
	}
	return
}

var ErrMissingColon = errors.New("invalid URI (missing `:`)")

func ParseURI(uri string) (ParsedURI, error) {
	colonIndex := strings.IndexRune(uri, ':')
	if colonIndex == -1 {
		return ParsedURI{}, ErrMissingColon
	}
	return validateURI(Scheme(uri[:colonIndex]), uri[colonIndex+1:])
}

func ParseURIBytes(uri []byte) (ParsedURI, error) {
	colonIndex := bytes.IndexRune(uri, ':')
	if colonIndex == -1 {
		return ParsedURI{}, ErrMissingColon
	}
	return validateURI(Scheme(uri[:colonIndex]), string(uri[colonIndex+1:]))
}

func (uri *ParsedURI) IsShortcode() bool {
	return uri != nil && uri.Scheme == SchemeTel && len(uri.Identifier) <= 6
}

func (pu *ParsedURI) IsEmpty() bool {
	return pu == nil || (pu.Scheme == "" && pu.Identifier == "")
}

func (pu *ParsedURI) String() string {
	if pu.IsEmpty() {
		return ""
	}
	return fmt.Sprintf("%s:%s", pu.Scheme, pu.Identifier)
}

func (pu *ParsedURI) StringPtr() *string {
	if pu == nil {
		return nil
	}
	val := pu.String()
	return &val
}

func (pu *ParsedURI) UnmarshalPlist(unmarshal func(any) error) error {
	if pu == nil {
		return fmt.Errorf("can't unmarshal into nil")
	}
	var uri string
	err := unmarshal(&uri)
	if err != nil {
		return err
	}
	*pu, err = ParseURI(uri)
	return err
}

func (pu *ParsedURI) MarshalPlist() (any, error) {
	return pu.String(), nil
}

func (pu *ParsedURI) MarshalText() ([]byte, error) {
	return []byte(pu.String()), nil
}

func (pu *ParsedURI) UnmarshalText(text []byte) (err error) {
	if pu == nil {
		return fmt.Errorf("can't unmarshal into nil")
	}
	*pu, err = ParseURIBytes(text)
	return
}

func (pu *ParsedURI) Scan(i interface{}) error {
	if pu == nil {
		return fmt.Errorf("can't scan into nil")
	}
	var parsed ParsedURI
	var err error
	switch value := i.(type) {
	case nil:
		// don't do anything, set uri to empty
	case []byte:
		if len(value) == 0 {
			return nil
		}
		parsed, err = ParseURIBytes(value)
	case string:
		if len(value) == 0 {
			return nil
		}
		parsed, err = ParseURI(value)
	default:
		return fmt.Errorf("invalid type %T for ParsedURI.Scan", i)
	}
	if err != nil {
		return err
	}
	*pu = parsed
	return nil
}

// This needs to be a non-pointer receiver, otherwise all ParsedURIs need to be passed as pointers

func (pu ParsedURI) Value() (driver.Value, error) {
	return pu.String(), nil
}

func Compare(a, b ParsedURI) int {
	if a.Scheme == b.Scheme {
		return strings.Compare(a.Identifier, b.Identifier)
	}
	return cmp.Compare(a.Scheme.Order(), b.Scheme.Order())
}

func Sort(handles []ParsedURI) []ParsedURI {
	if len(handles) == 0 {
		return handles
	}
	slices.SortFunc(handles, Compare)
	return slices.Compact(handles)
}

func ToStringSlice(handles []ParsedURI) []string {
	ret := make([]string, len(handles))
	for i, handle := range handles {
		ret[i] = handle.String()
	}
	return ret
}

func ToIdentifierStringSlice(handles []ParsedURI) []string {
	ret := make([]string, len(handles))
	for i, handle := range handles {
		ret[i] = handle.String()
	}
	return ret
}

func ToZerologArray(handles []ParsedURI) *zerolog.Array {
	arr := zerolog.Arr()
	for _, handle := range handles {
		arr.Str(handle.String())
	}
	return arr
}
