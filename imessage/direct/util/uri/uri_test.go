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

package uri_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/beeper/imessage/imessage/direct/util/uri"
)

type parseTestCase struct {
	name   string
	input  string
	output uri.ParsedURI
}

func TestParseURI(t *testing.T) {
	testCases := []parseTestCase{
		{"ShortCodePhone", "tel:123456", uri.ParsedURI{uri.SchemeTel, "123456"}},
		{"InternationalPhone", "tel:+1234567890", uri.ParsedURI{uri.SchemeTel, "+1234567890"}},
		{"AlphanumericPhone", "tel:meow", uri.ParsedURI{uri.SchemeTel, "meow"}},
		{"AlphanumericMixedCasePhone", "tel:MeoW", uri.ParsedURI{uri.SchemeTel, "MeoW"}},
		{"AlphanumericSpacePhone", "tel:Meow Meow", uri.ParsedURI{uri.SchemeTel, "Meow Meow"}},
		{"Email", "mailto:123@example.com", uri.ParsedURI{uri.SchemeMailto, "123@example.com"}},
		{"GroupUUID", "group:76A976F2-92CC-49F0-8500-DC5F42AAF2BB", uri.ParsedURI{uri.SchemeGroup, "76A976F2-92CC-49F0-8500-DC5F42AAF2BB"}},
		{"GroupArbitrary", "group:Meow Meow", uri.ParsedURI{uri.SchemeGroup, "Meow Meow"}},
		{"GroupParticipantsHash", "group-participants:QEzde8EJxDL4zCRDtFvP6VmA9RByFcZFI25XeSmsPlI", uri.ParsedURI{uri.SchemeGroupParticipants, "QEzde8EJxDL4zCRDtFvP6VmA9RByFcZFI25XeSmsPlI"}},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			parsedURI, err := uri.ParseURI(tc.input)
			assert.NoError(t, err)
			assert.Equal(t, tc.output, parsedURI)
		})
		t.Run(tc.name+"/ParseIdentifier", func(t *testing.T) {
			parsedURI, err := uri.ParseIdentifier(tc.input, uri.ParseAnyChat)
			assert.NoError(t, err)
			assert.Equal(t, tc.output, parsedURI)
		})
	}
}

func TestParseURI_Fail(t *testing.T) {
	testCases := []string{
		"tel:meeeeeeeeeeeeeeeeeeeeeeeeeeeow", // too long alphanumeric id
		"tel:me=ow",                          // invalid character in alphanumeric ids
		"tel:1234567890",                     // international numbers must start with + (and shortcodes are max 6 digits)
		"mailto:meow",                        // missing @
		"group-participants:woof",            // not a base64'd sha256 hash
	}
	for _, tc := range testCases {
		_, err := uri.ParseURI(tc)
		assert.Error(t, err)
		_, err = uri.ParseIdentifier(tc, uri.ParseAnyChat)
		assert.Error(t, err)
	}
}

type parseIdentTestCase struct {
	name     string
	requires uri.ParsingOption
	input    string
	output   uri.ParsedURI
}

type parseIdentOptions struct {
	opts uri.ParsingOption
	name string
}

var defaultOpts = []parseIdentOptions{
	{uri.ParseIncomingSMSForward, "AsIncomingSMSForward"},
	{uri.ParseOutgoingSMSForward, "AsOutgoingSMSForward"},
	{uri.ParseiMessageDM, "AsiMessageDM"},
	{uri.ParseiMessageGroup, "AsiMessageGroup"},
	{uri.ParseAnyChat, "AsAnyChat"},
}

func TestParseIdentifier(t *testing.T) {
	testCases := []parseIdentTestCase{
		{"ShortCode4", uri.POShortcodes, "1234", uri.ParsedURI{uri.SchemeTel, "1234"}},
		{"ShortCode5", uri.POShortcodes, "12345", uri.ParsedURI{uri.SchemeTel, "12345"}},
		{"ShortCode6", uri.POShortcodes, "123456", uri.ParsedURI{uri.SchemeTel, "123456"}},
		//{"ShortestInternationalNo+", uri.POIntlNumberWithoutPrefix, "2902123", uri.ParsedURI{uri.SchemeTel, "+2902123"}},
		{"ShortestInternationalWith+", uri.POIntlNumber, "+2902123", uri.ParsedURI{uri.SchemeTel, "+2902123"}},
		//{"NormalInternationalNo+", uri.POIntlNumberWithoutPrefix, "1234567890", uri.ParsedURI{uri.SchemeTel, "+1234567890"}},
		{"NormalInternationalWith+", uri.POIntlNumber, "+1234567890", uri.ParsedURI{uri.SchemeTel, "+1234567890"}},
		{"Alphanumeric", uri.POAlphanumericSenderID, "meow", uri.ParsedURI{uri.SchemeTel, "meow"}},
		{"AlphanumericMixedCase", uri.POAlphanumericSenderID, "MeoW", uri.ParsedURI{uri.SchemeTel, "MeoW"}},
		{"AlphanumericSpace", uri.POAlphanumericSenderID, "Meow Meow", uri.ParsedURI{uri.SchemeTel, "Meow Meow"}},
		{"Email", uri.POEmail, "123@example.com", uri.ParsedURI{uri.SchemeMailto, "123@example.com"}},
		{"GroupUUIDLowercase", uri.POGroupUUID, "76a976f2-92cc-49f0-8500-dc5f42aaf2bb", uri.ParsedURI{uri.SchemeGroup, "76A976F2-92CC-49F0-8500-DC5F42AAF2BB"}},
		{"GroupUUIDUppercase", uri.POGroupUUID, "76A976F2-92CC-49F0-8500-DC5F42AAF2BB", uri.ParsedURI{uri.SchemeGroup, "76A976F2-92CC-49F0-8500-DC5F42AAF2BB"}},
		{"GroupParticipantsHash", uri.POGroupParticipantHash, "QEzde8EJxDL4zCRDtFvP6VmA9RByFcZFI25XeSmsPlI", uri.ParsedURI{uri.SchemeGroupParticipants, "QEzde8EJxDL4zCRDtFvP6VmA9RByFcZFI25XeSmsPlI"}},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Run("OnlyRequirement", func(t *testing.T) {
				normalizedURI, err := uri.ParseIdentifier(tc.input, tc.requires)
				assert.NoError(t, err)
				assert.Equal(t, tc.output, normalizedURI)
			})
			for _, opt := range defaultOpts {
				t.Run(opt.name, func(t *testing.T) {
					normalizedURI, err := uri.ParseIdentifier(tc.input, opt.opts)
					if opt.opts&tc.requires > 0 {
						assert.NoError(t, err)
						assert.Equal(t, tc.output, normalizedURI)
						// Don't check errors if alphanumeric sender IDs are enabled, because anything passes with those
					} else {
						assert.Error(t, err)
					}
				})
			}
		})
	}
}
