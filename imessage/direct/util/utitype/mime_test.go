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

package utitype_test

import (
	"mime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/beeper/imessage/imessage/direct/util/utitype"
)

func TestMIME(t *testing.T) {
	tests := []struct{ name, mime, uti string }{
		{"Plaintext", "text/plain", "public.plain-text"},
		{"Markdown", "text/markdown", "net.daringfireball.markdown"},
		{"ImageJPEG", "image/jpeg", "public.jpeg"},
		{"ImagePNG", "image/png", "public.png"},
		{"ImageGIF", "image/gif", "com.compuserve.gif"},
		{"VideoMP4", "video/mp4", "public.mpeg-4"},
		{"AudioM4A", "audio/x-m4a", "com.apple.m4a-audio"},
		{"AudioMessage", "audio/x-caf", "com.apple.coreaudio-format"},
		{"PDF", "application/pdf", "com.adobe.pdf"},
		{"VCard", "text/vcard", "public.vcard"},
		{"CustomLocation", "text/x-vlocation", "public.vlocation"},
		{"BinaryData", "application/octet-stream", "public.data"},
		{"CustomData", "application/x-foo", "dyn.ah62d4rv4gq80c6durvy0g2pyrf106p52fzxg852"},
		{"CustomImage", "image/x-foo", "dyn.ah62d4uv4gq80w5pbq7ww88brq3108"},
		{"CustomText", "text/x-foo", "dyn.ah62d4r34gq81k3p2su11uppgr71u"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.uti, utitype.MIME(test.mime))
		})
	}
}
func TestMIME_CustomImage_WithExtension(t *testing.T) {
	err := mime.AddExtensionType(".meow", "image/x-meow")
	require.NoError(t, err)
	assert.Equal(t, "dyn.ah62d4uv4gq80w5pbq7ww88brrzw08734ge8043pts6", utitype.MIME("image/x-meow"))
}
