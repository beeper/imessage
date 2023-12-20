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
	"strings"

	"github.com/rs/zerolog/log"
	"golang.org/x/net/html"
)

func getAttr(node *html.Node, attrName string) string {
	for _, attr := range node.Attr {
		if attr.Key == attrName {
			return attr.Val
		}
	}
	return ""
}

func nodeToTagAwareString(node *html.Node) (string, error) {
	var builder strings.Builder
	for ; node != nil; node = node.NextSibling {
		switch node.Type {
		case html.TextNode:
			builder.WriteString(node.Data)
		case html.ElementNode:
			if node.Data == "br" {
				builder.WriteString("\n")
				continue
			}
			val, err := nodeToTagAwareString(node.FirstChild)
			if err != nil {
				return "", err
			}

			builder.WriteString(val)
		case html.DocumentNode:
			return nodeToTagAwareString(node.FirstChild)
		default:
			log.Warn().Uint32("type", uint32(node.Type)).Msgf("unhandled node type")
		}
	}
	return builder.String(), nil
}

func ParseEditXML(editXML string) (string, error) {
	doc, err := html.Parse(strings.NewReader(editXML))
	if err != nil {
		return "", err
	}
	return nodeToTagAwareString(doc)
}
