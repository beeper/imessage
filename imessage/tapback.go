// beeper-imessage - A Matrix-iMessage puppeting bridge.
// Copyright (C) 2021 Tulir Asokan
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
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/google/uuid"
)

const (
	TapbackLove TapbackType = iota + 2000
	TapbackLike
	TapbackDislike
	TapbackLaugh
	TapbackEmphasis
	TapbackQuestion

	TapbackRemoveOffset = 1000
)

type Tapback struct {
	TargetGUIDString string `json:"-"`

	TargetGUID uuid.UUID       `json:"target_guid"`
	TargetPart int             `json:"-"`
	PartInfo   MessagePartInfo `json:"-"`
	Remove     bool            `json:"-"`
	Type       TapbackType     `json:"type"`
}

var (
	ErrUnknownNormalTapbackTarget = errors.New("unrecognized formatting of normal tapback target")
	ErrInvalidTapbackTargetPart   = errors.New("tapback target part index is invalid")
	ErrUnknownTapbackTargetType   = errors.New("unrecognized tapback target type")
)

func (tapback *Tapback) Parse() (*Tapback, error) {
	if tapback.Type >= 3000 && tapback.Type < 4000 {
		tapback.Type -= TapbackRemoveOffset
		tapback.Remove = true
	}
	if strings.HasPrefix(tapback.TargetGUIDString, "bp:") {
		// TODO don't ignore errors
		tapback.TargetGUID, _ = uuid.Parse(tapback.TargetGUIDString[len("bp:"):])
	} else if strings.HasPrefix(tapback.TargetGUIDString, "p:") {
		targetParts := strings.Split(tapback.TargetGUIDString[len("p:"):], "/")
		if len(targetParts) == 2 {
			var err error
			tapback.TargetPart, err = strconv.Atoi(targetParts[0])
			if err != nil {
				return nil, fmt.Errorf("%w: '%s' (%v)", ErrInvalidTapbackTargetPart, tapback.TargetGUID, err)
			}
			// TODO don't ignore errors
			tapback.TargetGUID, _ = uuid.Parse(targetParts[1])
		} else {
			return nil, fmt.Errorf("%w: '%s'", ErrUnknownNormalTapbackTarget, tapback.TargetGUID)
		}
	} else {
		return nil, fmt.Errorf("%w: '%s'", ErrUnknownTapbackTargetType, tapback.TargetGUID)
	}
	return tapback, nil
}

type TapbackType int

func TapbackFromEmoji(emoji string) TapbackType {
	switch []rune(emoji)[0] {
	case '\u2665', '\u2764', '\U0001f499', '\U0001f49a', '\U0001f90e', '\U0001f5a4', '\U0001f90d', '\U0001f9e1',
		'\U0001f49b', '\U0001f49c', '\U0001f496', '\u2763', '\U0001f495', '\U0001f49f':
		// '♥', '❤', '💙', '💚', '🤎', '🖤', '🤍', '🧡', '💛', '💜', '💖', '❣', '💕', '💟'
		return TapbackLove
	case '\U0001f44d': // '👍'
		return TapbackLike
	case '\U0001f44e': // '👎'
		return TapbackDislike
	case '\U0001f602', '\U0001f639', '\U0001f606', '\U0001f923': // '😂', '😹', '😆', '🤣'
		return TapbackLaugh
	case '\u2755', '\u2757', '\u203c': // '❕', '❗', '‼',
		return TapbackEmphasis
	case '\u2753', '\u2754': // '❓', '❔'
		return TapbackQuestion
	default:
		return 0
	}
}

func (tt TapbackType) String() string {
	return tt.Emoji()
}

func (tt TapbackType) Redacted(redact bool) int {
	if redact {
		return int(tt) + TapbackRemoveOffset
	}
	return int(tt)
}

var actionMap = map[TapbackType]string{
	TapbackLove:                           "Loved",
	TapbackLike:                           "Liked",
	TapbackDislike:                        "Disliked",
	TapbackLaugh:                          "Laughed at",
	TapbackEmphasis:                       "Emphasized",
	TapbackQuestion:                       "Questioned",
	TapbackLove + TapbackRemoveOffset:     "Removed a heart from",
	TapbackLike + TapbackRemoveOffset:     "Removed a like from",
	TapbackDislike + TapbackRemoveOffset:  "Removed a dislike from",
	TapbackLaugh + TapbackRemoveOffset:    "Removed a laugh from",
	TapbackEmphasis + TapbackRemoveOffset: "Removed an exclamation from",
	TapbackQuestion + TapbackRemoveOffset: "Removed a question mark from",
}

func (tt TapbackType) ActionString(target string) string {
	if action, ok := actionMap[tt]; ok {
		return fmt.Sprintf("%s %s", action, target)
	} else {
		return ""
	}
}

func (tt TapbackType) Emoji() string {
	switch tt {
	case 0:
		return ""
	case TapbackLove:
		return "\u2764\ufe0f" // "❤️"
	case TapbackLike:
		return "\U0001f44d\ufe0f" // "👍️"
	case TapbackDislike:
		return "\U0001f44e\ufe0f" // "👎️"
	case TapbackLaugh:
		return "\U0001f602" // "😂"
	case TapbackEmphasis:
		return "\u203c\ufe0f" // "‼️"
	case TapbackQuestion:
		return "\u2753\ufe0f" // "❓️"
	default:
		return "\ufffd" // "�"
	}
}
