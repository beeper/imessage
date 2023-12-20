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

import "crypto/sha1"

type Topic string

const (
	TopicMadrid                       Topic = "com.apple.madrid"
	TopicAlloySMS                     Topic = "com.apple.private.alloy.sms"
	TopicAlloyGelato                  Topic = "com.apple.private.alloy.gelato"
	TopicAlloyBiz                     Topic = "com.apple.private.alloy.biz"
	TopicAlloySafetyMonitor           Topic = "com.apple.private.alloy.safetymonitor"
	TopicAlloySafetyMonitorOwnAccount Topic = "com.apple.private.alloy.safetymonitor.ownaccount"
	TopicAlloyGamecenteriMessage      Topic = "com.apple.private.alloy.gamecenter.imessage"
	TopicAlloyFitnessFriendsiMessage  Topic = "com.apple.private.alloy.fitnessfriends.imessage"
	TopicAlloyAskTo                   Topic = "com.apple.private.alloy.askto"
	TopicIDS                          Topic = "com.apple.private.ids"
)

var TopicHashMap = map[[20]byte]Topic{}

func init() {
	topics := []Topic{
		TopicMadrid,
		TopicAlloySMS,
		TopicAlloyGelato,
		TopicAlloyBiz,
		TopicAlloyGamecenteriMessage,
		TopicAlloySafetyMonitor,
		TopicAlloySafetyMonitorOwnAccount,
		TopicAlloyFitnessFriendsiMessage,
		TopicAlloyAskTo,
		TopicIDS,
	}
	for _, topic := range topics {
		TopicHashMap[sha1.Sum([]byte(topic))] = topic
	}
}
