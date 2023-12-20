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
	"math/rand"
	"time"

	"golang.org/x/time/rate"
	"maunium.net/go/mautrix/bridge/bridgeconfig"
	"maunium.net/go/mautrix/id"
)

type AnalyticsConfig struct {
	Host   string `yaml:"host" json:"host"`
	Token  string `yaml:"token" json:"token"`
	UserID string `yaml:"user_id" json:"user_id"`
}

type IMessageLoginTestConfig struct {
	Identifiers                 []string `yaml:"identifiers" json:"identifiers"`
	LookupTestOnLogin           bool     `yaml:"lookup_test_on_login" json:"lookup_test_on_login"`
	RerouteOnLoginTestFailURL   string   `yaml:"reroute_on_login_test_fail_url" json:"reroute_on_login_test_fail_url"`
	LookupTestAfterLoginSeconds int      `yaml:"lookup_test_after_login_seconds" json:"lookup_test_after_login_seconds"`
}

func (c *IMessageLoginTestConfig) GetRandomTestIdentifier() string {
	return c.Identifiers[rand.Intn(len(c.Identifiers))]
}

type RatelimitConfig struct {
	Every time.Duration `yaml:"every" json:"every"`
	Burst int           `yaml:"burst" json:"burst"`
}

func (rc *RatelimitConfig) Compile() *rate.Limiter {
	return rate.NewLimiter(rate.Every(rc.Every), rc.Burst)
}

type IMessageConfig struct {
	DeviceName          string                  `yaml:"device_name" json:"device_name"`
	LoginTest           IMessageLoginTestConfig `yaml:"login_test"`
	EnablePairECSending bool                    `yaml:"enable_pair_ec_sending" json:"enable_pair_ec_sending"`
	LookupRatelimit     RatelimitConfig         `yaml:"lookup_ratelimit"`
}

type Config struct {
	*bridgeconfig.BaseConfig `yaml:",inline"`

	Analytics AnalyticsConfig `yaml:"analytics"`
	IMessage  IMessageConfig  `yaml:"imessage"`
	Bridge    BridgeConfig    `yaml:"bridge"`
}

func (config *Config) CanAutoDoublePuppet(userID id.UserID) bool {
	_, homeserver, _ := userID.Parse()
	_, hasSecret := config.Bridge.DoublePuppetConfig.SharedSecretMap[homeserver]
	return hasSecret
}
