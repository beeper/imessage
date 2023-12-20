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

package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/beeper/imessage/imessage/appleid"
)

func must[T any](val T, err error) T {
	if err != nil {
		panic(err)
	}
	return val
}

var scanner = bufio.NewScanner(os.Stdin)

func input(prompt string) string {
	fmt.Print(prompt, ": ")
	scanner.Scan()
	return scanner.Text()
}

func main() {
	ctx := context.Background()
	cli := appleid.NewClient()

	must(0, cli.Prepare(ctx))
	username := input("Enter username")
	must(0, cli.EnterUsername(ctx, username, false))
	password := input("Enter password")
	twoFactorInfo := must(cli.EnterPassword(ctx, password))
	if twoFactorInfo.HasTrustedDevices {
		must(0, cli.RequestSMS2FA(ctx, twoFactorInfo.PhoneNumberInfo.TrustedPhoneNumber.PushMode, twoFactorInfo.PhoneNumberInfo.TrustedPhoneNumber.ID))
	}
	code := input("Enter code sent to " + twoFactorInfo.PhoneNumberInfo.TrustedPhoneNumber.NumberWithDialCode)
	must(0, cli.Submit2FA(ctx, code))

	fmt.Printf("Old app-specific passwords: %#v\n", must(cli.GetAppSpecificPasswords(ctx)))

	resp, err := cli.CreateAppSpecificPassword(ctx, "test passwd")
	if errors.Is(err, appleid.ErrStandardAdditionalAuthNeeded) {
		must(0, cli.SubmitStandardAdditionalAuth(ctx, password))
		resp, err = cli.CreateAppSpecificPassword(ctx, "test passwd")
	}
	if err != nil {
		panic(err)
	}
	fmt.Printf("Created app-specific password: %#v\n", resp)

	fmt.Printf("New app-specific passwords: %#v\n", must(cli.GetAppSpecificPasswords(ctx)))

	time.Sleep(5 * time.Second)
	must(0, cli.DeleteAppSpecificPasswords(ctx, resp.ID))

	fmt.Printf("App-specific passwords after deleting: %#v\n", must(cli.GetAppSpecificPasswords(ctx)))
}
