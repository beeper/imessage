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

package types

//go:generate go run generator.go
//go:generate goimports -w idserrors.gen.go

type IDSStatus int

type IDSError struct {
	ErrorCode IDSStatus
}

func (e IDSError) Error() string {
	return e.ErrorCode.String()
}

func (e IDSError) Is(other error) bool {
	o, ok := other.(IDSError)
	return ok && e.ErrorCode == o.ErrorCode
}

var (
	Err2FARequired              = IDSError{ErrorCode: IDSStatusUnauthenticated}
	ErrInvalidNameOrPassword    = IDSError{ErrorCode: IDSStatusInvalidNameOrPassword}
	ErrActionRefreshCredentials = IDSError{ErrorCode: IDSStatusActionRefreshCredentials}
	ErrProxyResponseTooLarge    = IDSError{ErrorCode: IDSStatusWebTunnelServiceResponseTooLarge}
)
