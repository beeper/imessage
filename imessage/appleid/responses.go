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

package appleid

import (
	"errors"
	"fmt"
)

type FederateRequest struct {
	AccountName string `json:"accountName"`
	RememberMe  bool   `json:"rememberMe"`
}

type FederateResponse struct {
	ShowFederatedIdPConfirmation bool `json:"showFederatedIdpConfirmation"`
	Federated                    bool `json:"federated"`
}

type InitRequest struct {
	A           []byte   `json:"a"`
	AccountName string   `json:"accountName"`
	Protocols   []string `json:"protocols"`
}

type InitResponse struct {
	Iteration int    `json:"iteration"`
	Salt      []byte `json:"salt"`
	Protocol  string `json:"protocol"`
	B         []byte `json:"b"`
	C         string `json:"c"`
}

type CompleteRequest struct {
	AccountName string `json:"accountName"`
	RememberMe  bool   `json:"rememberMe"`
	M1          []byte `json:"m1"`
	C           string `json:"c"`
	M2          []byte `json:"m2"`
}

type CompleteResponse struct {
	AuthType string `json:"authType"`
}

type CompleteErrorResponse struct {
	ServiceErrors []struct {
		Code              string `json:"code"` // -20101 for wrong password
		Message           string `json:"message"`
		SuppressDismissal bool   `json:"suppressDismissal"`
	} `json:"serviceErrors"`
}

type PhoneNumberID struct {
	ID int `json:"id"`
}

type RequestPhoneCodeRequest struct {
	Mode        string        `json:"mode"`
	PhoneNumber PhoneNumberID `json:"phoneNumber"`
}

type RequestSecurityCodeResponse struct{}

type SecurityCodeWrapper struct {
	Code string `json:"code"`
}

type SubmitPhoneCodeRequest struct {
	PhoneNumber  PhoneNumberID       `json:"phoneNumber"`
	SecurityCode SecurityCodeWrapper `json:"securityCode"`
	Mode         string              `json:"mode"`
}

type SubmitTrustedDeviceCodeRequest struct {
	SecurityCode SecurityCodeWrapper `json:"securityCode"`
}

type RerequestSecurityCodeResponse struct {
	TrustedDeviceCount      int                     `json:"trustedDeviceCount"`
	SecurityCode            SecurityCodeParams      `json:"securityCode"`
	PhoneNumberVerification PhoneNumberVerification `json:"phoneNumberVerification"`

	AboutTwoFactorAuthenticationURL string `json:"aboutTwoFactorAuthenticationUrl"`
}

type SubmitSecurityCodeResponse struct{}

type SubmitPhoneCodeResponse struct {
	TrustedPhoneNumbers             []TrustedPhoneNumber `json:"trustedPhoneNumbers"`
	PhoneNumber                     TrustedPhoneNumber   `json:"phoneNumber"`
	SecurityCode                    SecurityCodeParams   `json:"securityCode"`
	Mode                            string               `json:"mode"`
	Type                            string               `json:"type"`
	AuthenticationType              string               `json:"authenticationType"`
	RecoveryUrl                     string               `json:"recoveryUrl"`
	CantUsePhoneNumberUrl           string               `json:"cantUsePhoneNumberUrl"`
	RecoveryWebUrl                  string               `json:"recoveryWebUrl"`
	RepairPhoneNumberUrl            string               `json:"repairPhoneNumberUrl"`
	RepairPhoneNumberWebUrl         string               `json:"repairPhoneNumberWebUrl"`
	AboutTwoFactorAuthenticationUrl string               `json:"aboutTwoFactorAuthenticationUrl"`
	AutoVerified                    bool                 `json:"autoVerified"`
	ShowAutoVerificationUI          bool                 `json:"showAutoVerificationUI"`
	SupportsCustodianRecovery       bool                 `json:"supportsCustodianRecovery"`
	HideSendSMSCodeOption           bool                 `json:"hideSendSMSCodeOption"`
	SupervisedChangePasswordFlow    bool                 `json:"supervisedChangePasswordFlow"`
	SupportsRecovery                bool                 `json:"supportsRecovery"`
	TrustedPhoneNumber              TrustedPhoneNumber   `json:"trustedPhoneNumber"`
	Hsa2Account                     bool                 `json:"hsa2Account"`
	RestrictedAccount               bool                 `json:"restrictedAccount"`
	ManagedAccount                  bool                 `json:"managedAccount"`
}

type AppSpecificPassword struct {
	ID                  int    `json:"id"`
	CreateDatetime      string `json:"createDatetime"`
	LocalizedCreateDate string `json:"localizedCreateDate"`
	CreateDate          string `json:"createDate"`
	Description         string `json:"description"`
}

type AdditionalAuthenticationNeededError struct {
	Type                 string `json:"type"`
	FormattedAccountName string `json:"formattedAccountName"`
}

var ErrStandardAdditionalAuthNeeded = &AdditionalAuthenticationNeededError{Type: "STANDARD"}

func (err *AdditionalAuthenticationNeededError) Is(target error) bool {
	var other *AdditionalAuthenticationNeededError
	if !errors.As(target, &other) {
		return false
	}
	return err.Type == other.Type
}

func (err *AdditionalAuthenticationNeededError) Error() string {
	return fmt.Sprintf("re-authentication needed for %s (type: %s)", err.FormattedAccountName, err.Type)
}

type AdditionalAuthenticateRequest struct {
	Password string `json:"password"`
}

type CreateAppSpecificPasswordRequest struct {
	Description string `json:"description"`
}

type CreateAppSpecificPasswordResponse struct {
	AppSpecificPassword
	Password string `json:"password"`
}

type GetAppSpecificPasswordsResponse []*AppSpecificPassword
