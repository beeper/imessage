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

type BootArgs struct {
	Direct     DirectBootArgs     `json:"direct"`
	Additional AdditionalBootArgs `json:"additional"`
}

type DirectBootArgs struct {
	// Shared
	ScriptSk7URL string `json:"scriptSk7Url"`

	// Only initial login
	IsPasswordSecondStep             bool           `json:"isPasswordSecondStep"`
	IsFederatedAuthEnabled           bool           `json:"isFederatedAuthEnabled"`
	AccountNameAutoComplete          string         `json:"accountNameAutoComplete"`
	AccountName                      string         `json:"accountName"`
	URLBag                           URLBag         `json:"urlBag"`
	RefererURL                       string         `json:"refererUrl"`
	AuthAttributes                   []byte         `json:"authAttributes"`
	IsRaFF                           bool           `json:"isRaFF"`
	ForgotPassword                   bool           `json:"forgotPassword"`
	SwpAuth                          bool           `json:"swpAuth"`
	TwoFactorAuthEnv                 int            `json:"twoFactorAuthEnv"`
	CountryCode                      string         `json:"countryCode"`
	IsInterstitialFedAuthPageEnabled bool           `json:"isInterstitialFedAuthPageEnabled"`
	TwoFactorAuthAppKey              []byte         `json:"twoFactorAuthAppKey"`
	IsRTL                            string         `json:"isRtl"`
	Hashcash                         HashcashParams `json:"hashcash"`
	WebSRPClientWorkerScriptTag      string         `json:"webSRPClientWorkerScriptTag"`
	IsRaIDP                          bool           `json:"isRaIdp"`
	AcURL                            string         `json:"acUrl"`
	EnableSRPAuth                    bool           `json:"enableSRPAuth"`
	DomainID                         int            `json:"domainId"`
	ShouldSuppressIForgotLink        bool           `json:"shouldSuppressIForgotLink"`
	DisableChromeAutoComplete        bool           `json:"disableChromeAutoComplete"`
	GenerateHashcashScriptTag        string         `json:"generateHashcashScriptTag"`
	IframeID                         string         `json:"iframeId"`
	Meta                             AuthMeta       `json:"meta"`
	EnableFPN                        bool           `json:"enableFpn"`
	EnableSecurityKeyIndividual      bool           `json:"enableSecurityKeyIndividual"`
	ShowSwpAuth                      bool           `json:"showSwpAuth"`

	// Only two-factor
	ScriptURL         string        `json:"scriptUrl"`
	Module            string        `json:"module"`
	IsReact           bool          `json:"isReact"`
	AuthUserType      string        `json:"authUserType"`
	HasTrustedDevices bool          `json:"hasTrustedDevices"`
	TwoSV             TwoSVBootArgs `json:"twoSV"`
	ReferrerQuery     string        `json:"referrerQuery"`
	URLContext        string        `json:"urlContext"`
	Tag               string        `json:"tag"`
	AuthType          string        `json:"authType"`
	AuthInitialRoute  string        `json:"authInitialRoute"`
	AppleIDURL        string        `json:"appleIDUrl"`
}

type URLBag struct {
	PasswordReset        string `json:"passwordReset"`
	CreateAppleID        string `json:"createAppleID"`
	AppleID              string `json:"appleId"`
	VerificationCodeHelp string `json:"verificationCodeHelp"`
	AccountRecoveryHelp  string `json:"accountRecoveryHelp"`
	CRResetURL           string `json:"crResetUrl"`
}

type AuthMeta struct {
	FutureReservedAuthUIModes []string `json:"futureReservedAuthUIModes"`
	SupportedAuthUIModes      []string `json:"supportedAuthUIModes"`
	FEConfiguration           struct {
		PmrpcTimeout            string `json:"pmrpcTimeout"`
		EnableAllowAttribute    bool   `json:"enableAllowAttribute"`
		EnableSwpAuth           bool   `json:"enableSwpAuth"`
		IsEyebrowTextboxEnabled bool   `json:"isEyebrowTextboxEnabled"`
		SkVersion               string `json:"skVersion"`
		PmrpcRetryCount         string `json:"pmrpcRetryCount"`
		JSLogLevel              string `json:"jsLogLevel"`
		AppLoadDelay            string `json:"appLoadDelay"`
		EnablePerformanceLog    bool   `json:"enablePerformanceLog"`
	} `json:"FEConfiguration"`
}

type HashcashParams struct {
	GenerationTimeout int    `json:"hashcashGenerationTimeout"`
	Challenge         string `json:"hcChallenge"`
	Bits              int    `json:"hcBits,string"`
	IsStrictTimeout   bool   `json:"isHCstrictTimeout"`
}

type TrustedPhoneNumber struct {
	ID                 int    `json:"id"`
	NumberWithDialCode string `json:"numberWithDialCode"`
	PushMode           string `json:"pushMode"`
	ObfuscatedNumber   string `json:"obfuscatedNumber"`
	LastTwoDigits      string `json:"lastTwoDigits"`
}

type SecurityCodeParams struct {
	Length                int  `json:"length"`
	TooManyCodesSent      bool `json:"tooManyCodesSent"`
	TooManyCodesValidated bool `json:"tooManyCodesValidated"`
	SecurityCodeLocked    bool `json:"securityCodeLocked"`
	SecurityCodeCooldown  bool `json:"securityCodeCooldown"`

	// Only for submit
	Valid bool `json:"valid"`
}

type PhoneNumberVerification struct {
	TrustedPhoneNumbers             []TrustedPhoneNumber `json:"trustedPhoneNumbers"`
	PhoneNumber                     TrustedPhoneNumber   `json:"phoneNumber"`
	SecurityCode                    SecurityCodeParams   `json:"securityCode"`
	AuthenticationType              string               `json:"authenticationType"`
	RecoveryURL                     string               `json:"recoveryUrl"`
	CantUsePhoneNumberURL           string               `json:"cantUsePhoneNumberUrl"`
	RecoveryWebURL                  string               `json:"recoveryWebUrl"`
	RepairPhoneNumberURL            string               `json:"repairPhoneNumberUrl"`
	RepairPhoneNumberWebURL         string               `json:"repairPhoneNumberWebUrl"`
	AboutTwoFactorAuthenticationURL string               `json:"aboutTwoFactorAuthenticationUrl"`
	TwoFactorVerificationSupportURL string               `json:"twoFactorVerificationSupportUrl"`
	HasRecoveryKey                  bool                 `json:"hasRecoveryKey"`
	SupportsRecoveryKey             bool                 `json:"supportsRecoveryKey"`
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

type TwoSVBootArgs struct {
	SupportedPushModes      []string                `json:"supportedPushModes"`
	PhoneNumberVerification PhoneNumberVerification `json:"phoneNumberVerification"`
	AuthFactors             []string                `json:"authFactors"`
	SourceReturnURL         string                  `json:"source_returnurl"`
	SourceAppID             int                     `json:"sourceAppId"`
}

type AdditionalBootArgs struct {
	CanRoute2SV bool `json:"canRoute2sv"`
}
