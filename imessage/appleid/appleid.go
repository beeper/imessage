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
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/rs/zerolog"
	"go.mau.fi/util/random"
	"golang.org/x/net/publicsuffix"

	"github.com/beeper/imessage/imessage/appleid/srp6apple"
)

type Client struct {
	HTTP http.Client
	SCNT map[string]string
	SRP  *srp6apple.SRPClient

	AuthID         string
	AuthSessionID  string
	AuthAttributes []byte

	HashcashParams *HashcashParams
	RememberMe     bool
	Username       string
	InitResp       *InitResponse

	SMSRequestedFrom int
	SMSRequestedMode string
}

func NewClient() *Client {
	jar, _ := cookiejar.New(&cookiejar.Options{
		PublicSuffixList: publicsuffix.List,
	})
	return &Client{
		HTTP: http.Client{
			Jar: jar,
		},
		SCNT:   make(map[string]string),
		SRP:    srp6apple.New(),
		AuthID: generateAuthID(),
	}
}

type fdClientInfo struct {
	UserAgent string `json:"U"`
	Language  string `json:"L"`
	TimeZone  string `json:"Z"`
	Version   string `json:"V"`
	F         string `json:"F,omitempty"`
}

func makeFDClientInfo() string {
	fci, _ := json.Marshal(&fdClientInfo{
		UserAgent: UserAgent,
		Language:  Language,
		TimeZone:  TimeZone,
		Version:   HdrValFDClientInfoVersion,
		//F:       TODO,
	})
	return string(fci)
}

func (cli *Client) addOAuthHeaders(req *http.Request) {
	req.Header.Set("X-Apple-I-FD-Client-Info", makeFDClientInfo())
	req.Header.Set("X-Apple-Domain-Id", "1")
	req.Header.Set("X-Apple-Frame-Id", cli.AuthID)
	if len(cli.AuthAttributes) > 0 {
		req.Header.Set(HdrAuthAttributes, base64.StdEncoding.EncodeToString(cli.AuthAttributes))
	}
	if len(cli.AuthSessionID) > 0 {
		req.Header.Set(HdrAuthSessionID, cli.AuthSessionID)
	}
	req.Header.Set("X-Apple-OAuth-Client-Id", OAuthClientID)
	req.Header.Set("X-Apple-App-Id", OAuthClientID)
	req.Header.Set("X-Apple-OAuth-Client-Type", "firstPartyAuth")
	req.Header.Set("X-Apple-OAuth-Redirect-URI", OAuthRedirectURI)
	req.Header.Set("X-Apple-OAuth-Response-Mode", OAuthResponseMode)
	req.Header.Set("X-Apple-OAuth-Response-Type", OAuthResponseType)
	req.Header.Set("X-Apple-OAuth-State", cli.AuthID)
	req.Header.Set("X-Apple-Widget-Key", OAuthClientID)
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
}

func addNormalHeadersWithoutAPIKey(req *http.Request) {
	req.Header.Set("X-Apple-I-FD-Client-Info", makeFDClientInfo())
	req.Header.Set("X-Apple-I-Request-Context", HdrValRequestContext)
	req.Header.Set("X-Apple-I-TimeZone", TimeZoneName)
	req.Header.Set("Content-Type", "application/json")
}

func addNormalHeaders(req *http.Request) {
	addNormalHeadersWithoutAPIKey(req)
	req.Header.Set("X-Apple-Api-Key", APIKey)
}

func prepareRequest(ctx context.Context, method, url string, body io.Reader) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", UserAgent)
	req.Header.Set("Accept-Language", AcceptLanguage)
	return req, nil
}

func (cli *Client) prepareFetchRequest(ctx context.Context, method, addr string, body []byte) (*http.Request, error) {
	req, err := prepareRequest(ctx, method, addr, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	parsed, err := url.Parse(addr)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Sec-Fetch-Dest", "empty")
	req.Header.Set("Sec-Fetch-Mode", "cors")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	req.Header.Set("Origin", fmt.Sprintf("%s://%s", parsed.Scheme, parsed.Host))
	req.Header.Set("Referer", fmt.Sprintf("%s://%s/", parsed.Scheme, parsed.Host))
	req.Header.Set("Accept", "application/json")
	scnt, ok := cli.SCNT[parsed.Host]
	if ok {
		req.Header.Set(HdrScnt, scnt)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	return req, nil
}

func (cli *Client) prepareHTMLFetchRequest(ctx context.Context, addr string) (*http.Request, error) {
	req, err := cli.prepareFetchRequest(ctx, http.MethodGet, addr, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "text/html")
	return req, nil
}

func prepareIframeRequest(ctx context.Context, url string) (*http.Request, error) {
	req, err := prepareRequest(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", HdrValDocumentAccept)
	req.Header.Set("Referer", AppleIDBaseURL)
	req.Header.Set("Sec-Fetch-Dest", "iframe")
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	req.Header.Set("Sec-Fetch-Site", "same-site")
	return req, nil
}

func prepareDocumentRequest(ctx context.Context, url string) (*http.Request, error) {
	req, err := prepareRequest(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", HdrValDocumentAccept)
	req.Header.Set("Sec-Fetch-Dest", "document")
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	req.Header.Set("Sec-Fetch-Site", "none")
	req.Header.Set("Sec-Fetch-User", "?1")
	return req, nil
}

func generateAuthID() string {
	return fmt.Sprintf("auth-%s-%s-%s-%s-%s", randomLowerString(8), randomLowerString(4), randomLowerString(4), randomLowerString(4), randomLowerString(8))
}

func (cli *Client) doRequest(req *http.Request) (*http.Response, error) {
	resp, err := cli.HTTP.Do(req)
	if err != nil {
		return nil, err
	}

	scnt := resp.Header.Get(HdrScnt)
	if scnt != "" {
		cli.SCNT[req.URL.Host] = scnt
	}
	sessID := resp.Header.Get(HdrAuthSessionID)
	if sessID != "" {
		cli.AuthSessionID = sessID
	}
	authAttributes := resp.Header.Get(HdrAuthAttributes)
	if authAttributes != "" {
		decoded, err := base64.StdEncoding.DecodeString(authAttributes)
		if err == nil {
			cli.AuthAttributes = decoded
		}
	}
	return resp, nil
}

func checkStatus(resp *http.Response, err error) (*http.Response, error) {
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 300 {
		_ = resp.Body.Close()
		return nil, fmt.Errorf("unexpected HTTP %d", resp.StatusCode)
	}
	return resp, nil
}

func readResponseBody(resp *http.Response, err error) ([]byte, error) {
	if err != nil {
		return nil, err
	}
	data, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil {
		return nil, err
	}
	return data, nil
}

func randomLowerString(n int) string {
	return strings.ToLower(random.String(n))
}

var bootArgsRegex = regexp.MustCompile(`<script type="application/json" class="boot_args">([\s\S]+?)</script>`)

func parseBootArgs(data []byte) (*BootArgs, error) {
	matches := bootArgsRegex.FindAllSubmatch(data, 3)
	if len(matches) == 0 {
		return nil, fmt.Errorf("didn't find boot args")
	}
	var bootArgs BootArgs
	return &bootArgs, json.Unmarshal(matches[len(matches)-1][1], &bootArgs)
}

func parseResponseJSON[T any](resp *http.Response, err error) (T, error) {
	defer resp.Body.Close()
	var respData T
	if err != nil {
		return respData, err
	}
	return respData, json.NewDecoder(resp.Body).Decode(&respData)
}

func discardBody(resp *http.Response, err error) error {
	if err != nil {
		return err
	}
	_ = resp.Body.Close()
	return nil
}

func (cli *Client) fetchTwoFactorHTML(ctx context.Context) (*BootArgs, error) {
	authSigninURL := idmsaBaseURL
	// No idea why this is just the base path
	authSigninURL.Path = authBasePath
	prep, err := cli.prepareHTMLFetchRequest(ctx, authSigninURL.String())
	if err != nil {
		return nil, err
	}
	cli.addOAuthHeaders(prep)
	data, err := readResponseBody(checkStatus(cli.doRequest(prep)))
	if err != nil {
		return nil, err
	}
	return parseBootArgs(data)
}

func (cli *Client) fetchAuthIframe(ctx context.Context) (*BootArgs, error) {
	authSigninURL := idmsaBaseURL
	authSigninURL.Path = loginIframePath
	authSigninURL.RawQuery = url.Values{
		"frame_id":      {cli.AuthID},
		"skVersion":     {"7"},
		"iframeId":      {cli.AuthID},
		"client_id":     {OAuthClientID},
		"redirect_uri":  {OAuthRedirectURI},
		"response_type": {OAuthResponseType},
		"response_mode": {OAuthResponseMode},
		"state":         {cli.AuthID},
		"authVersion":   {"latest"},
	}.Encode()
	req, err := prepareIframeRequest(ctx, authSigninURL.String())
	if err != nil {
		return nil, err
	}
	data, err := readResponseBody(checkStatus(cli.doRequest(req)))
	if err != nil {
		return nil, err
	}
	return parseBootArgs(data)
}

func (cli *Client) fetchFrontPage(ctx context.Context) error {
	req, err := prepareDocumentRequest(ctx, "https://appleid.apple.com/")
	if err != nil {
		return err
	}
	return discardBody(checkStatus(cli.doRequest(req)))
}

func (cli *Client) doOAuthRequest(ctx context.Context, method, url string, req any, expectedStatus int, hashcash string) (resp *http.Response, err error) {
	var reqData []byte
	reqData, err = json.Marshal(req)
	if err != nil {
		return
	}
	var prep *http.Request
	prep, err = cli.prepareFetchRequest(ctx, method, url, reqData)
	if err != nil {
		return
	}
	cli.addOAuthHeaders(prep)
	if hashcash != "" {
		prep.Header.Set("X-APPLE-HC", hashcash)
	}
	resp, err = cli.doRequest(prep)
	if err != nil {
		return
	}

	if resp.StatusCode >= 300 && resp.StatusCode != expectedStatus {
		defer resp.Body.Close()
		var body []byte
		body, _ = io.ReadAll(resp.Body)
		zerolog.Ctx(ctx).Error().Str("body", string(body)).Int("status", resp.StatusCode).Msg("unexpected HTTP status")
		err = fmt.Errorf("unexpected HTTP %d", resp.StatusCode)
		return
	}
	return
}

func (cli *Client) doAPIRequest(ctx context.Context, method, url string, req any, expectedStatus int) (resp *http.Response, err error) {
	var reqData []byte
	if method != http.MethodGet && req != nil {
		reqData, err = json.Marshal(req)
		if err != nil {
			return
		}
	}
	var prep *http.Request
	prep, err = cli.prepareFetchRequest(ctx, method, url, reqData)
	if err != nil {
		return nil, err
	}
	addNormalHeaders(prep)
	resp, err = cli.doRequest(prep)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode >= 300 && resp.StatusCode != expectedStatus {
		_ = resp.Body.Close()
		err = fmt.Errorf("unexpected HTTP %d", resp.StatusCode)
		return
	}
	return
}

const rememberMeQueryParam = "isRememberMeEnabled"

func buildURL(base url.URL, path string, query url.Values) string {
	base.Path = path
	if query != nil {
		base.RawQuery = query.Encode()
	}
	return base.String()
}

func (cli *Client) doFederateRequest(ctx context.Context, req *FederateRequest) (*FederateResponse, error) {
	federateURL := buildURL(idmsaBaseURL, federatePath, url.Values{
		rememberMeQueryParam: {strconv.FormatBool(req.RememberMe)},
	})
	return parseResponseJSON[*FederateResponse](
		cli.doOAuthRequest(ctx, http.MethodPost, federateURL, req, http.StatusOK, ""),
	)
}

func (cli *Client) doInitRequest(ctx context.Context, req *InitRequest) (*InitResponse, error) {
	initURL := buildURL(idmsaBaseURL, initPath, nil)
	return parseResponseJSON[*InitResponse](
		cli.doOAuthRequest(ctx, http.MethodPost, initURL, req, http.StatusOK, ""),
	)
}

func (cli *Client) doCompleteRequest(ctx context.Context, req *CompleteRequest, hashcash string) (*CompleteResponse, error) {
	completeURL := buildURL(idmsaBaseURL, completePath, url.Values{
		rememberMeQueryParam: {strconv.FormatBool(req.RememberMe)},
	})
	return parseResponseJSON[*CompleteResponse](
		cli.doOAuthRequest(ctx, http.MethodPost, completeURL, req, http.StatusConflict, hashcash),
	)
}

func (cli *Client) doRerequestTrustedDeviceCodeRequest(ctx context.Context) (*RerequestSecurityCodeResponse, error) {
	rerequestSecurityCodeURL := buildURL(idmsaBaseURL, trustedDeviceSecurityCodePath, nil)
	return parseResponseJSON[*RerequestSecurityCodeResponse](
		cli.doOAuthRequest(ctx, http.MethodPut, rerequestSecurityCodeURL, nil, http.StatusOK, ""),
	)
}

func (cli *Client) doRequestPhoneCodeRequest(ctx context.Context, req *RequestPhoneCodeRequest) (*RequestSecurityCodeResponse, error) {
	requestPhoneCodeURL := buildURL(idmsaBaseURL, requestPhoneCodePath, nil)
	return parseResponseJSON[*RequestSecurityCodeResponse](
		cli.doOAuthRequest(ctx, http.MethodPut, requestPhoneCodeURL, req, http.StatusOK, ""),
	)
}

func (cli *Client) doSubmitPhoneCodeRequest(ctx context.Context, req *SubmitPhoneCodeRequest) (*SubmitPhoneCodeResponse, error) {
	submitPhoneCodeURL := buildURL(idmsaBaseURL, submitPhoneCodePath, nil)
	return parseResponseJSON[*SubmitPhoneCodeResponse](
		cli.doOAuthRequest(ctx, http.MethodPost, submitPhoneCodeURL, req, http.StatusOK, ""),
	)
}

func (cli *Client) doSubmitTrustedDeviceCodeRequest(ctx context.Context, req *SubmitTrustedDeviceCodeRequest) (*SubmitSecurityCodeResponse, error) {
	submitSecurityCodeURL := buildURL(idmsaBaseURL, submitPhoneCodePath, nil)
	return parseResponseJSON[*SubmitSecurityCodeResponse](
		cli.doOAuthRequest(ctx, http.MethodPost, submitSecurityCodeURL, req, http.StatusOK, ""),
	)
}

func (cli *Client) getGSToken(ctx context.Context, expect401 bool) error {
	gsTokenURL := buildURL(appleIDBaseURL, gsTokenPath, nil)
	req, err := cli.prepareFetchRequest(ctx, http.MethodGet, gsTokenURL, nil)
	if err != nil {
		return err
	}
	addNormalHeadersWithoutAPIKey(req)
	resp, err := cli.doRequest(req)
	if err != nil {
		return err
	}
	_ = resp.Body.Close()
	if resp.StatusCode >= 300 && (resp.StatusCode != http.StatusUnauthorized || !expect401) {
		return fmt.Errorf("unexpected HTTP %d", resp.StatusCode)
	}
	return nil
}

func (cli *Client) Prepare(ctx context.Context) error {
	err := cli.fetchFrontPage(ctx)
	if err != nil {
		return fmt.Errorf("failed to fetch front page: %w", err)
	}
	err = cli.getGSToken(ctx, true)
	if err != nil {
		return fmt.Errorf("failed to fetch pre-login token: %w", err)
	}
	bootArgs, err := cli.fetchAuthIframe(ctx)
	if err != nil {
		return fmt.Errorf("failed to fetch auth iframe: %w", err)
	}
	cli.AuthAttributes = bootArgs.Direct.AuthAttributes
	cli.HashcashParams = &bootArgs.Direct.Hashcash
	return nil
}

func (cli *Client) EnterUsername(ctx context.Context, username string, rememberMe bool) error {
	cli.Username = username
	cli.RememberMe = rememberMe
	federateResp, err := cli.doFederateRequest(ctx, &FederateRequest{
		AccountName: username,
		RememberMe:  cli.RememberMe,
	})
	if err != nil {
		return fmt.Errorf("failed to check auth federation: %w", err)
	} else if federateResp.Federated {
		return fmt.Errorf("federated accounts aren't supported")
	}
	initResp, err := cli.doInitRequest(ctx, &InitRequest{
		A:           cli.SRP.ABytes(),
		AccountName: username,
		Protocols:   []string{srp6apple.ProtocolS2K, srp6apple.ProtocolS2KFO},
	})
	if err != nil {
		return fmt.Errorf("failed to initialize auth: %w", err)
	}
	cli.InitResp = initResp
	return nil
}

type TwoFactorInfo struct {
	HasTrustedDevices bool
	PhoneNumberInfo   PhoneNumberVerification
}

func (cli *Client) EnterPassword(ctx context.Context, password string) (*TwoFactorInfo, error) {
	if cli.InitResp == nil {
		return nil, fmt.Errorf("must call EnterUsername before EnterPassword")
	}
	cli.SRP.Compute(cli.Username, password, cli.InitResp.Protocol, cli.InitResp.Iteration, cli.InitResp.Salt, cli.InitResp.B)
	resp, err := cli.doCompleteRequest(ctx, &CompleteRequest{
		AccountName: cli.Username,
		RememberMe:  true,
		M1:          cli.SRP.M1,
		C:           cli.InitResp.C,
		M2:          cli.SRP.M2,
	}, cli.HashcashParams.Compute())
	if err != nil {
		return nil, fmt.Errorf("failed to log in: %w", err)
	} else if resp.AuthType != "hsa2" {
		return nil, fmt.Errorf("unrecognized auth type %q", resp.AuthType)
	}
	twoBootArgs, err := cli.fetchTwoFactorHTML(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch 2FA info: %w", err)
	}
	if !twoBootArgs.Direct.HasTrustedDevices {
		cli.SMSRequestedFrom = twoBootArgs.Direct.TwoSV.PhoneNumberVerification.TrustedPhoneNumber.ID
		cli.SMSRequestedMode = twoBootArgs.Direct.TwoSV.PhoneNumberVerification.TrustedPhoneNumber.PushMode
	}
	return &TwoFactorInfo{
		HasTrustedDevices: twoBootArgs.Direct.HasTrustedDevices,
		PhoneNumberInfo:   twoBootArgs.Direct.TwoSV.PhoneNumberVerification,
	}, nil
}

func (cli *Client) RerequestTrustedDevice2FA(ctx context.Context) error {
	_, err := cli.doRerequestTrustedDeviceCodeRequest(ctx)
	// TODO do something with response?
	return err
}

func (cli *Client) RequestSMS2FA(ctx context.Context, pushMode string, phoneNumID int) error {
	_, err := cli.doRequestPhoneCodeRequest(ctx, &RequestPhoneCodeRequest{
		Mode: pushMode,
		PhoneNumber: PhoneNumberID{
			ID: phoneNumID,
		},
	})
	// Response has no data here

	if err == nil {
		cli.SMSRequestedFrom = phoneNumID
		cli.SMSRequestedMode = pushMode
	}
	return err
}

func (cli *Client) Submit2FA(ctx context.Context, code string) (err error) {
	if cli.SMSRequestedFrom > 0 {
		_, err = cli.doSubmitPhoneCodeRequest(ctx, &SubmitPhoneCodeRequest{
			PhoneNumber: PhoneNumberID{
				ID: cli.SMSRequestedFrom,
			},
			SecurityCode: SecurityCodeWrapper{
				Code: code,
			},
			Mode: cli.SMSRequestedMode,
		})
	} else {
		_, err = cli.doSubmitTrustedDeviceCodeRequest(ctx, &SubmitTrustedDeviceCodeRequest{
			SecurityCode: SecurityCodeWrapper{Code: code},
		})
	}
	if err != nil {
		return err
	}
	err = cli.getGSToken(ctx, false)
	if err != nil {
		return fmt.Errorf("failed to finish auth: %w", err)
	}
	return nil
}

func (cli *Client) GetAppSpecificPasswords(ctx context.Context) (GetAppSpecificPasswordsResponse, error) {
	appSpecificPasswordURL := buildURL(appleIDBaseURL, appSpecificPasswordPath, nil)
	return parseResponseJSON[GetAppSpecificPasswordsResponse](
		cli.doAPIRequest(ctx, http.MethodGet, appSpecificPasswordURL, nil, http.StatusOK),
	)
}

func (cli *Client) DeleteAppSpecificPasswords(ctx context.Context, id int) error {
	appSpecificPasswordURL := buildURL(appleIDBaseURL, fmt.Sprintf("%s/%d", appSpecificPasswordPath, id), nil)
	return discardBody(cli.doAPIRequest(ctx, http.MethodDelete, appSpecificPasswordURL, nil, http.StatusNoContent))
}

func (cli *Client) SubmitStandardAdditionalAuth(ctx context.Context, password string) error {
	appSpecificPasswordURL := buildURL(appleIDBaseURL, additionalAuthenticatePath, nil)
	return discardBody(cli.doAPIRequest(ctx, http.MethodPost, appSpecificPasswordURL, &AdditionalAuthenticateRequest{
		Password: password,
	}, http.StatusNoContent))
}

func (cli *Client) CreateAppSpecificPassword(ctx context.Context, description string) (*CreateAppSpecificPasswordResponse, error) {
	appSpecificPasswordURL := buildURL(appleIDBaseURL, appSpecificPasswordPath, nil)
	resp, err := cli.doAPIRequest(ctx, http.MethodPost, appSpecificPasswordURL, &CreateAppSpecificPasswordRequest{
		Description: description,
	}, http.StatusUnavailableForLegalReasons)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == http.StatusUnavailableForLegalReasons {
		parsed, err := parseResponseJSON[*AdditionalAuthenticationNeededError](resp, nil)
		if err != nil {
			return nil, err
		} else {
			return nil, parsed
		}
	} else {
		return parseResponseJSON[*CreateAppSpecificPasswordResponse](resp, nil)
	}
}
