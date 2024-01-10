package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	_ "net/http/pprof"
	"strings"
	"time"

	"maunium.net/go/mautrix/bridge/status"

	"github.com/beeper/imessage/database"
	"github.com/beeper/imessage/imessage/direct/nacserv"
	"github.com/beeper/imessage/imessage/direct/util/uri"

	"github.com/gorilla/mux"
	"github.com/rs/zerolog"
	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/id"

	"github.com/beeper/imessage/imessage/direct/ids/types"
)

type ProvisioningAPI struct {
	bridge *IMBridge
	log    zerolog.Logger
}

func (prov *ProvisioningAPI) Init() {
	prov.log = prov.bridge.ZLog.With().Str("module", "provisioning").Logger()

	prov.log.Debug().Str("prefix", prov.bridge.Config.Bridge.Provisioning.Prefix).Msg("Enabling provisioning API")
	r := prov.bridge.AS.Router.PathPrefix(prov.bridge.Config.Bridge.Provisioning.Prefix).Subrouter()
	r.Use(prov.AuthMiddleware)
	r.HandleFunc("/v1/login", prov.Login).Methods(http.MethodPost)
	r.HandleFunc("/v1/logout", prov.Logout).Methods(http.MethodPost)
	r.HandleFunc("/v1/reregister", prov.Reregister).Methods(http.MethodPost)
	r.HandleFunc("/v1/set_relay", prov.SetRelay).Methods(http.MethodPost)
	r.HandleFunc("/v1/get_relay", prov.GetRelay).Methods(http.MethodGet)
	r.HandleFunc("/v1/dependent_registrations", prov.GetDependentRegistrations).Methods(http.MethodGet)
	r.HandleFunc("/v1/resolve_identifier/{identifier}", prov.ResolveIdentifier).Methods(http.MethodGet)
	r.HandleFunc("/v1/start_chat", prov.StartChat).Methods(http.MethodPost)
	r.HandleFunc("/v1/default_handle", prov.UpdateDefaultHandle).Methods(http.MethodPost)
	r.HandleFunc("/v1/read_receipts", prov.ToggleReadReceipts).Methods(http.MethodPost)
	r.HandleFunc("/v1/chatwoot_start_chat", prov.ChatwootStartChat).Methods(http.MethodPost)

	if prov.bridge.Config.Bridge.Provisioning.DebugEndpoints {
		prov.log.Debug().Msg("Enabling debug API at /debug")
		r := prov.bridge.AS.Router.PathPrefix("/debug").Subrouter()
		r.Use(prov.AuthMiddleware)
		r.PathPrefix("/pprof").Handler(http.DefaultServeMux)
	}
}

func jsonResponse(w http.ResponseWriter, status int, response any) {
	w.Header().Add("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(response)
}

type responseWrap struct {
	http.ResponseWriter
	statusCode int
}

var _ http.Hijacker = (*responseWrap)(nil)

func (rw *responseWrap) WriteHeader(statusCode int) {
	rw.ResponseWriter.WriteHeader(statusCode)
	rw.statusCode = statusCode
}

func (rw *responseWrap) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hijacker, ok := rw.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, errors.New("response does not implement http.Hijacker")
	}
	return hijacker.Hijack()
}

func (prov *ProvisioningAPI) AuthMiddleware(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log := prov.log.With().Str("method", r.Method).Str("path", r.URL.Path).Logger()
		auth := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if auth != prov.bridge.Config.Bridge.Provisioning.SharedSecret {
			log.Info().Msg("Authentication token does not match shared secret")
			jsonResponse(w, http.StatusForbidden, &mautrix.RespError{
				Err:     "Authentication token does not match shared secret",
				ErrCode: mautrix.MForbidden.ErrCode,
			})
			return
		}
		user := prov.bridge.GetUserByMXID(id.UserID(r.URL.Query().Get("user_id")))
		log = log.With().Str("user_id", user.MXID.String()).Logger()
		start := time.Now()
		wWrap := &responseWrap{w, 200}
		ctx := log.WithContext(r.Context())
		ctx = context.WithValue(ctx, "user", user)
		h.ServeHTTP(wWrap, r.WithContext(ctx))
		log.Info().
			Str("user_id", user.MXID.String()).
			Dur("duration", time.Now().Sub(start)).
			Int("status_code", wWrap.statusCode).
			Msg("Provisioning Access")
	})
}

type ProvisioningResponseStatus string

const (
	ProvisioningResponseStatusTwoFactor ProvisioningResponseStatus = "two-factor"
	ProvisioningResponseStatusLoggedIn  ProvisioningResponseStatus = "logged-in"
)

type ProvisioningResponse struct {
	Status        ProvisioningResponseStatus `json:"status"`
	HasPhoneAlias bool                       `json:"has_phone_alias"`
}

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Code     string `json:"code,omitempty"`
}

func (prov *ProvisioningAPI) Login(w http.ResponseWriter, r *http.Request) {
	user := r.Context().Value("user").(*User)
	if user.IsLoggedIn() && !user.NeedsRefresh() && user.IsIDSRegistered() {
		prov.log.Info().Msg("User already logged in")
		jsonResponse(w, http.StatusConflict, &mautrix.RespError{
			Err:     "User ID is already logged in",
			ErrCode: "COM.BEEPER.IMESSAGE.ALREADY_LOGGED_IN",
		})
		return
	}

	var loginRequest LoginRequest
	if requestData, err := io.ReadAll(r.Body); err != nil {
		jsonResponse(w, http.StatusBadRequest, &mautrix.MBadJSON)
		return
	} else if err := json.Unmarshal(requestData, &loginRequest); err != nil {
		prov.log.Warn().Err(err).Msg("Got error parsing request")
		jsonResponse(w, http.StatusBadRequest, &mautrix.MBadJSON)
		return
	}

	if loginRequest.Username == "" || loginRequest.Password == "" {
		jsonResponse(w, http.StatusConflict, &mautrix.RespError{
			Err:     "Username and password must be provided",
			ErrCode: mautrix.MInvalidParam.ErrCode,
		})
		return
	}

	err := user.Start()
	if errors.Is(err, ErrNoNAC) {
		jsonResponse(w, http.StatusBadRequest, &mautrix.RespError{
			Err:     "Must provide registration code before login",
			ErrCode: mautrix.MBadState.ErrCode,
		})
		return
	} else if err != nil {
		jsonResponse(w, http.StatusInternalServerError, &mautrix.RespError{
			Err:     "Internal server error preparing login",
			ErrCode: "M_UNKNOWN",
		})
	}

	err = user.IM.Login(r.Context(), loginRequest.Username, loginRequest.Password, loginRequest.Code)
	if errors.Is(err, types.Err2FARequired) && loginRequest.Code == "" {
		jsonResponse(w, http.StatusOK, ProvisioningResponse{Status: ProvisioningResponseStatusTwoFactor})
		return
	} else if errors.Is(err, types.ErrInvalidNameOrPassword) {
		errorMsg := "Invalid username or password."
		if loginRequest.Code != "" {
			errorMsg = "Login with 2FA code failed. Please check your 2FA code and try again or check your account on https://appleid.apple.com."
		}
		jsonResponse(w, http.StatusForbidden, &mautrix.RespError{
			Err:     errorMsg,
			ErrCode: mautrix.MForbidden.ErrCode,
		})
		return
	} else if err != nil {
		prov.log.Warn().Err(err).Msg("Login failed")
		jsonResponse(w, http.StatusForbidden, &mautrix.RespError{
			Err:     fmt.Sprintf("Login failed: %s", err),
			ErrCode: mautrix.MForbidden.ErrCode,
		})
		return
	}

	prov.log.Info().Msg("Login success!")
	user.tryAutomaticDoublePuppeting()
	user.Update(context.TODO())

	hasPhoneAlias := false
	for _, h := range user.IM.User.Handles {
		if h.Scheme == uri.SchemeTel {
			hasPhoneAlias = true
		}
	}

	go user.broadcastHandlesToRecentConversations()

	jsonResponse(w, http.StatusOK, &ProvisioningResponse{
		Status:        ProvisioningResponseStatusLoggedIn,
		HasPhoneAlias: hasPhoneAlias,
	})
}

func (prov *ProvisioningAPI) Logout(w http.ResponseWriter, r *http.Request) {
	user := r.Context().Value("user").(*User)
	if user.AppleRegistration == nil {
		prov.log.Warn().Msg("User isn't logged in")
		jsonResponse(w, http.StatusConflict, &mautrix.RespError{
			Err:     "User ID isn't logged in",
			ErrCode: "COM.BEEPER.IMESSAGE.NOT_LOGGED_IN",
		})
		return
	}

	user.Logout()

	jsonResponse(w, http.StatusOK, map[string]any{})
}

type ReregisterRequest struct {
	Force         *bool `json:"force,omitempty"`
	ClearIDSCache bool  `json:"clear_ids_cache,omitempty"`
}

func (prov *ProvisioningAPI) Reregister(w http.ResponseWriter, r *http.Request) {
	log := zerolog.Ctx(r.Context())
	user := r.Context().Value("user").(*User)
	if !user.HasValidAuthCerts() {
		log.Warn().Msg("User isn't logged in")
		jsonResponse(w, http.StatusConflict, &mautrix.RespError{
			Err:     "User ID isn't logged in",
			ErrCode: "COM.BEEPER.IMESSAGE.NOT_LOGGED_IN",
		})
		return
	}

	var req ReregisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Warn().Err(err).Msg("Got error parsing request")
		jsonResponse(w, http.StatusBadRequest, &mautrix.MBadJSON)
		return
	}
	force := true
	if req.Force != nil {
		force = *req.Force
	}

	err := user.IM.RegisterIDS(r.Context(), force)
	if err != nil {
		log.Err(err).Msg("Failed to reregister IDS")

		if errors.Is(err, nacserv.ErrProviderNotReachable) {
			jsonResponse(w, http.StatusBadRequest, &mautrix.RespError{
				Err:     "Invalid registration code or provider not reachable",
				ErrCode: "COM.BEEPER.BAD_REGISTRATION_CODE",
			})
		} else {
			jsonResponse(w, http.StatusInternalServerError, &mautrix.RespError{
				ErrCode: "M_UNKNOWN",
				Err:     "Internal error",
			})
		}
		return
	}
	if req.ClearIDSCache {
		if err = user.IM.IDSCache.Clear(r.Context()); err != nil {
			log.Err(err).Msg("Failed to clear IDS cache after reregistering")
		}
		if err = user.IM.RerouteHistory.Clear(r.Context()); err != nil {
			log.Err(err).Msg("Failed to clear reroute history after reregistering")
		}
	}
	jsonResponse(w, http.StatusOK, map[string]any{})
}

type ResolveIdentifierResponse struct {
	Identifier string `json:"identifier"`
	Protocol   string `json:"protocol"`
}

func (prov *ProvisioningAPI) ResolveIdentifier(w http.ResponseWriter, r *http.Request) {
	user := r.Context().Value("user").(*User)
	if user.MXID != id.UserID(r.URL.Query().Get("user_id")) {
		prov.log.Info().Msg("User ID does not match")
		jsonResponse(w, http.StatusForbidden, &mautrix.MForbidden)
		return
	}

	if !user.IsLoggedIn() {
		prov.log.Warn().Msg("User isn't logged in")
		jsonResponse(w, http.StatusConflict, &mautrix.RespError{
			Err:     "User ID isn't logged in",
			ErrCode: "COM.BEEPER.IMESSAGE.NOT_LOGGED_IN",
		})
		return
	}

	handle := r.URL.Query().Get("handle")
	var handleURI *uri.ParsedURI
	if handle != "" {
		parsedURI, err := uri.ParseURI(handle)
		if err != nil {
			prov.log.Warn().Err(err).Msg("Got error parsing handle")
			jsonResponse(w, http.StatusBadRequest, &mautrix.RespError{
				Err:     fmt.Sprintf("Got error parsing handle: %s", err),
				ErrCode: mautrix.MInvalidParam.ErrCode,
			})
		}
		handleURI = &parsedURI
	}

	identifier, _ := mux.Vars(r)["identifier"]
	log := zerolog.Ctx(r.Context()).With().Str("identifier", identifier).Str("action", "resolve identifier").Logger()
	ctx := log.WithContext(r.Context())
	found, notFound, err := user.IM.ResolveIdentifiers(ctx, r.URL.Query().Get("force") == "true", handleURI, identifier)
	if err != nil {
		prov.log.Warn().Err(err).Msg("Got error looking up identifier")
		jsonResponse(w, http.StatusBadRequest, &mautrix.RespError{
			Err:     fmt.Sprintf("Got error resolving identifier: %s", err),
			ErrCode: mautrix.MInvalidParam.ErrCode,
		})
		return
	}

	if len(found) == 0 {
		if user.IM.User.SMSForwarding != nil && user.IM.User.SMSForwarding.Token != nil {
			parsedURI, err := uri.ParseIdentifier(identifier, uri.ParseOutgoingSMSForward)
			log = log.With().Str("parsed_uri", parsedURI.String()).Err(err).Logger()
			if err == nil {
				log.Debug().Msg("Identifier was not on iMessage, but is a phone number and SMS forwarding is available")
				jsonResponse(w, http.StatusOK, &ResolveIdentifierResponse{
					Identifier: identifier,
					Protocol:   "imessagego-sms",
				})
				return
			} else {
				log.Debug().Msg("Identifier was not on iMessage and SMS forwarding is available but it's not a phone number")
			}
		} else {
			log.Debug().Msg("Identifier was not on iMessage and SMS forwarding is not available")
		}
		jsonResponse(w, http.StatusNotFound, &mautrix.RespError{
			Err:     fmt.Sprintf("The server said %s is not on iMessage", notFound[0]),
			ErrCode: "COM.BEEPER.IMESSAGE.NOT_ON_IMESSAGE",
		})
		return
	}

	jsonResponse(w, http.StatusOK, &ResolveIdentifierResponse{
		Identifier: found[0].String(),
		Protocol:   "imessagego",
	})
}

type SetRelayRequest struct {
	Token string `json:"token"`
	URL   string `json:"url"`
}

func (prov *ProvisioningAPI) SetRelay(w http.ResponseWriter, r *http.Request) {
	log := zerolog.Ctx(r.Context())
	var req SetRelayRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Warn().Err(err).Msg("Got error parsing request")
		jsonResponse(w, http.StatusBadRequest, &mautrix.MBadJSON)
		return
	}

	if req.Token == prov.bridge.DB.KV.Get(database.KVNACServToken) && req.URL == prov.bridge.DB.KV.Get(database.KVNACServURL) {
		log.Info().
			Str("url", req.URL).
			Str("token", req.Token[:10]+"…").
			Msg("url and token are unchanged")

		jsonResponse(w, http.StatusOK, map[string]any{})
		return
	}

	// Make a temporary client and fetch versions with it
	cli := &nacserv.Client{
		URL:     req.URL,
		Token:   req.Token,
		IsRelay: true,
	}
	user := r.Context().Value("user").(*User)
	if strings.HasPrefix(cli.URL, "https://registration-relay.beeper") {
		cli.BeeperToken = user.bridge.Config.Bridge.Provisioning.SharedSecret
	}
	timeoutCtx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	versions, err := cli.FetchVersions(timeoutCtx)
	cancel()
	if err != nil {
		log.Err(err).
			Str("url", req.URL).
			Str("token", req.Token[:10]+"…").
			Msg("Failed to fetch versions from relay")
		if errors.Is(err, nacserv.ErrProviderNotReachable) || errors.Is(err, context.Canceled) {
			jsonResponse(w, http.StatusBadRequest, &mautrix.RespError{
				Err:     "Invalid registration code or provider not reachable",
				ErrCode: "COM.BEEPER.BAD_REGISTRATION_CODE",
			})
		} else {
			jsonResponse(w, http.StatusBadRequest, &mautrix.RespError{
				Err:     "Failed to check registration code",
				ErrCode: "COM.BEEPER.BAD_REGISTRATION_CODE",
			})
		}
		return
	}
	zerolog.Ctx(r.Context()).Info().
		Str("url", req.URL).
		Str("token", req.Token[:10]+"…").
		Bool("user_has_im", user.IM != nil).
		Object("versions", versions).
		Msg("Successfully fetched versions from relay")

	// Now that we know the relay exists, save it to the database
	prov.bridge.DB.KV.Set(database.KVNACServURL, req.URL)
	prov.bridge.DB.KV.Set(database.KVNACServToken, req.Token)
	if user.bridge.DB.KV.Get(database.KVHackyNACErrorPersistence) != "" {
		if user.AppleRegistration == nil {
			user.bridge.SendGlobalBridgeState(status.BridgeState{StateEvent: status.StateUnconfigured})
		}
		user.bridge.DB.KV.Delete(database.KVHackyNACErrorPersistence)
	}

	if user.IM != nil {
		user.IM.NACServ = user.makeNACClient()
		if user.HasValidAuthCerts() {
			err := user.IM.RegisterIDS(r.Context(), true)
			if err != nil {
				log.Err(err).Msg("Failed to reregister IDS")

				if errors.Is(err, nacserv.ErrProviderNotReachable) {
					jsonResponse(w, http.StatusBadRequest, &mautrix.RespError{
						Err:     "Invalid registration code or provider not reachable",
						ErrCode: "COM.BEEPER.BAD_REGISTRATION_CODE",
					})
				} else {
					jsonResponse(w, http.StatusInternalServerError, &mautrix.RespError{
						ErrCode: "M_UNKNOWN",
						Err:     "Internal error",
					})
				}
				return
			}
		}
	}
	jsonResponse(w, http.StatusOK, map[string]any{})
}

func (prov *ProvisioningAPI) GetRelay(w http.ResponseWriter, r *http.Request) {
	jsonResponse(w, http.StatusOK, SetRelayRequest{
		Token: prov.bridge.DB.KV.Get(database.KVNACServToken),
		URL:   prov.bridge.DB.KV.Get(database.KVNACServURL),
	})
}

func (prov *ProvisioningAPI) GetDependentRegistrations(w http.ResponseWriter, r *http.Request) {
	user := r.Context().Value("user").(*User)
	if user.MXID != id.UserID(r.URL.Query().Get("user_id")) {
		prov.log.Info().Msg("User ID does not match")
		jsonResponse(w, http.StatusForbidden, &mautrix.MForbidden)
		return
	}

	if !user.IsLoggedIn() {
		prov.log.Warn().Msg("User isn't logged in")
		jsonResponse(w, http.StatusConflict, &mautrix.RespError{
			Err:     "User ID isn't logged in",
			ErrCode: "COM.BEEPER.IMESSAGE.NOT_LOGGED_IN",
		})
		return
	}

	resp, err := user.IM.User.GetDependentRegistrations(r.Context(), user.IM.User.ProfileID)
	if err != nil {
		prov.log.Err(err).Msg("Failed to get dependent registrations")
		jsonResponse(w, http.StatusInternalServerError, &mautrix.RespError{
			Err:     "Internal server error getting dependent registrations",
			ErrCode: "M_UNKNOWN",
		})
		return
	} else {
		jsonResponse(w, http.StatusOK, resp)
	}
}

func (prov *ProvisioningAPI) StartChat(w http.ResponseWriter, r *http.Request) {
	user := r.Context().Value("user").(*User)
	if user.MXID != id.UserID(r.URL.Query().Get("user_id")) {
		prov.log.Info().Msg("User ID does not match")
		jsonResponse(w, http.StatusForbidden, &mautrix.MForbidden)
		return
	}

	if !user.IsLoggedIn() {
		prov.log.Warn().Msg("User isn't logged in")
		jsonResponse(w, http.StatusConflict, &mautrix.RespError{
			Err:     "User ID isn't logged in",
			ErrCode: "COM.BEEPER.IMESSAGE.NOT_LOGGED_IN",
		})
		return
	}

	requestData, _ := io.ReadAll(r.Body)
	var startChatRequest StartChatRequest
	if err := json.Unmarshal(requestData, &startChatRequest); err != nil {
		prov.log.Warn().Err(err).Msg("Got error parsing request")
		jsonResponse(w, http.StatusBadRequest, &mautrix.MBadJSON)
		return
	}

	res, err := user.startChat(startChatRequest)
	if err != nil {
		prov.log.Warn().Err(err).Msg("Got error starting chat")
		jsonResponse(w, http.StatusBadRequest, &mautrix.RespError{
			Err:     fmt.Sprintf("Got error starting chat: %s", err),
			ErrCode: mautrix.MInvalidParam.ErrCode,
		})
		return
	}

	jsonResponse(w, http.StatusOK, res)
}

type UpdateDefaultHandleRequest struct {
	Handle string `json:"handle"`
}

func (prov *ProvisioningAPI) UpdateDefaultHandle(w http.ResponseWriter, r *http.Request) {
	user := r.Context().Value("user").(*User)
	if user.MXID != id.UserID(r.URL.Query().Get("user_id")) {
		prov.log.Info().Msg("User ID does not match")
		jsonResponse(w, http.StatusForbidden, &mautrix.MForbidden)
		return
	}

	if !user.IsLoggedIn() {
		prov.log.Warn().Msg("User isn't logged in")
		jsonResponse(w, http.StatusConflict, &mautrix.RespError{
			Err:     "User ID isn't logged in",
			ErrCode: "COM.BEEPER.IMESSAGE.NOT_LOGGED_IN",
		})
		return
	}

	var updatedDefaultHandleRequest UpdateDefaultHandleRequest
	if err := json.NewDecoder(r.Body).Decode(&updatedDefaultHandleRequest); err != nil {
		prov.log.Warn().Err(err).Msg("Got error parsing request")
		jsonResponse(w, http.StatusBadRequest, &mautrix.MBadJSON)
		return
	}

	parsedHandle, err := uri.ParseURI(updatedDefaultHandleRequest.Handle)
	if err != nil {
		prov.log.Warn().Err(err).Msg("Got error parsing handle")
		jsonResponse(w, http.StatusBadRequest, &mautrix.RespError{
			Err:     fmt.Sprintf("Got error parsing handle: %s", err),
			ErrCode: mautrix.MInvalidParam.ErrCode,
		})
		return
	}

	if err = user.setDefaultHandle(parsedHandle); err != nil {
		prov.log.Err(err).Msg("Failed to set default handle")
		jsonResponse(w, http.StatusBadRequest, &mautrix.RespError{
			Err:     "Internal server error setting default handle",
			ErrCode: "M_UNKNOWN",
		})
	}

	jsonResponse(w, http.StatusOK, map[string]any{})
}

type ToggleReadReceiptsRequest struct {
	HideReadReceipts bool `json:"hide_read_receipts"`
}

func (prov *ProvisioningAPI) ToggleReadReceipts(w http.ResponseWriter, r *http.Request) {
	user := r.Context().Value("user").(*User)
	if user.MXID != id.UserID(r.URL.Query().Get("user_id")) {
		prov.log.Info().Msg("User ID does not match")
		jsonResponse(w, http.StatusForbidden, &mautrix.MForbidden)
		return
	}

	if !user.IsLoggedIn() {
		prov.log.Warn().Msg("User isn't logged in")
		jsonResponse(w, http.StatusConflict, &mautrix.RespError{
			Err:     "User ID isn't logged in",
			ErrCode: "COM.BEEPER.IMESSAGE.NOT_LOGGED_IN",
		})
		return
	}

	var reqData ToggleReadReceiptsRequest
	if err := json.NewDecoder(r.Body).Decode(&reqData); err != nil {
		prov.log.Warn().Err(err).Msg("Got error parsing request")
		jsonResponse(w, http.StatusBadRequest, &mautrix.MBadJSON)
	} else if err := user.setHideReadReceipts(reqData.HideReadReceipts); err != nil {
		prov.log.Err(err).Msg("Failed to set hide read receipts flag")
		jsonResponse(w, http.StatusBadRequest, &mautrix.RespError{
			Err:     "Internal server error toggling read receipts",
			ErrCode: "M_UNKNOWN",
		})
	} else {
		jsonResponse(w, http.StatusOK, map[string]any{
			"hide_read_receipts": user.HideReadReceipts,
		})
	}
}

type ChatwootStartChatRequest struct {
	PhoneNumber string `json:"phone_number"`
	Email       string `json:"email"`
}

func (prov *ProvisioningAPI) ChatwootStartChat(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	user := ctx.Value("user").(*User)
	if user.MXID != id.UserID(r.URL.Query().Get("user_id")) {
		prov.log.Info().Msg("User ID does not match")
		jsonResponse(w, http.StatusForbidden, &mautrix.MForbidden)
		return
	}

	if !user.IsLoggedIn() {
		prov.log.Warn().Msg("User isn't logged in")
		jsonResponse(w, http.StatusConflict, &mautrix.RespError{
			Err:     "User ID isn't logged in",
			ErrCode: "COM.BEEPER.IMESSAGE.NOT_LOGGED_IN",
		})
		return
	}

	var startChatRequest ChatwootStartChatRequest
	if err := json.NewDecoder(r.Body).Decode(&startChatRequest); err != nil {
		prov.log.Warn().Err(err).Msg("Got error parsing request")
		jsonResponse(w, http.StatusBadRequest, &mautrix.MBadJSON)
		return
	}

	zerolog.Ctx(r.Context()).Info().
		Str("phone_number", startChatRequest.PhoneNumber).
		Str("email", startChatRequest.Email).
		Msg("Got start chat request from Chatwoot bot")

	var identifiers []string
	if startChatRequest.PhoneNumber != "" {
		identifiers = append(identifiers, startChatRequest.PhoneNumber)
	}
	if startChatRequest.Email != "" {
		identifiers = append(identifiers, startChatRequest.Email)
	}

	if len(identifiers) == 0 {
		jsonResponse(w, http.StatusBadRequest, &mautrix.RespError{
			Err:     "At least one of phone number or email must be provided",
			ErrCode: mautrix.MInvalidParam.ErrCode,
		})
		return
	}

	found, _, err := user.IM.ResolveIdentifiers(ctx, false, nil, identifiers...)
	if err != nil {
		jsonResponse(w, http.StatusBadRequest, &mautrix.RespError{
			Err:     fmt.Sprintf("Got error resolving identifiers: %s", err),
			ErrCode: mautrix.MInvalidParam.ErrCode,
		})
		return
	}

	if len(found) == 0 {
		jsonResponse(w, http.StatusNotFound, &mautrix.RespError{
			Err:     fmt.Sprintf("Neither phone number nor email found on iMessage"),
			ErrCode: mautrix.MInvalidParam.ErrCode,
		})
	}

	// Default to sending to phone number if there is one.
	res, err := user.startChat(StartChatRequest{
		Identifiers: []string{found[0].String()},
	})
	if err != nil {
		prov.log.Warn().Err(err).Msg("Got error starting chat")
		jsonResponse(w, http.StatusBadRequest, &mautrix.RespError{
			Err:     fmt.Sprintf("Got error starting chat: %s", err),
			ErrCode: mautrix.MInvalidParam.ErrCode,
		})
		return
	}

	jsonResponse(w, http.StatusOK, res)
}
