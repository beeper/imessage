package types

// ========== WARNING ==========
//
// This file is auto-generated by generator.go. Do not edit!
//
// Instead, edit errors.json and run generator.go.
//
// errors.json was created using the data found in the JavaScript file for web
// FaceTime.
//
// ==============================

import "fmt"

const (
	IDSStatusSuccess                              IDSStatus = 0
	IDSStatusNoResultCode                         IDSStatus = 1
	IDSStatusLegacyTunnelBadRequest               IDSStatus = 400
	IDSStatusParseFailure                         IDSStatus = 1000
	IDSStatusInvalidField                         IDSStatus = 1001
	IDSStatusMessageRemoved                       IDSStatus = 1002
	IDSStatusMessageInhibited                     IDSStatus = 1003
	IDSStatusDecodeFailureBase64                  IDSStatus = 1004
	IDSStatusDecodeFailureHex                     IDSStatus = 1005
	IDSStatusAuthFailure                          IDSStatus = 1006
	IDSStatusStorageFailure                       IDSStatus = 1007
	IDSStatusInternalError                        IDSStatus = 5001
	IDSStatusServerTooBusy                        IDSStatus = 5004
	IDSStatusBadPushToken                         IDSStatus = 5006
	IDSStatusMissingRequiredKey                   IDSStatus = 5008
	IDSStatusBadSignature                         IDSStatus = 5032
	IDSStatusWebTunnelServiceDisabled             IDSStatus = 5200
	IDSStatusWebTunnelServiceInternalError        IDSStatus = 5201
	IDSStatusWebTunnelServiceTooBusy              IDSStatus = 5202
	IDSStatusWebTunnelServiceMissingKey           IDSStatus = 5203
	IDSStatusWebTunnelServiceMalformedURL         IDSStatus = 5204
	IDSStatusWebTunnelServiceUnauthorizedURL      IDSStatus = 5205
	IDSStatusWebTunnelServiceResponseTooLarge     IDSStatus = 5206
	IDSStatusWebTunnelServiceOriginServerTimeout  IDSStatus = 5207
	IDSStatusUnknownCommand                       IDSStatus = 6000
	IDSStatusRateLimited                          IDSStatus = 7000
	IDSStatusServiceDisabled                      IDSStatus = 7001
	IDSStatusAliasEmpty                           IDSStatus = 5035
	IDSStatusEmailInvalid                         IDSStatus = 5036
	IDSStatusEmailInRequired                      IDSStatus = 5037
	IDSStatusEmailInUse                           IDSStatus = 5038
	IDSStatusEmailInUseAlt                        IDSStatus = 5055
	IDSStatusEmailLegacyOrInactive                IDSStatus = 5088
	IDSStatusEmailVetted                          IDSStatus = 5051
	IDSStatusEmailNotVetted                       IDSStatus = 5052
	IDSStatusHTTPSuccess                          IDSStatus = 200
	IDSStatusBadRequest                           IDSStatus = 5003
	IDSStatusCancelledByUser                      IDSStatus = 5013
	IDSStatusUnsupportedManagedID                 IDSStatus = 5100
	IDSStatusUnsupportedAuditorID                 IDSStatus = 5103
	IDSStatusValidationFailure                    IDSStatus = 8000
	IDSStatusValidationCertFetchFailure           IDSStatus = 8001
	IDSStatusNoNetworkAvailable                   IDSStatus = 10000
	IDSStatusFailedRequest                        IDSStatus = 20000
	IDSStatusPushRequestFailed                    IDSStatus = 20001
	IDSStatusActionDoNotRetry                     IDSStatus = 6001
	IDSStatusActionRetryWithDelay                 IDSStatus = 6002
	IDSStatusActionRetryWithCorrectedTime         IDSStatus = 6003
	IDSStatusActionRetryWithNewAbsintheContext    IDSStatus = 6004
	IDSStatusActionRefreshCredentials             IDSStatus = 6005
	IDSStatusActionRefreshRegistration            IDSStatus = 6006
	IDSStatusActionAuthenticationFailed           IDSStatus = 6008
	IDSStatusActionPermanentFailure               IDSStatus = 6009
	IDSStatusActionIdMSSessionRefreshException    IDSStatus = 6010
	IDSStatusActionProvisionLimitReached          IDSStatus = 6011
	IDSStatusActionProvisionReplaceAllSessionKeys IDSStatus = 6012
	IDSStatusUnauthenticated                      IDSStatus = 5000
	IDSStatusInvalidNameOrPassword                IDSStatus = 5012
	IDSStatusAccountDisabledForSecurityReasons    IDSStatus = 5046
	IDSStatusVersionMismatch                      IDSStatus = 5002
	IDSStatusNoSuchPlayerID                       IDSStatus = 5005
	IDSStatusNoSuchAchievement                    IDSStatus = 5007
	IDSStatusMissingRequiredHeader                IDSStatus = 5009
	IDSStatusUnrecognizedGameDescriptorHeaders    IDSStatus = 5010
	IDSStatusMustAcceptTermsOfService             IDSStatus = 5011
	IDSStatusNoSuchFriendRelationship             IDSStatus = 5014
	IDSStatusNoSuchAlias                          IDSStatus = 5015
	IDSStatusEmailNotInNetwork                    IDSStatus = 5016
	IDSStatusRequestDisallowed                    IDSStatus = 5017
	IDSStatusNoSuchRID                            IDSStatus = 5018
	IDSStatusNoSuchGame                           IDSStatus = 5019
	IDSStatusMixedResponse                        IDSStatus = 5020
	IDSStatusProfileExists                        IDSStatus = 5021
	IDSStatusAliasExists                          IDSStatus = 5022
	IDSStatusAccountNameNotEmailAddress           IDSStatus = 5023
	IDSStatusAliasTooLong                         IDSStatus = 5024
	IDSStatusAliasTooFrequentUpdates              IDSStatus = 5025
	IDSStatusPlayerStatusNotAllowed               IDSStatus = 5026
	IDSStatusPlayerStatusTooLong                  IDSStatus = 5027
	IDSStatusNoSuchBucketID                       IDSStatus = 5028
	IDSStatusAuthenticatedNotAuthorized           IDSStatus = 5029
	IDSStatusNoPushTokenForID                     IDSStatus = 5030
	IDSStatusPushPayloadTooBig                    IDSStatus = 5031
	IDSStatusNewSignatureRequired                 IDSStatus = 5033
	IDSStatusNewLinkedSignatureRequired           IDSStatus = 5099
	IDSStatusNewRegistrationRequred               IDSStatus = 5034
	IDSStatusExpiredRelayToken                    IDSStatus = 5039
	IDSStatusBadSessionToken                      IDSStatus = 5040
	IDSStatusExpiredSessionToken                  IDSStatus = 5041
	IDSStatusForcePasswordChange                  IDSStatus = 5047
	IDSStatusProfileBlocklisted                   IDSStatus = 5048
	IDSStatusSelfVersionTooOld                    IDSStatus = 5057
	IDSStatusPeerVersionTooOld                    IDSStatus = 5058
	IDSStatusPhoneNumberTooShort                  IDSStatus = 5059
	IDSStatusPhoneNumberTooLong                   IDSStatus = 5060
	IDSStatusPhoneNumberBadCountryCode            IDSStatus = 5061
	IDSStatusPhoneNumberMalformed                 IDSStatus = 5062
	IDSStatusBadInvitationContext                 IDSStatus = 5063
	IDSStatusUnpromotablePhoneNumber              IDSStatus = 5064
	IDSStatusRegistrationLimitReached             IDSStatus = 5068
	IDSStatusAbsintheInternalError                IDSStatus = 5078
	IDSStatusAbsintheSessionCreationFailed        IDSStatus = 5079
	IDSStatusAbsintheValidationFailed             IDSStatus = 5080
	IDSStatusAlbertInternalError                  IDSStatus = 5089
	IDSStatusAlbertValidationFailed               IDSStatus = 5090
	IDSStatusNeedsBreakBeforeMake                 IDSStatus = 5076
	IDSStatusBadCert                              IDSStatus = 5085
	IDSStatusBadNonce                             IDSStatus = 5086
	IDSStatusBadNonceTimestamp                    IDSStatus = 5087
	IDSStatusServerRegistrationUnsupported        IDSStatus = 5092
	IDSStatusNone                                 IDSStatus = 255
)

func (s IDSStatus) String() string {
	switch s {
	case IDSStatusSuccess:
		return "Success"
	case IDSStatusNoResultCode:
		return "NoResultCode"
	case IDSStatusLegacyTunnelBadRequest:
		return "LegacyTunnelBadRequest"
	case IDSStatusParseFailure:
		return "ParseFailure"
	case IDSStatusInvalidField:
		return "InvalidField"
	case IDSStatusMessageRemoved:
		return "MessageRemoved"
	case IDSStatusMessageInhibited:
		return "MessageInhibited"
	case IDSStatusDecodeFailureBase64:
		return "DecodeFailureBase64"
	case IDSStatusDecodeFailureHex:
		return "DecodeFailureHex"
	case IDSStatusAuthFailure:
		return "AuthFailure"
	case IDSStatusStorageFailure:
		return "StorageFailure"
	case IDSStatusInternalError:
		return "InternalError"
	case IDSStatusServerTooBusy:
		return "ServerTooBusy"
	case IDSStatusBadPushToken:
		return "BadPushToken"
	case IDSStatusMissingRequiredKey:
		return "MissingRequiredKey"
	case IDSStatusBadSignature:
		return "BadSignature"
	case IDSStatusWebTunnelServiceDisabled:
		return "WebTunnelServiceDisabled"
	case IDSStatusWebTunnelServiceInternalError:
		return "WebTunnelServiceInternalError"
	case IDSStatusWebTunnelServiceTooBusy:
		return "WebTunnelServiceTooBusy"
	case IDSStatusWebTunnelServiceMissingKey:
		return "WebTunnelServiceMissingKey"
	case IDSStatusWebTunnelServiceMalformedURL:
		return "WebTunnelServiceMalformedURL"
	case IDSStatusWebTunnelServiceUnauthorizedURL:
		return "WebTunnelServiceUnauthorizedURL"
	case IDSStatusWebTunnelServiceResponseTooLarge:
		return "WebTunnelServiceResponseTooLarge"
	case IDSStatusWebTunnelServiceOriginServerTimeout:
		return "WebTunnelServiceOriginServerTimeout"
	case IDSStatusUnknownCommand:
		return "UnknownCommand"
	case IDSStatusRateLimited:
		return "RateLimited"
	case IDSStatusServiceDisabled:
		return "ServiceDisabled"
	case IDSStatusAliasEmpty:
		return "AliasEmpty"
	case IDSStatusEmailInvalid:
		return "EmailInvalid"
	case IDSStatusEmailInRequired:
		return "EmailInRequired"
	case IDSStatusEmailInUse:
		return "EmailInUse"
	case IDSStatusEmailInUseAlt:
		return "EmailInUseAlt"
	case IDSStatusEmailLegacyOrInactive:
		return "EmailLegacyOrInactive"
	case IDSStatusEmailVetted:
		return "EmailVetted"
	case IDSStatusEmailNotVetted:
		return "EmailNotVetted"
	case IDSStatusHTTPSuccess:
		return "HTTPSuccess"
	case IDSStatusBadRequest:
		return "BadRequest"
	case IDSStatusCancelledByUser:
		return "CancelledByUser"
	case IDSStatusUnsupportedManagedID:
		return "UnsupportedManagedID"
	case IDSStatusUnsupportedAuditorID:
		return "UnsupportedAuditorID"
	case IDSStatusValidationFailure:
		return "ValidationFailure"
	case IDSStatusValidationCertFetchFailure:
		return "ValidationCertFetchFailure"
	case IDSStatusNoNetworkAvailable:
		return "NoNetworkAvailable"
	case IDSStatusFailedRequest:
		return "FailedRequest"
	case IDSStatusPushRequestFailed:
		return "PushRequestFailed"
	case IDSStatusActionDoNotRetry:
		return "ActionDoNotRetry"
	case IDSStatusActionRetryWithDelay:
		return "ActionRetryWithDelay"
	case IDSStatusActionRetryWithCorrectedTime:
		return "ActionRetryWithCorrectedTime"
	case IDSStatusActionRetryWithNewAbsintheContext:
		return "ActionRetryWithNewAbsintheContext"
	case IDSStatusActionRefreshCredentials:
		return "ActionRefreshCredentials"
	case IDSStatusActionRefreshRegistration:
		return "ActionRefreshRegistration"
	case IDSStatusActionAuthenticationFailed:
		return "ActionAuthenticationFailed"
	case IDSStatusActionPermanentFailure:
		return "ActionPermanentFailure"
	case IDSStatusActionIdMSSessionRefreshException:
		return "ActionIdMSSessionRefreshException"
	case IDSStatusActionProvisionLimitReached:
		return "ActionProvisionLimitReached"
	case IDSStatusActionProvisionReplaceAllSessionKeys:
		return "ActionProvisionReplaceAllSessionKeys"
	case IDSStatusUnauthenticated:
		return "Unauthenticated"
	case IDSStatusInvalidNameOrPassword:
		return "InvalidNameOrPassword"
	case IDSStatusAccountDisabledForSecurityReasons:
		return "AccountDisabledForSecurityReasons"
	case IDSStatusVersionMismatch:
		return "VersionMismatch"
	case IDSStatusNoSuchPlayerID:
		return "NoSuchPlayerID"
	case IDSStatusNoSuchAchievement:
		return "NoSuchAchievement"
	case IDSStatusMissingRequiredHeader:
		return "MissingRequiredHeader"
	case IDSStatusUnrecognizedGameDescriptorHeaders:
		return "UnrecognizedGameDescriptorHeaders"
	case IDSStatusMustAcceptTermsOfService:
		return "MustAcceptTermsOfService"
	case IDSStatusNoSuchFriendRelationship:
		return "NoSuchFriendRelationship"
	case IDSStatusNoSuchAlias:
		return "NoSuchAlias"
	case IDSStatusEmailNotInNetwork:
		return "EmailNotInNetwork"
	case IDSStatusRequestDisallowed:
		return "RequestDisallowed"
	case IDSStatusNoSuchRID:
		return "NoSuchRID"
	case IDSStatusNoSuchGame:
		return "NoSuchGame"
	case IDSStatusMixedResponse:
		return "MixedResponse"
	case IDSStatusProfileExists:
		return "ProfileExists"
	case IDSStatusAliasExists:
		return "AliasExists"
	case IDSStatusAccountNameNotEmailAddress:
		return "AccountNameNotEmailAddress"
	case IDSStatusAliasTooLong:
		return "AliasTooLong"
	case IDSStatusAliasTooFrequentUpdates:
		return "AliasTooFrequentUpdates"
	case IDSStatusPlayerStatusNotAllowed:
		return "PlayerStatusNotAllowed"
	case IDSStatusPlayerStatusTooLong:
		return "PlayerStatusTooLong"
	case IDSStatusNoSuchBucketID:
		return "NoSuchBucketID"
	case IDSStatusAuthenticatedNotAuthorized:
		return "AuthenticatedNotAuthorized"
	case IDSStatusNoPushTokenForID:
		return "NoPushTokenForID"
	case IDSStatusPushPayloadTooBig:
		return "PushPayloadTooBig"
	case IDSStatusNewSignatureRequired:
		return "NewSignatureRequired"
	case IDSStatusNewLinkedSignatureRequired:
		return "NewLinkedSignatureRequired"
	case IDSStatusNewRegistrationRequred:
		return "NewRegistrationRequred"
	case IDSStatusExpiredRelayToken:
		return "ExpiredRelayToken"
	case IDSStatusBadSessionToken:
		return "BadSessionToken"
	case IDSStatusExpiredSessionToken:
		return "ExpiredSessionToken"
	case IDSStatusForcePasswordChange:
		return "ForcePasswordChange"
	case IDSStatusProfileBlocklisted:
		return "ProfileBlocklisted"
	case IDSStatusSelfVersionTooOld:
		return "SelfVersionTooOld"
	case IDSStatusPeerVersionTooOld:
		return "PeerVersionTooOld"
	case IDSStatusPhoneNumberTooShort:
		return "PhoneNumberTooShort"
	case IDSStatusPhoneNumberTooLong:
		return "PhoneNumberTooLong"
	case IDSStatusPhoneNumberBadCountryCode:
		return "PhoneNumberBadCountryCode"
	case IDSStatusPhoneNumberMalformed:
		return "PhoneNumberMalformed"
	case IDSStatusBadInvitationContext:
		return "BadInvitationContext"
	case IDSStatusUnpromotablePhoneNumber:
		return "UnpromotablePhoneNumber"
	case IDSStatusRegistrationLimitReached:
		return "RegistrationLimitReached"
	case IDSStatusAbsintheInternalError:
		return "AbsintheInternalError"
	case IDSStatusAbsintheSessionCreationFailed:
		return "AbsintheSessionCreationFailed"
	case IDSStatusAbsintheValidationFailed:
		return "AbsintheValidationFailed"
	case IDSStatusAlbertInternalError:
		return "AlbertInternalError"
	case IDSStatusAlbertValidationFailed:
		return "AlbertValidationFailed"
	case IDSStatusNeedsBreakBeforeMake:
		return "NeedsBreakBeforeMake"
	case IDSStatusBadCert:
		return "BadCert"
	case IDSStatusBadNonce:
		return "BadNonce"
	case IDSStatusBadNonceTimestamp:
		return "BadNonceTimestamp"
	case IDSStatusServerRegistrationUnsupported:
		return "ServerRegistrationUnsupported"
	case IDSStatusNone:
		return "None"
	default:
		return fmt.Sprintf("IDSStatus(%d)", int(s))
	}
}
