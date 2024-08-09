package oauth2

import (
	"net/http"
	"net/url"
	internalHttp "stopnik/internal/http"
	"stopnik/log"
	"strings"
)

// AuthorizationErrorType as described in multiple places e.g. https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2.1
type AuthorizationErrorType string

// AuthorizationErrorResponseParameter related to https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2.1
type AuthorizationErrorResponseParameter struct {
	Error       AuthorizationErrorType
	Description string
	Uri         string
}

const (
	AuthorizationEtInvalidRequest          AuthorizationErrorType = "invalid_request"
	AuthorizationEtUnauthorizedClient      AuthorizationErrorType = "unauthorized_client"
	AuthorizationEtAccessDenied            AuthorizationErrorType = "access_denied"
	AuthorizationEtUnsupportedResponseType AuthorizationErrorType = "unsupported_response_type"
	AuthorizationEtInvalidScope            AuthorizationErrorType = "invalid_scope"
	AuthorizationEtServerError             AuthorizationErrorType = "server_error"
	AuthorizationEtTemporaryUnavailable    AuthorizationErrorType = "temporarily_unavailable"
)

var authorizationErrorTypeMap = map[string]AuthorizationErrorType{
	"invalid_request":           AuthorizationEtInvalidRequest,
	"unauthorized_client":       AuthorizationEtUnauthorizedClient,
	"access_denied":             AuthorizationEtAccessDenied,
	"unsupported_response_type": AuthorizationEtUnsupportedResponseType,
	"invalid_scope":             AuthorizationEtInvalidScope,
	"server_error":              AuthorizationEtServerError,
	"temporarily_unavailable":   AuthorizationEtTemporaryUnavailable,
}

// TokenErrorType as described in multiple places e.g. https://datatracker.ietf.org/doc/html/rfc6749#section-5.2
type TokenErrorType string

// TokenErrorResponseParameter related to https://datatracker.ietf.org/doc/html/rfc6749#section-5.2
type TokenErrorResponseParameter struct {
	Error       TokenErrorType
	Description string
	Uri         string
}

const (
	TokenEtInvalidRequest       TokenErrorType = "invalid_request"
	TokenEtInvalidClient        TokenErrorType = "invalid_client"
	TokenEtInvalidGrant         TokenErrorType = "invalid_grant"
	TokenEtUnauthorizedClient   TokenErrorType = "unauthorized_client"
	TokenEtUnsupportedGrandType TokenErrorType = "unsupported_grant_type"
	TokenEtInvalidScope         TokenErrorType = "invalid_scope"
)

var tokenErrorTypeMap = map[string]TokenErrorType{
	"invalid_request":        TokenEtInvalidRequest,
	"invalid_client":         TokenEtInvalidClient,
	"invalid_grant":          TokenEtInvalidGrant,
	"unauthorized_client":    TokenEtUnauthorizedClient,
	"unsupported_grant_type": TokenEtUnsupportedGrandType,
	"invalid_scope":          TokenEtInvalidScope,
}

func AuthorizationErrorTypeFromString(value string) (AuthorizationErrorType, bool) {
	result, ok := authorizationErrorTypeMap[strings.ToLower(value)]
	return result, ok
}

func TokenErrorTypeFromString(value string) (TokenErrorType, bool) {
	result, ok := tokenErrorTypeMap[strings.ToLower(value)]
	return result, ok
}

func AuthorizationErrorResponseHandler(w http.ResponseWriter, redirectURL *url.URL, state string, errorResponseParameter *AuthorizationErrorResponseParameter) {
	if redirectURL == nil {
		sendStatus(w, http.StatusInternalServerError, "No redirect URL")
		return
	}
	query := redirectURL.Query()
	if errorResponseParameter == nil {
		query.Set(ParameterError, string(AuthorizationEtServerError))
	} else {
		query.Set(ParameterError, string(errorResponseParameter.Error))
		if errorResponseParameter.Description != "" {
			query.Set(ParameterErrorDescription, errorResponseParameter.Description)
		}
		if errorResponseParameter.Uri != "" {
			query.Set(ParameterErrorUri, errorResponseParameter.Uri)
		}
	}
	if state != "" {
		query.Set(ParameterState, state)
	}
	redirectURL.RawQuery = query.Encode()
	w.Header().Set(internalHttp.Location, redirectURL.String())
	w.WriteHeader(http.StatusFound)
}

func sendStatus(w http.ResponseWriter, status int, message string) {
	w.WriteHeader(status)
	_, err := w.Write([]byte(message))
	if err != nil {
		log.Error("Could not send status message: %v", err)
	}
}
