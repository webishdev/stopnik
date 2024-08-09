package oauth2

import (
	"net/http"
	"net/url"
	internalHttp "stopnik/internal/http"
	"stopnik/log"
	"strings"
)

// AuthorizationErrorResponseParameter related to https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2.1
type AuthorizationErrorResponseParameter struct {
	Error       AuthorizationErrorType
	Description string
	Uri         string
}

// AuthorizationErrorType as described in multiple places e.g. https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2.1
type AuthorizationErrorType string

const (
	EtInvalidRequest          AuthorizationErrorType = "invalid_request"
	EtUnauthorizedClient      AuthorizationErrorType = "unauthorized_client"
	EtAccessDenied            AuthorizationErrorType = "access_denied"
	EtUnsupportedResponseType AuthorizationErrorType = "unsupported_response_type"
	EtInvalidScope            AuthorizationErrorType = "invalid_scope"
	EtServerError             AuthorizationErrorType = "server_error"
	EtTemporaryUnavailable    AuthorizationErrorType = "temporarily_unavailable"
)

var errorTypeMap = map[string]AuthorizationErrorType{
	"invalid_request":           EtInvalidRequest,
	"unauthorized_client":       EtUnauthorizedClient,
	"access_denied":             EtAccessDenied,
	"unsupported_response_type": EtUnsupportedResponseType,
	"invalid_scope":             EtInvalidScope,
	"server_error":              EtServerError,
	"temporarily_unavailable":   EtTemporaryUnavailable,
}

func ErrorTypeFromString(value string) (AuthorizationErrorType, bool) {
	result, ok := errorTypeMap[strings.ToLower(value)]
	return result, ok
}

func AuthorizationErrorResponseHandler(w http.ResponseWriter, redirectURL *url.URL, state string, errorResponseParameter *AuthorizationErrorResponseParameter) {
	if redirectURL == nil {
		sendStatus(w, http.StatusInternalServerError, "No redirect URL")
		return
	}
	query := redirectURL.Query()
	if errorResponseParameter == nil {
		query.Set(ParameterError, string(EtServerError))
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
