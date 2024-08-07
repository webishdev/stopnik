package oauth2

import (
	"net/http"
	"net/url"
	internalHttp "stopnik/internal/http"
	"stopnik/log"
	"strings"
)

// ErrorResponseParameter related to https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2.1
type ErrorResponseParameter struct {
	Error       ErrorType
	Description string
	Uri         string
}

// ErrorType as described in multiple places e.g. https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2.1
type ErrorType string

const (
	EtInvalidRequest          ErrorType = "invalid_request"
	EtUnauthorizedClient      ErrorType = "unauthorized_client"
	EtAccessDenied            ErrorType = "access_denied"
	EtUnsupportedResponseType ErrorType = "unsupported_response_type"
	EtInvalidScope            ErrorType = "invalid_scope"
	EtServerError             ErrorType = "server_error"
	EtTemporaryUnavailable    ErrorType = "temporarily_unavailable"
)

var errorTypeMap = map[string]ErrorType{
	"invalid_request":           EtInvalidRequest,
	"unauthorized_client":       EtUnauthorizedClient,
	"access_denied":             EtAccessDenied,
	"unsupported_response_type": EtUnsupportedResponseType,
	"invalid_scope":             EtInvalidScope,
	"server_error":              EtServerError,
	"temporarily_unavailable":   EtTemporaryUnavailable,
}

func ErrorTypeFromString(value string) (ErrorType, bool) {
	result, ok := errorTypeMap[strings.ToLower(value)]
	return result, ok
}

func ErrorResponseHandler(w http.ResponseWriter, redirectURL *url.URL, state string, errorResponseParameter *ErrorResponseParameter) {
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
