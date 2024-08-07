package oauth2

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	internalHttp "stopnik/internal/http"
	"testing"
)

func Test_Error(t *testing.T) {

	type errorResponseHandlerParameter struct {
		state                    string
		expectedErrorParameter   ErrorType
		expectedErrorDescription string
		expectedErrorUri         string
		errorResponseParameter   *ErrorResponseParameter
	}

	var errorResponseHandlerParameters = []errorResponseHandlerParameter{
		{"", EtServerError, "", "", nil},
		{"xyz", EtServerError, "", "", nil},
		{"abc", EtInvalidRequest, "", "", &ErrorResponseParameter{Error: EtInvalidRequest}},
		{"abc", EtUnauthorizedClient, "", "", &ErrorResponseParameter{Error: EtUnauthorizedClient}},
		{"abc", EtAccessDenied, "", "", &ErrorResponseParameter{Error: EtAccessDenied}},
		{"abc", EtUnsupportedResponseType, "", "", &ErrorResponseParameter{Error: EtUnsupportedResponseType}},
		{"abc", EtInvalidScope, "", "", &ErrorResponseParameter{Error: EtInvalidScope}},
		{"abc", EtServerError, "", "", &ErrorResponseParameter{Error: EtServerError}},
		{"abc", EtTemporaryUnavailable, "", "", &ErrorResponseParameter{Error: EtTemporaryUnavailable}},
		{"abc", EtTemporaryUnavailable, "foobar", "", &ErrorResponseParameter{Error: EtTemporaryUnavailable, Description: "foobar"}},
		{"abc", EtTemporaryUnavailable, "", "abcxyz", &ErrorResponseParameter{Error: EtTemporaryUnavailable, Uri: "abcxyz"}},
		{"abc", EtTemporaryUnavailable, "foobar", "abcxyz", &ErrorResponseParameter{Error: EtTemporaryUnavailable, Description: "foobar", Uri: "abcxyz"}},
	}

	for _, test := range errorResponseHandlerParameters {
		testMessage := fmt.Sprintf("Error handler type %s %v %v", test.state, test.expectedErrorParameter, test.errorResponseParameter)
		t.Run(testMessage, func(t *testing.T) {
			redirectURL, parseError := url.Parse("https://example.com/foo")
			if parseError != nil {
				t.Fatal(parseError)
			}

			rr := httptest.NewRecorder()

			ErrorResponseHandler(rr, redirectURL, test.state, test.errorResponseParameter)

			if rr.Code != http.StatusFound {
				t.Errorf("handler returned wrong status code: got %v want %v", rr.Code, http.StatusFound)
			}

			locationHeader := rr.Header().Get(internalHttp.Location)
			location, parseError := url.Parse(locationHeader)
			if parseError != nil {
				t.Errorf("location header could not be parsed: %v", parseError)
			}

			errorQueryParameter := location.Query().Get(ParameterError)

			errorType, errorTypeExists := ErrorTypeFromString(errorQueryParameter)

			if !errorTypeExists {
				t.Errorf("error type could not be parsed: %v", errorQueryParameter)
			}

			if errorType != test.expectedErrorParameter {
				t.Errorf("error type %v did not match: %v", errorType, test.expectedErrorParameter)
			}

			stateParameter := location.Query().Get(ParameterState)

			if stateParameter != test.state {
				t.Errorf("state parameter %v did not match %v", stateParameter, test.state)
			}

			errorDescription := location.Query().Get(ParameterErrorDescription)

			if errorDescription != test.expectedErrorDescription {
				t.Errorf("error description %v did not match %v", errorDescription, test.expectedErrorDescription)
			}

			errorUri := location.Query().Get(ParameterErrorUri)

			if errorUri != test.expectedErrorUri {
				t.Errorf("error uri %v did not match %v", errorUri, test.expectedErrorUri)
			}
		})
	}

	t.Run("No redirect uri provided", func(t *testing.T) {
		rr := httptest.NewRecorder()

		ErrorResponseHandler(rr, nil, "foo", nil)

		if rr.Code != http.StatusInternalServerError {
			t.Errorf("handler returned wrong status code: got %v want %v", rr.Code, http.StatusInternalServerError)
		}

	})

	type errorTypeParameter struct {
		value    string
		exists   bool
		expected string
	}

	var errorTypeParameters = []errorTypeParameter{
		{string(EtInvalidRequest), true, "invalid_request"},
		{string(EtUnauthorizedClient), true, "unauthorized_client"},
		{string(EtAccessDenied), true, "access_denied"},
		{string(EtUnsupportedResponseType), true, "unsupported_response_type"},
		{string(EtInvalidScope), true, "invalid_scope"},
		{string(EtServerError), true, "server_error"},
		{string(EtTemporaryUnavailable), true, "temporarily_unavailable"},
		{"foo", false, ""},
	}

	for _, test := range errorTypeParameters {
		testMessage := fmt.Sprintf("Error type %s %v", test.value, test.exists)
		t.Run(testMessage, func(t *testing.T) {
			if errorType, exits := ErrorTypeFromString(test.value); exits != test.exists && string(errorType) != test.expected {
				t.Errorf("Error type %s not found,", test.value)
			}
		})
	}
}
