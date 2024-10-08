package oauth2

import (
	"fmt"
	internalHttp "github.com/webishdev/stopnik/internal/http"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func Test_ErrorNoRedirectUri(t *testing.T) {
	t.Run("No redirect uri provided", func(t *testing.T) {
		rr := httptest.NewRecorder()

		AuthorizationErrorResponseHandler(rr, nil, "foo", nil)

		if rr.Code != http.StatusInternalServerError {
			t.Errorf("handler returned wrong status code: got %v want %v", rr.Code, http.StatusInternalServerError)
		}

	})
}

func Test_AuthorizationErrorTypeFromString(t *testing.T) {
	type authorizationErrorTypeParameter struct {
		value    string
		exists   bool
		expected string
	}

	var authorizationErrorTypeParameters = []authorizationErrorTypeParameter{
		{string(AuthorizationEtInvalidRequest), true, "invalid_request"},
		{string(AuthorizationEtUnauthorizedClient), true, "unauthorized_client"},
		{string(AuthorizationEtAccessDenied), true, "access_denied"},
		{string(AuthorizationEtUnsupportedResponseType), true, "unsupported_response_type"},
		{string(AuthorizationEtInvalidScope), true, "invalid_scope"},
		{string(AuthorizationEtServerError), true, "server_error"},
		{string(AuthorizationEtTemporaryUnavailable), true, "temporarily_unavailable"},
		{string(AuthorizationEtInteractionRequired), true, "interaction_required"},
		{string(AuthorizationEtLoginRequired), true, "login_required"},
		{string(AuthorizationEtAccountSelectionRequired), true, "account_selection_required"},
		{string(AuthorizationEtConsentRequired), true, "consent_required"},
		{string(AuthorizationEtInvalidRequestUri), true, "invalid_request_uri"},
		{string(AuthorizationEtInvalidRequestObject), true, "invalid_request_object"},
		{string(AuthorizationEtRequestNotSupported), true, "request_not_supported"},
		{string(AuthorizationEtRequestUriNotSupported), true, "request_uri_not_supported"},
		{string(AuthorizationEtRegistrationNotSupported), true, "registration_not_supported"},
		{"foo", false, ""},
	}

	for _, test := range authorizationErrorTypeParameters {
		testMessage := fmt.Sprintf("Error type %s %v", test.value, test.exists)
		t.Run(testMessage, func(t *testing.T) {
			if errorType, exits := AuthorizationErrorTypeFromString(test.value); exits != test.exists && string(errorType) != test.expected {
				t.Errorf("Error type %s not found,", test.value)
			}
		})
	}
}

func Test_AuthorizationErrorResponseHandler(t *testing.T) {
	type errorResponseHandlerParameter struct {
		state                    string
		expectedErrorParameter   AuthorizationErrorType
		expectedErrorDescription string
		expectedErrorUri         string
		errorResponseParameter   *AuthorizationErrorResponseParameter
	}

	var errorResponseHandlerParameters = []errorResponseHandlerParameter{
		{"", AuthorizationEtServerError, "", "", nil},
		{"xyz", AuthorizationEtServerError, "", "", nil},
		{"abc", AuthorizationEtInvalidRequest, "", "", &AuthorizationErrorResponseParameter{Error: AuthorizationEtInvalidRequest}},
		{"abc", AuthorizationEtUnauthorizedClient, "", "", &AuthorizationErrorResponseParameter{Error: AuthorizationEtUnauthorizedClient}},
		{"abc", AuthorizationEtAccessDenied, "", "", &AuthorizationErrorResponseParameter{Error: AuthorizationEtAccessDenied}},
		{"abc", AuthorizationEtUnsupportedResponseType, "", "", &AuthorizationErrorResponseParameter{Error: AuthorizationEtUnsupportedResponseType}},
		{"abc", AuthorizationEtInvalidScope, "", "", &AuthorizationErrorResponseParameter{Error: AuthorizationEtInvalidScope}},
		{"abc", AuthorizationEtServerError, "", "", &AuthorizationErrorResponseParameter{Error: AuthorizationEtServerError}},
		{"abc", AuthorizationEtTemporaryUnavailable, "", "", &AuthorizationErrorResponseParameter{Error: AuthorizationEtTemporaryUnavailable}},
		{"abc", AuthorizationEtTemporaryUnavailable, "foobar", "", &AuthorizationErrorResponseParameter{Error: AuthorizationEtTemporaryUnavailable, Description: "foobar"}},
		{"abc", AuthorizationEtTemporaryUnavailable, "", "abcxyz", &AuthorizationErrorResponseParameter{Error: AuthorizationEtTemporaryUnavailable, Uri: "abcxyz"}},
		{"abc", AuthorizationEtTemporaryUnavailable, "foobar", "abcxyz", &AuthorizationErrorResponseParameter{Error: AuthorizationEtTemporaryUnavailable, Description: "foobar", Uri: "abcxyz"}},
	}

	for _, test := range errorResponseHandlerParameters {
		testMessage := fmt.Sprintf("Authorization Error handler type %s %v %v", test.state, test.expectedErrorParameter, test.errorResponseParameter)
		t.Run(testMessage, func(t *testing.T) {
			redirectURL, parseError := url.Parse("https://example.com/foo")
			if parseError != nil {
				t.Fatal(parseError)
			}

			rr := httptest.NewRecorder()

			AuthorizationErrorResponseHandler(rr, redirectURL, test.state, test.errorResponseParameter)

			if rr.Code != http.StatusFound {
				t.Errorf("handler returned wrong status code: got %v want %v", rr.Code, http.StatusFound)
			}

			locationHeader := rr.Header().Get(internalHttp.Location)
			location, parseError := url.Parse(locationHeader)
			if parseError != nil {
				t.Errorf("location header could not be parsed: %v", parseError)
			}

			errorQueryParameter := location.Query().Get(ParameterError)

			errorType, errorTypeExists := AuthorizationErrorTypeFromString(errorQueryParameter)

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
}

func Test_TokenErrorResponseHandler(t *testing.T) {
	t.Run("Token error handler", func(t *testing.T) {
		request := httptest.NewRequest(http.MethodGet, "https://example.com/foo", nil)
		rr := httptest.NewRecorder()
		TokenErrorResponseHandler(rr, request, &TokenErrorResponseParameter{})

		if rr.Code != http.StatusBadRequest {
			t.Errorf("handler returned wrong status code: got %v want %v", rr.Code, http.StatusBadRequest)
		}
	})
}

func Test_TokenErrorStatusResponseHandler(t *testing.T) {
	statusCodes := []int{http.StatusBadRequest, http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound, http.StatusMethodNotAllowed, http.StatusRequestTimeout}
	for _, statusCode := range statusCodes {
		testMessage := fmt.Sprintf("Token error handler with status code %d", statusCode)
		t.Run(testMessage, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, "https://example.com/foo", nil)
			rr := httptest.NewRecorder()
			TokenErrorStatusResponseHandler(rr, request, statusCode, &TokenErrorResponseParameter{})

			if rr.Code != statusCode {
				t.Errorf("handler returned wrong status code: got %v want %v", rr.Code, statusCode)
			}
		})
	}
}

func Test_TokenErrorTypeFromString(t *testing.T) {
	type tokenErrorTypeParameter struct {
		value    string
		exists   bool
		expected string
	}

	var tokenErrorTypeParameters = []tokenErrorTypeParameter{
		{string(TokenEtInvalidRequest), true, "invalid_request"},
		{string(TokenEtInvalidClient), true, "invalid_client"},
		{string(TokenEtInvalidGrant), true, "invalid_grant"},
		{string(TokenEtUnauthorizedClient), true, "unauthorized_client"},
		{string(TokenEtUnsupportedGrandType), true, "unsupported_grant_type"},
		{string(TokenEtInvalidScope), true, "invalid_scope"},
		{"foo", false, ""},
	}

	for _, test := range tokenErrorTypeParameters {
		testMessage := fmt.Sprintf("Error type %s %v", test.value, test.exists)
		t.Run(testMessage, func(t *testing.T) {
			if errorType, exits := TokenErrorTypeFromString(test.value); exits != test.exists && string(errorType) != test.expected {
				t.Errorf("Error type %s not found,", test.value)
			}
		})
	}
}
