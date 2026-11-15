package validation

import (
	"fmt"
	"github.com/webishdev/stopnik/internal/config"
	"github.com/webishdev/stopnik/internal/limiter"
	"github.com/webishdev/stopnik/internal/oauth2"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
	"uuid"
)

func Test_ValidateClientCredentials(t *testing.T) {
	createValidationTestConfig(t)

	type passwordParameter struct {
		name     string
		password string
		valid    bool
	}

	var clientPasswordParameters = []passwordParameter{
		{name: "foo", password: "bar", valid: true},
		{name: "foo", password: "xxx", valid: false},
		{name: "bar", password: "xxx", valid: false},
		{name: "moo", password: "", valid: true},
		{name: "xxx", password: "", valid: false},
		{name: "moo", password: "bar", valid: false},
		{name: "", password: "", valid: false},
	}

	var httpMethods = []string{http.MethodGet, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete}

	for _, test := range clientPasswordParameters {
		for _, httpMethod := range httpMethods {
			testMessage := fmt.Sprintf("Valid client credentials from request %s %t %s", test.name, test.valid, httpMethod)
			t.Run(testMessage, func(t *testing.T) {
				httpRequest := &http.Request{
					Method: httpMethod,
					PostForm: map[string][]string{
						oauth2.ParameterClientId:     {test.name},
						oauth2.ParameterClientSecret: {test.password},
					},
				}

				requestValidator := NewRequestValidator()

				_, _, valid := requestValidator.ValidateClientCredentials(httpRequest)

				if httpMethod == http.MethodPost && test.valid != valid {
					t.Errorf("result does not match %t != %t", test.valid, valid)
				} else if httpMethod != http.MethodPost && valid {
					t.Error("should not be valid form login")
				}
			})
		}
	}
}

func Test_ValidateFormLogin(t *testing.T) {
	createValidationTestConfig(t)

	type passwordParameter struct {
		name     string
		password string
		valid    bool
	}

	var userPasswordParameters = []passwordParameter{
		{name: "foo", password: "bar", valid: true},
		{name: "foo", password: "xxx", valid: false},
		{name: "bar", password: "xxx", valid: false},
		{name: "", password: "", valid: false},
	}

	var httpMethods = []string{http.MethodGet, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete}

	for _, test := range userPasswordParameters {
		for _, httpMethod := range httpMethods {
			testMessage := fmt.Sprintf("Valid user password from request %s %t %s", test.name, test.valid, httpMethod)
			t.Run(testMessage, func(t *testing.T) {
				requestValidator := NewRequestValidator()

				httpRequest := &http.Request{
					Method: httpMethod,
					PostForm: map[string][]string{
						"stopnik_username": {test.name},
						"stopnik_password": {test.password},
					},
				}

				loginToken := requestValidator.NewLoginToken(uuid.New().String())
				httpRequest.PostForm["stopnik_auth_session"] = []string{loginToken}

				_, loginError := requestValidator.ValidateFormLogin(httpRequest)

				if httpMethod == http.MethodPost && test.valid && loginError != nil {
					t.Error("should be valid form login")
				} else if httpMethod != http.MethodPost && loginError == nil {
					t.Error("should not be valid form login")
				}
			})
		}
	}
}

func Test_ValidateFormLoginNoLoginToken(t *testing.T) {
	createValidationTestConfig(t)

	type passwordParameter struct {
		name     string
		password string
	}

	var userPasswordParameters = []passwordParameter{
		{name: "foo", password: "bar"},
		{name: "foo", password: "xxx"},
		{name: "bar", password: "xxx"},
		{name: "", password: ""},
	}

	var httpMethods = []string{http.MethodGet, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete}

	for _, test := range userPasswordParameters {
		for _, httpMethod := range httpMethods {
			testMessage := fmt.Sprintf("Valid user password from request %s %s", test.name, httpMethod)
			t.Run(testMessage, func(t *testing.T) {
				requestValidator := NewRequestValidator()

				httpRequest := &http.Request{
					Method: httpMethod,
					PostForm: map[string][]string{
						"stopnik_username": {test.name},
						"stopnik_password": {test.password},
					},
				}

				_, loginError := requestValidator.ValidateFormLogin(httpRequest)

				if loginError == nil {
					t.Error("login should fail")
				}
			})
		}
	}
}

func Test_ValidateFormLoginExpiredLoginToken(t *testing.T) {
	createValidationTestConfig(t)

	type passwordParameter struct {
		name     string
		password string
	}

	var userPasswordParameters = []passwordParameter{
		{name: "foo", password: "bar"},
		{name: "foo", password: "xxx"},
		{name: "bar", password: "xxx"},
		{name: "", password: ""},
	}

	var httpMethods = []string{http.MethodGet, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete}

	var mockedTime = time.Date(1979, 1, 17, 15, 0, 0, 0, time.Local)

	for _, test := range userPasswordParameters {
		for _, httpMethod := range httpMethods {
			testMessage := fmt.Sprintf("Valid user password from request %s %s", test.name, httpMethod)
			t.Run(testMessage, func(t *testing.T) {
				requestValidator := newRequestValidator(func() time.Time { return mockedTime })

				httpRequest := &http.Request{
					Method: httpMethod,
					PostForm: map[string][]string{
						"stopnik_username": {test.name},
						"stopnik_password": {test.password},
					},
				}

				loginToken := requestValidator.NewLoginToken(uuid.New().String())
				httpRequest.PostForm["stopnik_auth_session"] = []string{loginToken}

				_, loginError := requestValidator.ValidateFormLogin(httpRequest)

				if loginError == nil {
					t.Error("login should fail")
				}
			})
		}
	}
}

func Test_ValidateUserPassword(t *testing.T) {
	createValidationTestConfig(t)

	type passwordParameter struct {
		name     string
		password string
		valid    bool
	}

	var userPasswordParameters = []passwordParameter{
		{name: "foo", password: "bar", valid: true},
		{name: "foo", password: "xxx", valid: false},
		{name: "bar", password: "xxx", valid: false},
		{name: "", password: "", valid: false},
	}

	for _, test := range userPasswordParameters {
		testMessage := fmt.Sprintf("Valid user password %s %t", test.name, test.valid)
		t.Run(testMessage, func(t *testing.T) {

			requestValidator := NewRequestValidator()

			_, valid := requestValidator.ValidateUserPassword(httptest.NewRequest(http.MethodPost, "/token", nil), test.name, test.password)

			if test.valid != valid {
				t.Errorf("result does not match %t != %t", test.valid, valid)
			}
		})
	}
}

func Test_ValidateUserPasswordAlwaysHashes(t *testing.T) {
	createValidationTestConfig(t)

	originalVerifySecret := verifySecret
	defer func() {
		verifySecret = originalVerifySecret
	}()

	hashCalls := 0
	verifySecret = func(secret string, salt string, expectedHash string) bool {
		hashCalls++
		return originalVerifySecret(secret, salt, expectedHash)
	}

	// Existing and unknown users must cost the same, so timing does not reveal which users exist
	var usernames = []string{"foo", "unknown"}

	for _, username := range usernames {
		testMessage := fmt.Sprintf("Hash calculated for user %s", username)
		t.Run(testMessage, func(t *testing.T) {
			hashCalls = 0
			requestValidator := NewRequestValidator()

			requestValidator.ValidateUserPassword(httptest.NewRequest(http.MethodPost, "/token", nil), username, "xxx")

			if hashCalls != 1 {
				t.Errorf("hash was calculated %d times, expected 1", hashCalls)
			}
		})
	}
}

func Test_ValidateClientCredentialsDisabledFallback(t *testing.T) {
	httpRequest := &http.Request{
		Method: http.MethodPost,
		PostForm: map[string][]string{
			oauth2.ParameterClientId:     {"bar"},
			oauth2.ParameterClientSecret: {"bar"},
		},
	}

	requestValidator := NewRequestValidator()

	_, _, valid := requestValidator.ValidateClientCredentials(httpRequest)

	if valid {
		t.Errorf("Client password fallback disabled, should not be able to login")
	}
}

func createValidationTestConfig(t *testing.T) {
	testConfigEntries := config.Entries{
		Clients: []config.Client{
			{
				Id:                      "foo",
				ClientSecret:            "d82c4eb5261cb9c8aa9855edd67d1bd10482f41529858d925094d173fa662aa91ff39bc5b188615273484021dfb16fd8284cf684ccf0fc795be3aa2fc1e6c181",
				Redirects:               []string{"https://example.com/callback"},
				PasswordFallbackAllowed: true,
			},
			{
				Id:           "bar",
				ClientSecret: "d82c4eb5261cb9c8aa9855edd67d1bd10482f41529858d925094d173fa662aa91ff39bc5b188615273484021dfb16fd8284cf684ccf0fc795be3aa2fc1e6c181",
				Redirects:    []string{"https://example.com/callback"},
			},
			{
				Id:        "moo",
				Redirects: []string{"https://example.com/callback"},
			},
		},
		Users: []config.User{
			{
				Username: "foo",
				Password: "d82c4eb5261cb9c8aa9855edd67d1bd10482f41529858d925094d173fa662aa91ff39bc5b188615273484021dfb16fd8284cf684ccf0fc795be3aa2fc1e6c181",
			},
		},
	}
	testConfig := &config.Config{}
	initializationError := config.Initialize(testConfig)
	if initializationError != nil {
		t.Fatal(initializationError)
	}
	if applyError := testConfig.ApplyEntries(testConfigEntries); applyError != nil {
		t.Fatal(applyError)
	}
}

// useTestCredentialGuard replaces the credential guard with a new one for the duration of the test.
func useTestCredentialGuard(t *testing.T) {
	t.Helper()
	originalGuard := credentialGuard
	credentialGuard = limiter.NewCredentialGuard()
	t.Cleanup(func() {
		credentialGuard = originalGuard
	})
}

func testRequestFrom(address string) *http.Request {
	request := httptest.NewRequest(http.MethodPost, "/token", nil)
	request.RemoteAddr = address + ":51234"
	return request
}

func Test_ValidateUserPasswordBlockedAfterFailedAttempts(t *testing.T) {
	createValidationTestConfig(t)
	useTestCredentialGuard(t)

	requestValidator := NewRequestValidator()

	for range 10 {
		requestValidator.ValidateUserPassword(testRequestFrom("192.0.2.1"), "foo", "xxx")
	}

	_, valid := requestValidator.ValidateUserPassword(testRequestFrom("192.0.2.1"), "foo", "bar")
	if valid {
		t.Errorf("user should be delayed after too many failed attempts from the same address")
	}

	// Unknown users are blocked the same way, so blocking does not reveal existing users
	for range 10 {
		requestValidator.ValidateUserPassword(testRequestFrom("192.0.2.1"), "unknown", "xxx")
	}
	if !credentialGuard.Blocked("user:unknown", "192.0.2.1") {
		t.Errorf("unknown user should be delayed after too many failed attempts")
	}
}

func Test_ValidateUserPasswordOtherAddressNotBlocked(t *testing.T) {
	createValidationTestConfig(t)
	useTestCredentialGuard(t)

	requestValidator := NewRequestValidator()

	for range 10 {
		requestValidator.ValidateUserPassword(testRequestFrom("192.0.2.1"), "foo", "xxx")
	}

	// An attacker can not lock out a user, which signs in from another address
	_, valid := requestValidator.ValidateUserPassword(testRequestFrom("198.51.100.7"), "foo", "bar")
	if !valid {
		t.Errorf("failed attempts from one address must not block a correct login from another address")
	}
}

func Test_ValidateUserPasswordAddressBlocked(t *testing.T) {
	createValidationTestConfig(t)
	useTestCredentialGuard(t)

	requestValidator := NewRequestValidator()

	// One password against many usernames
	for index := range 50 {
		requestValidator.ValidateUserPassword(testRequestFrom("192.0.2.1"), fmt.Sprintf("user%d", index), "xxx")
	}

	_, valid := requestValidator.ValidateUserPassword(testRequestFrom("192.0.2.1"), "foo", "bar")
	if valid {
		t.Errorf("address should be blocked after too many failed attempts for different usernames")
	}

	_, valid = requestValidator.ValidateUserPassword(testRequestFrom("198.51.100.7"), "foo", "bar")
	if !valid {
		t.Errorf("other addresses should not be blocked")
	}
}

func Test_ValidateClientCredentialsAddressBlocked(t *testing.T) {
	createValidationTestConfig(t)
	useTestCredentialGuard(t)

	requestValidator := NewRequestValidator()

	createRequest := func(address string, clientId string, clientSecret string) *http.Request {
		request := testRequestFrom(address)
		request.SetBasicAuth(clientId, clientSecret)
		return request
	}

	for index := range 50 {
		requestValidator.ValidateClientCredentials(createRequest("192.0.2.1", fmt.Sprintf("client%d", index), "xxx"))
	}

	_, _, valid := requestValidator.ValidateClientCredentials(createRequest("192.0.2.1", "foo", "bar"))
	if valid {
		t.Errorf("address should be blocked after too many failed attempts for different clients")
	}

	_, _, valid = requestValidator.ValidateClientCredentials(createRequest("198.51.100.7", "foo", "bar"))
	if !valid {
		t.Errorf("other addresses should not be blocked")
	}
}

func Test_ValidateUserPasswordResetAfterSuccess(t *testing.T) {
	createValidationTestConfig(t)
	useTestCredentialGuard(t)

	requestValidator := NewRequestValidator()

	for range 2 {
		requestValidator.ValidateUserPassword(testRequestFrom("192.0.2.1"), "foo", "xxx")
		requestValidator.ValidateUserPassword(testRequestFrom("192.0.2.1"), "foo", "xxx")
		requestValidator.ValidateUserPassword(testRequestFrom("192.0.2.1"), "foo", "bar")
	}

	_, valid := requestValidator.ValidateUserPassword(testRequestFrom("192.0.2.1"), "foo", "bar")
	if !valid {
		t.Errorf("failed attempts should be reset after successful login")
	}
}

func Test_ValidateSameOrigin(t *testing.T) {
	type originParameter struct {
		name          string
		secFetchSite  string
		origin        string
		expectedValid bool
	}

	var originParameters = []originParameter{
		{"No browser headers", "", "", true},
		{"Same origin", "same-origin", "", true},
		{"Cross site", "cross-site", "", false},
		{"Cross origin via Origin header", "", "https://evil.com", false},
		{"Same host via Origin header", "", "http://example.com", true},
	}

	for _, test := range originParameters {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, "http://example.com/account", nil)
			if test.secFetchSite != "" {
				request.Header.Set("Sec-Fetch-Site", test.secFetchSite)
			}
			if test.origin != "" {
				request.Header.Set("Origin", test.origin)
			}

			if valid := ValidateSameOrigin(request); valid != test.expectedValid {
				t.Errorf("result %t did not match %t", valid, test.expectedValid)
			}
		})
	}
}
