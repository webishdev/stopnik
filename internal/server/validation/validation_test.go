package validation

import (
	"fmt"
	"github.com/google/uuid"
	"github.com/webishdev/stopnik/internal/config"
	"github.com/webishdev/stopnik/internal/oauth2"
	"net/http"
	"testing"
)

func Test_Validation(t *testing.T) {
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

	var clientPasswordParameters = []passwordParameter{
		{name: "foo", password: "bar", valid: true},
		{name: "foo", password: "xxx", valid: false},
		{name: "bar", password: "xxx", valid: false},
		{name: "moo", password: "", valid: true},
		{name: "", password: "", valid: false},
	}

	var httpMethods = []string{http.MethodGet, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete}

	testConfig := &config.Config{
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
	initializationError := config.Initialize(testConfig)
	if initializationError != nil {
		t.Fatal(initializationError)
	}

	for _, test := range userPasswordParameters {
		testMessage := fmt.Sprintf("Valid user password %s %t", test.name, test.valid)
		t.Run(testMessage, func(t *testing.T) {

			requestValidator := NewRequestValidator()

			_, valid := requestValidator.ValidateUserPassword(test.name, test.password)

			if test.valid != valid {
				t.Errorf("result does not match %t != %t", test.valid, valid)
			}
		})
	}

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

				if test.valid {
					loginToken := requestValidator.NewLoginToken(uuid.NewString())
					httpRequest.PostForm["stopnik_auth_session"] = []string{loginToken}
				}

				_, loginError := requestValidator.ValidateFormLogin(httpRequest)

				if httpMethod == http.MethodPost && test.valid && loginError != nil {
					t.Error("should be valid form login")
				} else if httpMethod != http.MethodPost && loginError == nil {
					t.Error("should not be valid form login")
				}
			})
		}
	}

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

	t.Run("Client password fallback disabled", func(t *testing.T) {
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
	})

}
