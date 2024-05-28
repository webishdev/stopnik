package validation

import (
	"fmt"
	"net/http"
	"stopnik/internal/config"
	"stopnik/internal/oauth2"
	"testing"
)

func Test_Validation(t *testing.T) {
	type passwordParameter struct {
		name     string
		password string
		valid    bool
	}

	var passwordParameters = []passwordParameter{
		{name: "foo", password: "bar", valid: true},
		{name: "foo", password: "xxx", valid: false},
		{name: "bar", password: "xxx", valid: false},
		{name: "", password: "", valid: false},
	}

	var httpMethods = []string{http.MethodGet, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete}

	testConfig := &config.Config{
		Clients: []config.Client{
			{
				Id:        "foo",
				Secret:    "d82c4eb5261cb9c8aa9855edd67d1bd10482f41529858d925094d173fa662aa91ff39bc5b188615273484021dfb16fd8284cf684ccf0fc795be3aa2fc1e6c181",
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
	setupError := testConfig.Setup()
	if setupError != nil {
		t.Fatal(setupError)
	}

	for _, test := range passwordParameters {
		testMessage := fmt.Sprintf("Valid user password %s %t", test.name, test.valid)
		t.Run(testMessage, func(t *testing.T) {

			requestValidator := NewRequestValidator(testConfig)

			_, valid := requestValidator.ValidateUserPassword(test.name, test.password)

			if test.valid != valid {
				t.Errorf("result does not match %t != %t", test.valid, valid)
			}
		})
	}

	for _, test := range passwordParameters {
		for _, httpMethod := range httpMethods {
			testMessage := fmt.Sprintf("Valid user password from request %s %t %s", test.name, test.valid, httpMethod)
			t.Run(testMessage, func(t *testing.T) {
				httpRequest := &http.Request{
					Method: httpMethod,
					PostForm: map[string][]string{
						"stopnik_username": {test.name},
						"stopnik_password": {test.password},
					},
				}

				requestValidator := NewRequestValidator(testConfig)

				_, valid := requestValidator.ValidateFormLogin(httpRequest)

				if httpMethod == http.MethodPost && test.valid != valid {
					t.Errorf("result does not match %t != %t", test.valid, valid)
				} else if httpMethod != http.MethodPost && valid {
					t.Error("should not be valid form login")
				}
			})
		}
	}

	for _, test := range passwordParameters {
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

				requestValidator := NewRequestValidator(testConfig)

				_, valid := requestValidator.ValidateClientCredentials(httpRequest)

				if httpMethod == http.MethodPost && test.valid != valid {
					t.Errorf("result does not match %t != %t", test.valid, valid)
				} else if httpMethod != http.MethodPost && valid {
					t.Error("should not be valid form login")
				}
			})
		}
	}

}
