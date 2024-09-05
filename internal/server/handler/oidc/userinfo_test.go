package oidc

import (
	"encoding/json"
	"fmt"
	"github.com/webishdev/stopnik/internal/config"
	"github.com/webishdev/stopnik/internal/endpoint"
	internalHttp "github.com/webishdev/stopnik/internal/http"
	"github.com/webishdev/stopnik/internal/manager/token"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func Test_UserInfo(t *testing.T) {

	testConfig := &config.Config{
		Clients: []config.Client{
			{
				Id:           "foo",
				ClientSecret: "d82c4eb5261cb9c8aa9855edd67d1bd10482f41529858d925094d173fa662aa91ff39bc5b188615273484021dfb16fd8284cf684ccf0fc795be3aa2fc1e6c181",
				Redirects:    []string{"https://example.com/callback"},
			},
		},
		Users: []config.User{
			{
				Username: "foo",
				Password: "d82c4eb5261cb9c8aa9855edd67d1bd10482f41529858d925094d173fa662aa91ff39bc5b188615273484021dfb16fd8284cf684ccf0fc795be3aa2fc1e6c181",
				Profile: config.UserProfile{
					PreferredUserName: "foobar",
					GivenName:         "John",
					FamilyName:        "Doe",
					Nickname:          "fooby",
					Email:             "foo@bar.com",
					EmailVerified:     true,
					Gender:            "bot",
					Address: config.UserAddress{
						Street:     "Mainstreet 1",
						PostalCode: "12345",
						City:       "Maintown",
						Region:     "Maino",
						Country:    "Main",
					},
				},
			},
		},
	}

	initializationError := config.Initialize(testConfig)
	if initializationError != nil {
		t.Fatal(initializationError)
	}

	testOidcUserInfo(t, testConfig)

	testOidcUserInfoNotAllowedHttpMethods(t)
}

func testOidcUserInfo(t *testing.T, testConfig *config.Config) {
	t.Run("OIDC UserInfo", func(t *testing.T) {
		tokenManager := token.GetTokenManagerInstance()

		client, clientExists := testConfig.GetClient("foo")
		if !clientExists {
			t.Error("client should exist")
		}

		request := httptest.NewRequest(http.MethodPost, endpoint.Token, nil)
		tokenResponse := tokenManager.CreateAccessTokenResponse(request, "foo", client, []string{"a:foo", "b:bar"}, "")

		oidcDiscoveryHandler := NewOidcUserInfoHandler(tokenManager)

		httpRequest := &http.Request{
			Method: http.MethodGet,
			Header: http.Header{
				internalHttp.Authorization: []string{"Bearer " + tokenResponse.AccessTokenValue},
			},
		}
		rr := httptest.NewRecorder()

		oidcDiscoveryHandler.ServeHTTP(rr, httpRequest)

		if rr.Code != http.StatusOK {
			t.Errorf("handler returned wrong status code: got %v want %v", rr.Code, http.StatusOK)
		}

		requestResponse := rr.Result()

		userProfile := testOidcUserInfoParse(t, requestResponse)

		if userProfile.Subject != "foo" {
			t.Errorf("userinfo subject did not match")
		}

		if userProfile.GivenName != "John" {
			t.Errorf("userinfo given name did not match")
		}

		if userProfile.FamilyName != "Doe" {
			t.Errorf("userinfo given name did not match")
		}

		if userProfile.Name != "John Doe" {
			t.Errorf("userinfo name did not match")
		}

		if userProfile.PreferredUserName != "foobar" {
			t.Errorf("userinfo name did not match")
		}

		if userProfile.Gender != "bot" {
			t.Errorf("userinfo gender did not match")
		}

		if userProfile.Nickname != "fooby" {
			t.Errorf("userinfo nickname did not match")
		}

		if userProfile.Email != "foo@bar.com" {
			t.Errorf("userinfo email did not match")
		}

		if !userProfile.EmailVerified {
			t.Errorf("userinfo email was not verified")
		}

		if userProfile.Address.Street != "Mainstreet 1" {
			t.Errorf("userinfo street did not match")
		}

		if userProfile.Address.PostalCode != "12345" {
			t.Errorf("userinfo street did not match")
		}

		if userProfile.Address.Region != "Maino" {
			t.Errorf("userinfo region did not match")
		}

		if userProfile.Address.City != "Maintown" {
			t.Errorf("userinfo city did not match")
		}

		if userProfile.Address.Formatted != "Mainstreet 1\n12345\nMaintown\n" {
			t.Errorf("userinfo formatted did not match")
		}
	})
}

func testOidcUserInfoNotAllowedHttpMethods(t *testing.T) {
	var testInvalidOidcUserInfoHttpMethods = []string{
		http.MethodPost,
		http.MethodPut,
		http.MethodPatch,
		http.MethodDelete,
	}

	for _, method := range testInvalidOidcUserInfoHttpMethods {
		testMessage := fmt.Sprintf("OIDC configuration with unsupported method %s", method)
		t.Run(testMessage, func(t *testing.T) {
			tokenManager := token.GetTokenManagerInstance()
			oidcDiscoveryHandler := NewOidcUserInfoHandler(tokenManager)

			rr := httptest.NewRecorder()

			oidcDiscoveryHandler.ServeHTTP(rr, httptest.NewRequest(method, endpoint.Metadata, nil))

			if rr.Code != http.StatusMethodNotAllowed {
				t.Errorf("handler returned wrong status code: got %v want %v", rr.Code, http.StatusMethodNotAllowed)
			}

		})
	}
}

func testOidcUserInfoParse(t *testing.T, r *http.Response) config.UserProfile {
	responseBody, bodyReadErr := io.ReadAll(r.Body)

	if bodyReadErr != nil {
		t.Errorf("could not read oidcConfigurationResponse body: %v", bodyReadErr)
	}

	if responseBody == nil {
		t.Errorf("oidcConfigurationResponse body was nil")
	}

	userProfileResponse := config.UserProfile{}
	jsonParseError := json.Unmarshal(responseBody, &userProfileResponse)
	if jsonParseError != nil {
		t.Errorf("could not parse oidcConfigurationResponse body: %v", jsonParseError)
	}

	return userProfileResponse
}
