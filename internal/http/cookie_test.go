package http

import (
	"stopnik/internal/config"
	"testing"
)

func Test_Cookie(t *testing.T) {
	testConfig := &config.Config{
		Users: []config.User{
			{Username: "foo", Password: "d82c4eb5261cb9c8aa9855edd67d1bd10482f41529858d925094d173fa662aa91ff39bc5b188615273484021dfb16fd8284cf684ccf0fc795be3aa2fc1e6c181"},
		},
	}
	setupError := testConfig.Setup()
	if setupError != nil {
		t.Fatal(setupError)
	}

	t.Run("Create and validate Cookie", func(t *testing.T) {
		cookieManager := NewCookieManager(testConfig)

		cookie, cookieError := cookieManager.CreateCookie("foo")

		if cookieError != nil {
			t.Error(cookieError)
		}

		if cookie.Name != "stopnik_auth" {
			t.Error("Cookie name is wrong")
		}

		if !cookie.HttpOnly {
			t.Error("Cookie httpOnly should be true")
		}

		if cookie.Path != "/" {
			t.Error("Cookie path is wrong")
		}

		if cookie.MaxAge != 3600 {
			t.Error("Cookie maxAge is wrong")
		}

		_, userExists := cookieManager.validateCookieValue(&cookie)

		if !userExists {
			t.Error("Token in cookie is invalid")
		}
	})
}
