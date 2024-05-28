package http

import (
	"fmt"
	"net/http"
	"stopnik/internal/config"
	"testing"
	"time"
)

func Test_Cookie(t *testing.T) {
	var mockedTime = time.Date(1979, 1, 17, 15, 0, 0, 0, time.Local)

	now := func() time.Time {
		return mockedTime
	}

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

		testCookieValues(t, cookie, 3600)

		httpRequest := &http.Request{
			Header: http.Header{
				"Cookie": []string{cookie.String()},
			},
		}

		_, userExists := cookieManager.ValidateCookie(httpRequest)

		if !userExists {
			t.Error("Token in cookie is invalid")
		}
	})

	t.Run("Create and validate expired Cookie", func(t *testing.T) {
		cookieManager := newCookieManagerWithTime(testConfig, now)

		cookie, cookieError := cookieManager.CreateCookie("foo")

		if cookieError != nil {
			t.Error(cookieError)
		}

		httpRequest := &http.Request{
			Header: http.Header{
				"Cookie": []string{cookie.String()},
			},
		}

		mockedTime.Add(time.Hour * time.Duration(-6))

		_, userExists := cookieManager.ValidateCookie(httpRequest)

		if userExists {
			t.Error("Expired token should not provide a user")
		}
	})

	t.Run("Create and validate Cookie with wrong username", func(t *testing.T) {
		cookieManager := NewCookieManager(testConfig)

		cookie, cookieError := cookieManager.CreateCookie("bar")

		if cookieError != nil {
			t.Error(cookieError)
		}

		httpRequest := &http.Request{
			Header: http.Header{
				"Cookie": []string{cookie.String()},
			},
		}

		_, userExists := cookieManager.ValidateCookie(httpRequest)

		if userExists {
			t.Error("User should not exists")
		}
	})

	t.Run("Create and validate Cookie with invalid content", func(t *testing.T) {
		cookieManager := NewCookieManager(testConfig)

		cookie := fmt.Sprintf("%s=%s", testConfig.GetAuthCookieName(), "moo")

		httpRequest := &http.Request{
			Header: http.Header{
				"Cookie": []string{cookie},
			},
		}

		_, userExists := cookieManager.ValidateCookie(httpRequest)

		if userExists {
			t.Error("User should not exists")
		}
	})

	t.Run("Delete Cookie", func(t *testing.T) {
		cookieManager := NewCookieManager(testConfig)

		deleteCookie := cookieManager.DeleteCookie()

		testCookieValues(t, deleteCookie, -1)
	})

}

func testCookieValues(t *testing.T, cookie http.Cookie, maxAge int) {
	if cookie.Name != "stopnik_auth" {
		t.Error("Cookie name is wrong")
	}

	if !cookie.HttpOnly {
		t.Error("Cookie httpOnly should be true")
	}

	if cookie.Path != "/" {
		t.Error("Cookie path is wrong")
	}

	if cookie.MaxAge != maxAge {
		t.Errorf("Cookie maxAge should be %d", maxAge)
	}
}
