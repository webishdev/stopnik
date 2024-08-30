package cookie

import (
	"fmt"
	"github.com/webishdev/stopnik/internal/config"
	"github.com/webishdev/stopnik/internal/endpoint"
	"net/http"
	"net/http/httptest"
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
	initializationError := config.Initialize(testConfig)
	if initializationError != nil {
		t.Fatal(initializationError)
	}

	t.Run("Create and validate auth cookie", func(t *testing.T) {
		cookieManager := GetCookieManagerInstance()

		cookie, cookieError := cookieManager.CreateAuthCookie("foo")

		if cookieError != nil {
			t.Error(cookieError)
		}

		testAuthCookieValues(t, cookie, 3600)

		httpRequest := &http.Request{
			Header: http.Header{
				"Cookie": []string{cookie.String()},
			},
		}

		_, userExists := cookieManager.ValidateAuthCookie(httpRequest)

		if !userExists {
			t.Error("Token in auth cookie is invalid")
		}
	})

	t.Run("Create and validate expired auth cookie", func(t *testing.T) {
		cookieManager := newCookieManagerWithTime(now)

		cookie, cookieError := cookieManager.CreateAuthCookie("foo")

		if cookieError != nil {
			t.Error(cookieError)
		}

		httpRequest := &http.Request{
			Header: http.Header{
				"Cookie": []string{cookie.String()},
			},
		}

		mockedTime = mockedTime.Add(time.Hour * time.Duration(-6))

		_, userExists := cookieManager.ValidateAuthCookie(httpRequest)

		if userExists {
			t.Error("Expired token should not provide a user")
		}
	})

	t.Run("Create and validate auth cookie with wrong username", func(t *testing.T) {
		cookieManager := GetCookieManagerInstance()

		cookie, cookieError := cookieManager.CreateAuthCookie("bar")

		if cookieError != nil {
			t.Error(cookieError)
		}

		httpRequest := &http.Request{
			Header: http.Header{
				"Cookie": []string{cookie.String()},
			},
		}

		_, userExists := cookieManager.ValidateAuthCookie(httpRequest)

		if userExists {
			t.Error("User should not exists")
		}
	})

	t.Run("Create and validate auth cookie with invalid content", func(t *testing.T) {
		cookieManager := GetCookieManagerInstance()

		cookie := fmt.Sprintf("%s=%s", testConfig.GetAuthCookieName(), "moo")

		httpRequest := &http.Request{
			Header: http.Header{
				"Cookie": []string{cookie},
			},
		}

		_, userExists := cookieManager.ValidateAuthCookie(httpRequest)

		if userExists {
			t.Error("User should not exists")
		}
	})

	t.Run("Delete auth cookie", func(t *testing.T) {
		cookieManager := GetCookieManagerInstance()

		deleteCookie := cookieManager.DeleteAuthCookie()

		testAuthCookieValues(t, deleteCookie, -1)
	})

	t.Run("Create and read message cookie", func(t *testing.T) {
		cookieManager := GetCookieManagerInstance()

		cookie := cookieManager.CreateMessageCookie("foo into bar")

		if cookie.Value != "foo into bar" {
			t.Errorf("Message cookie value did not match, expected foo into bar, got %v", cookie.Value)
		}

		httpRequest := httptest.NewRequest(http.MethodGet, endpoint.Account, nil)
		httpRequest.AddCookie(&cookie)

		cookieValue := cookieManager.GetMessageCookieValue(httpRequest)

		if cookieValue != "foo into bar" {
			t.Errorf("Message cookie value from request did not match, expected foo into bar, got %v", cookie.Value)
		}
	})

	t.Run("No message cookie exists in request", func(t *testing.T) {
		cookieManager := GetCookieManagerInstance()

		httpRequest := httptest.NewRequest(http.MethodGet, endpoint.Account, nil)

		cookieValue := cookieManager.GetMessageCookieValue(httpRequest)

		if cookieValue != "" {
			t.Error("Message cookie value should not exists")
		}
	})

}

func testAuthCookieValues(t *testing.T, cookie http.Cookie, maxAge int) {
	if cookie.Name != "stopnik_auth" {
		t.Error("auth cookie name is wrong")
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
