package logout

import (
	"fmt"
	"github.com/webishdev/stopnik/internal/config"
	"github.com/webishdev/stopnik/internal/endpoint"
	internalHttp "github.com/webishdev/stopnik/internal/http"
	"github.com/webishdev/stopnik/internal/manager"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func Test_Logout(t *testing.T) {

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
			},
		},
	}

	err := testConfig.Initialize()
	if err != nil {
		t.Error(err)
	}

	testInvalidCookies(t, testConfig)

	testLogout(t, testConfig)

	testLogoutNotAllowedHttpMethods(t)
}

func testInvalidCookies(t *testing.T, testConfig *config.Config) {
	t.Run("Logout with invalid cookie", func(t *testing.T) {
		cookieManager := manager.NewCookieManager()

		cookie := http.Cookie{
			Name:     testConfig.GetAuthCookieName(),
			Value:    "foobar",
			Path:     "/",
			MaxAge:   testConfig.GetSessionTimeoutSeconds(),
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
		}

		logoutHandler := NewLogoutHandler(cookieManager, "")

		rr := httptest.NewRecorder()

		request := httptest.NewRequest(http.MethodPost, endpoint.Logout, nil)
		request.AddCookie(&cookie)

		logoutHandler.ServeHTTP(rr, request)

		if rr.Code != http.StatusForbidden {
			t.Errorf("handler returned wrong status code: got %v want %v", rr.Code, http.StatusForbidden)
		}
	})
}

func testLogout(t *testing.T, testConfig *config.Config) {
	type logoutParameter struct {
		handlerRedirect  string
		formRedirect     string
		expectedRedirect string
	}

	var logoutParameters = []logoutParameter{
		{"", "", endpoint.Logout},
		{"/foo", "", "/foo"},
		{"", "/bar", "/bar"},
	}
	for _, test := range logoutParameters {
		testMessage := fmt.Sprintf("Logout handler redirect %v, form redirect %v", test.handlerRedirect, test.formRedirect)
		t.Run(testMessage, func(t *testing.T) {
			cookieManager := manager.NewCookieManager()

			user, _ := testConfig.GetUser("foo")
			cookie, _ := cookieManager.CreateAuthCookie(user.Username)

			logoutHandler := NewLogoutHandler(cookieManager, test.handlerRedirect)

			rr := httptest.NewRecorder()

			bodyString := ""
			if test.formRedirect != "" {
				bodyString = testCreateBody(
					"stopnik_logout_redirect", test.formRedirect,
				)
			}
			body := strings.NewReader(bodyString)

			request := httptest.NewRequest(http.MethodPost, endpoint.Logout, body)
			request.AddCookie(&cookie)
			if bodyString != "" {
				request.Header.Add(internalHttp.ContentType, "application/x-www-form-urlencoded")
			}

			logoutHandler.ServeHTTP(rr, request)

			if rr.Code != http.StatusSeeOther {
				t.Errorf("handler returned wrong status code: got %v want %v", rr.Code, http.StatusSeeOther)
			}

			location, locationError := rr.Result().Location()
			if locationError != nil {
				t.Errorf("handler did not provide location %v", locationError)
			}

			if location.String() != test.expectedRedirect {
				t.Errorf("handler returned wrong location: got %v want %v", location.String(), test.expectedRedirect)
			}

			cookies := rr.Result().Cookies()

			if len(cookies) != 1 {
				t.Errorf("handler returned wrong cookie count: got %v want %v", len(cookies), 1)
			}

			currentCookie := cookies[0]
			if currentCookie.MaxAge != -1 {
				t.Errorf("handler returned wrong max age: got %v want %v", currentCookie.MaxAge, -1)
			}
		})
	}
}

func testLogoutNotAllowedHttpMethods(t *testing.T) {
	var testInvalidLogoutHttpMethods = []string{
		http.MethodGet,
		http.MethodPut,
		http.MethodPatch,
		http.MethodDelete,
	}

	for _, method := range testInvalidLogoutHttpMethods {
		testMessage := fmt.Sprintf("Logout with unsupported method %s", method)
		t.Run(testMessage, func(t *testing.T) {
			logoutHandler := NewLogoutHandler(&manager.CookieManager{}, "")

			rr := httptest.NewRecorder()

			logoutHandler.ServeHTTP(rr, httptest.NewRequest(method, endpoint.Logout, nil))

			if rr.Code != http.StatusMethodNotAllowed {
				t.Errorf("handler returned wrong status code: got %v want %v", rr.Code, http.StatusMethodNotAllowed)
			}
		})
	}
}

func testCreateBody(values ...any) string {
	result := ""
	for index, value := range values {
		result += fmt.Sprintf("%v", value)
		if index > 0 && index%2 != 0 && index < len(values)-1 {
			result += "&"
		} else if index < len(values)-1 {
			result += "="
		}
	}
	return result
}
