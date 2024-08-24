package account

import (
	"fmt"
	"github.com/webishdev/stopnik/internal/config"
	"github.com/webishdev/stopnik/internal/endpoint"
	internalHttp "github.com/webishdev/stopnik/internal/http"
	"github.com/webishdev/stopnik/internal/server/validation"
	"github.com/webishdev/stopnik/internal/template"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func Test_Account(t *testing.T) {

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

	err := testConfig.Setup()
	if err != nil {
		t.Error(err)
	}

	testAccountWithoutCookie(t, testConfig)

	testAccountWithCookie(t, testConfig)

	testAccountLogin(t, testConfig)

	testAccountNotAllowedHttpMethods(t)
}

func testAccountWithoutCookie(t *testing.T, testConfig *config.Config) {
	t.Run("Account without cookie", func(t *testing.T) {
		requestValidator := validation.NewRequestValidator(testConfig)
		cookieManager := internalHttp.NewCookieManager(testConfig)
		templateManager := template.NewTemplateManager(testConfig)

		accountHandler := NewAccountHandler(requestValidator, cookieManager, templateManager)

		rr := httptest.NewRecorder()

		accountHandler.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, endpoint.Account, nil))

		if rr.Code != http.StatusOK {
			t.Errorf("handler returned wrong status code: got %v want %v", rr.Code, http.StatusOK)
		}

		contentType := rr.Header().Get(internalHttp.ContentType)

		if contentType != "text/html; charset=utf-8" {
			t.Errorf("content type was not text/html: %v", contentType)
		}

		response := rr.Result()
		body, bodyReadErr := io.ReadAll(response.Body)

		if bodyReadErr != nil {
			t.Errorf("could not read response body: %v", bodyReadErr)
		}

		if body == nil {
			t.Errorf("response body was nil")
		}
	})
}

func testAccountWithCookie(t *testing.T, testConfig *config.Config) {
	t.Run("Account cookie", func(t *testing.T) {
		requestValidator := validation.NewRequestValidator(testConfig)
		cookieManager := internalHttp.NewCookieManager(testConfig)
		templateManager := template.NewTemplateManager(testConfig)

		user, _ := testConfig.GetUser("foo")
		cookie, _ := cookieManager.CreateAuthCookie(user.Username)

		accountHandler := NewAccountHandler(requestValidator, cookieManager, templateManager)

		rr := httptest.NewRecorder()

		request := httptest.NewRequest(http.MethodGet, endpoint.Account, nil)
		request.AddCookie(&cookie)

		accountHandler.ServeHTTP(rr, request)

		if rr.Code != http.StatusOK {
			t.Errorf("handler returned wrong status code: got %v want %v", rr.Code, http.StatusOK)
		}

		contentType := rr.Header().Get(internalHttp.ContentType)

		if contentType != "text/html; charset=utf-8" {
			t.Errorf("content type was not text/html: %v", contentType)
		}

		response := rr.Result()
		body, bodyReadErr := io.ReadAll(response.Body)

		if bodyReadErr != nil {
			t.Errorf("could not read response body: %v", bodyReadErr)
		}

		if body == nil {
			t.Errorf("response body was nil")
		}
	})
}

func testAccountLogin(t *testing.T, testConfig *config.Config) {
	type loginParameter struct {
		username string
		password string
	}
	var loginParameters = []loginParameter{
		{"foo", "bar"},
		{"xxx", "zzz"},
	}
	for _, test := range loginParameters {
		testMessage := fmt.Sprintf("Account login %v", test.username)

		t.Run(testMessage, func(t *testing.T) {
			requestValidator := validation.NewRequestValidator(testConfig)
			cookieManager := internalHttp.NewCookieManager(testConfig)
			templateManager := template.NewTemplateManager(testConfig)

			cookie, _ := cookieManager.CreateAuthCookie(test.username)

			accountHandler := NewAccountHandler(requestValidator, cookieManager, templateManager)

			rr := httptest.NewRecorder()

			bodyString := testCreateBody(
				"stopnik_username", test.username,
				"stopnik_password", test.password,
			)
			body := strings.NewReader(bodyString)

			request := httptest.NewRequest(http.MethodPost, endpoint.Account, body)
			request.Header.Add(internalHttp.ContentType, "application/x-www-form-urlencoded")
			request.AddCookie(&cookie)

			accountHandler.ServeHTTP(rr, request)

			if rr.Code != http.StatusSeeOther {
				t.Errorf("handler returned wrong status code: got %v want %v", rr.Code, http.StatusSeeOther)
			}

			location, locationError := rr.Result().Location()
			if locationError != nil {
				t.Errorf("location was not provied: %v", locationError)
			}

			if location.String() != endpoint.Account {
				t.Errorf("handler returned wrong location: got %v want %v", location.String(), endpoint.Account)
			}
		})
	}
}

func testAccountNotAllowedHttpMethods(t *testing.T) {
	var testInvalidAccountHttpMethods = []string{
		http.MethodPut,
		http.MethodPatch,
		http.MethodDelete,
	}

	for _, method := range testInvalidAccountHttpMethods {
		testMessage := fmt.Sprintf("Account with unsupported method %s", method)
		t.Run(testMessage, func(t *testing.T) {
			accountHandler := NewAccountHandler(&validation.RequestValidator{}, &internalHttp.CookieManager{}, &template.Manager{})

			rr := httptest.NewRecorder()

			accountHandler.ServeHTTP(rr, httptest.NewRequest(method, endpoint.Account, nil))

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
