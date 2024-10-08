package account

import (
	"fmt"
	"github.com/google/uuid"
	"github.com/webishdev/stopnik/internal/config"
	"github.com/webishdev/stopnik/internal/endpoint"
	internalHttp "github.com/webishdev/stopnik/internal/http"
	"github.com/webishdev/stopnik/internal/manager/cookie"
	"github.com/webishdev/stopnik/internal/manager/session"
	"github.com/webishdev/stopnik/internal/server/validation"
	"github.com/webishdev/stopnik/internal/template"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func Test_AccountWithCookie(t *testing.T) {
	testConfig := testInitializeConfig(t)

	requestValidator := validation.NewRequestValidator()
	cookieManager := cookie.GetCookieManagerInstance()
	loginSessionManager := session.GetLoginSessionManagerInstance()
	templateManager := template.GetTemplateManagerInstance()

	user, _ := testConfig.GetUser("foo")
	loginSession := &session.LoginSession{
		Id:       uuid.NewString(),
		Username: user.Username,
	}
	loginSessionManager.StartSession(loginSession)
	authCookie, _ := cookieManager.CreateAuthCookie(user.Username, loginSession.Id)

	accountHandler := NewAccountHandler(requestValidator, cookieManager, loginSessionManager, templateManager)

	rr := httptest.NewRecorder()

	request := httptest.NewRequest(http.MethodGet, endpoint.Account, nil)
	request.AddCookie(&authCookie)

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
}

func Test_AccountWithoutCookie(t *testing.T) {
	testInitializeConfig(t)

	requestValidator := validation.NewRequestValidator()
	cookieManager := cookie.GetCookieManagerInstance()
	loginSessionManager := session.GetLoginSessionManagerInstance()
	templateManager := template.GetTemplateManagerInstance()

	accountHandler := NewAccountHandler(requestValidator, cookieManager, loginSessionManager, templateManager)

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
}

func Test_AccountLogin(t *testing.T) {
	testConfig := testInitializeConfig(t)

	type loginParameter struct {
		username string
		password string
		success  bool
	}
	var loginParameters = []loginParameter{
		{"foo", "bar", true},
		{"xxx", "zzz", false},
	}
	for _, test := range loginParameters {
		testMessage := fmt.Sprintf("Account login %v", test.username)

		t.Run(testMessage, func(t *testing.T) {
			requestValidator := validation.NewRequestValidator()
			cookieManager := cookie.GetCookieManagerInstance()
			loginSessionManager := session.GetLoginSessionManagerInstance()
			templateManager := template.GetTemplateManagerInstance()

			accountHandler := NewAccountHandler(requestValidator, cookieManager, loginSessionManager, templateManager)

			loginToken := requestValidator.NewLoginToken(uuid.NewString())

			rr := httptest.NewRecorder()

			bodyString := testCreateBody(
				"stopnik_username", test.username,
				"stopnik_password", test.password,
				"stopnik_auth_session", loginToken,
			)
			body := strings.NewReader(bodyString)

			request := httptest.NewRequest(http.MethodPost, endpoint.Account, body)
			request.Header.Add(internalHttp.ContentType, "application/x-www-form-urlencoded")

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

			var authCookie *http.Cookie
			for _, currentCookie := range rr.Result().Cookies() {
				if currentCookie.Name == testConfig.GetAuthCookieName() {
					authCookie = currentCookie
					break
				}
			}

			if test.success && authCookie == nil {
				t.Error("Should have auth cookie after login")
			} else if !test.success && authCookie != nil {
				t.Error("Should not have auth cookie after login")
			}

			_, loginSessionExists := loginSessionManager.SearchSession(test.username)
			if test.success != loginSessionExists {
				t.Error("Login session state does not match")
			}
		})
	}
}

func Test_AccountNotAllowedHttpMethods(t *testing.T) {
	var testInvalidAccountHttpMethods = []string{
		http.MethodPut,
		http.MethodPatch,
		http.MethodDelete,
	}

	for _, method := range testInvalidAccountHttpMethods {
		testMessage := fmt.Sprintf("Account with unsupported method %s", method)
		t.Run(testMessage, func(t *testing.T) {
			loginSessionManager := session.GetLoginSessionManagerInstance()
			accountHandler := NewAccountHandler(&validation.RequestValidator{}, &cookie.Manager{}, loginSessionManager, &template.Manager{})

			rr := httptest.NewRecorder()

			accountHandler.ServeHTTP(rr, httptest.NewRequest(method, endpoint.Account, nil))

			if rr.Code != http.StatusMethodNotAllowed {
				t.Errorf("handler returned wrong status code: got %v want %v", rr.Code, http.StatusMethodNotAllowed)
			}
		})
	}
}

func testInitializeConfig(t *testing.T) *config.Config {
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

	initializationError := config.Initialize(testConfig)
	if initializationError != nil {
		t.Fatal(initializationError)
	}

	return testConfig
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
