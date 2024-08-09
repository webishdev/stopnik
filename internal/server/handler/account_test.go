package handler

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	internalHttp "stopnik/internal/http"
	"stopnik/internal/server/validation"
	"testing"
)

func Test_Account(t *testing.T) {

	var testInvalidAccountHttpMethods = []string{
		http.MethodPut,
		http.MethodPatch,
		http.MethodDelete,
	}

	for _, method := range testInvalidAccountHttpMethods {
		testMessage := fmt.Sprintf("Account with unsupported method %s", method)
		t.Run(testMessage, func(t *testing.T) {
			accountHandler := CreateAccountHandler(&validation.RequestValidator{}, &internalHttp.CookieManager{})

			rr := httptest.NewRecorder()

			accountHandler.ServeHTTP(rr, httptest.NewRequest(method, "/account", nil))

			if rr.Code != http.StatusMethodNotAllowed {
				t.Errorf("handler returned wrong status code: got %v want %v", rr.Code, http.StatusMethodNotAllowed)
			}
		})
	}
}
