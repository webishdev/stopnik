package handler

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	internalHttp "stopnik/internal/http"
	"stopnik/internal/server/validation"
	"stopnik/internal/store"
	"testing"
)

func Test_Authorize(t *testing.T) {

	var testInvalidAuthorizeHttpMethods = []string{
		http.MethodPut,
		http.MethodPatch,
		http.MethodDelete,
	}

	for _, method := range testInvalidAuthorizeHttpMethods {
		testMessage := fmt.Sprintf("Authorize with unsupported method %s", method)
		t.Run(testMessage, func(t *testing.T) {
			authorizeHandler := CreateAuthorizeHandler(&validation.RequestValidator{}, &internalHttp.CookieManager{}, &store.SessionManager{}, &store.TokenManager{})

			rr := httptest.NewRecorder()

			authorizeHandler.ServeHTTP(rr, httptest.NewRequest(method, "/authorize", nil))

			if rr.Code != http.StatusMethodNotAllowed {
				t.Errorf("handler returned wrong status code: got %v want %v", rr.Code, http.StatusMethodNotAllowed)
			}
		})
	}

}
