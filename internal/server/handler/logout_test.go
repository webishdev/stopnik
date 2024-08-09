package handler

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	internalHttp "stopnik/internal/http"
	"testing"
)

func Test_Logout(t *testing.T) {

	var testInvalidLogoutHttpMethods = []string{
		http.MethodGet,
		http.MethodPut,
		http.MethodPatch,
		http.MethodDelete,
	}

	for _, method := range testInvalidLogoutHttpMethods {
		testMessage := fmt.Sprintf("Logout with unsupported method %s", method)
		t.Run(testMessage, func(t *testing.T) {
			logoutHandler := CreateLogoutHandler(&internalHttp.CookieManager{}, "")

			rr := httptest.NewRecorder()

			logoutHandler.ServeHTTP(rr, httptest.NewRequest(method, "/logout", nil))

			if rr.Code != http.StatusMethodNotAllowed {
				t.Errorf("handler returned wrong status code: got %v want %v", rr.Code, http.StatusMethodNotAllowed)
			}
		})
	}
}
