package handler

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"stopnik/internal/config"
	"stopnik/internal/server/validation"
	"stopnik/internal/store"
	"testing"
)

func Test_Revoke(t *testing.T) {

	var testInvalidRevokeHttpMethods = []string{
		http.MethodGet,
		http.MethodPut,
		http.MethodPatch,
		http.MethodDelete,
	}

	for _, method := range testInvalidRevokeHttpMethods {
		testMessage := fmt.Sprintf("Revoke with unsupported method %s", method)
		t.Run(testMessage, func(t *testing.T) {
			revokeHandler := CreateRevokeHandler(&config.Config{}, &validation.RequestValidator{}, &store.TokenManager{})

			rr := httptest.NewRecorder()

			revokeHandler.ServeHTTP(rr, httptest.NewRequest(method, "/introspect", nil))

			if rr.Code != http.StatusMethodNotAllowed {
				t.Errorf("handler returned wrong status code: got %v want %v", rr.Code, http.StatusMethodNotAllowed)
			}
		})
	}
}
