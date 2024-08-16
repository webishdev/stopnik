package error

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func Test_Errors(t *testing.T) {
	type errorTestCase struct {
		name    string
		status  int
		handler func(http.ResponseWriter, *http.Request)
	}

	errorHandler := NewErrorHandler()

	var errorTestCases = []errorTestCase{
		{"Method not allowed", http.StatusMethodNotAllowed, errorHandler.MethodNotAllowedHandler},
		{"Forbidden", http.StatusForbidden, errorHandler.ForbiddenHandler},
		{"Internal server error", http.StatusInternalServerError, errorHandler.InternalServerErrorHandler},
		{"Not found", http.StatusNotFound, errorHandler.NotFoundHandler},
		{"No content", http.StatusNoContent, errorHandler.NoContentHandler},
		{"See other", http.StatusSeeOther, errorHandler.SeeOtherHandler},
	}

	var testStatusCodes = []int{
		http.StatusOK,
		http.StatusBadRequest,
		http.StatusInternalServerError,
	}

	for _, test := range errorTestCases {
		testMessage := fmt.Sprintf("Error handler %s %v", test.name, test.status)
		t.Run(testMessage, func(t *testing.T) {
			httpRequest := &http.Request{}
			rr := httptest.NewRecorder()

			test.handler(rr, httpRequest)

			if rr.Code != test.status {
				t.Errorf("handler returned wrong status code: got %v want %v", rr.Code, test.status)
			}
		})
	}

	for _, testStatus := range testStatusCodes {
		testMessage := fmt.Sprintf("Send status code %d", testStatus)
		t.Run(testMessage, func(t *testing.T) {
			httpRequest := &http.Request{}
			rr := httptest.NewRecorder()

			errorHandler.sendStatus(testStatus, "message", rr, httpRequest)

			if rr.Code != testStatus {
				t.Errorf("handler returned wrong status code: got %v want %v", rr.Code, testStatus)
			}
		})
	}

}
