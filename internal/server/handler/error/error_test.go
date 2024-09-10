package error

import (
	"errors"
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
		{"Not found", http.StatusNotFound, errorHandler.NotFoundHandler},
		{"No content", http.StatusNoContent, errorHandler.NoContentHandler},
		{"See other", http.StatusSeeOther, errorHandler.SeeOtherHandler},
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

}

func Test_StatusCodes(t *testing.T) {
	var testStatusCodes = []int{
		http.StatusOK,
		http.StatusBadRequest,
		http.StatusInternalServerError,
	}

	errorHandler := NewErrorHandler()

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

func Test_InternalServerError(t *testing.T) {
	errorHandler := NewErrorHandler()

	httpRequest := &http.Request{}
	rr := httptest.NewRecorder()

	errorHandler.InternalServerErrorHandler(rr, httpRequest, errors.New("message"))

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("Internal server error returned wrong status code")
	}
}
