package handler

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

type errorTestCase struct {
	name    string
	status  int
	handler func(http.ResponseWriter, *http.Request)
}

var errorTestCases = []errorTestCase{
	{"Method not allowed", http.StatusMethodNotAllowed, MethodNotAllowedHandler},
	{"Forbidden", http.StatusForbidden, ForbiddenHandler},
	{"Internal server error", http.StatusInternalServerError, InternalServerErrorHandler},
	{"Not found", http.StatusNotFound, NotFoundHandler},
	{"No content", http.StatusNoContent, NoContentHandler},
	{"See other", http.StatusSeeOther, SeeOtherHandler},
}

var testStatusCodes = []int{
	http.StatusOK,
	http.StatusBadRequest,
	http.StatusInternalServerError,
}

func Test_Errors(t *testing.T) {
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

			sendStatus(testStatus, "message", rr, httpRequest)

			if rr.Code != testStatus {
				t.Errorf("handler returned wrong status code: got %v want %v", rr.Code, testStatus)
			}
		})
	}

}
