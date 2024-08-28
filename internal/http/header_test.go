package http

import (
	"fmt"
	"testing"
)

func Test_HTTPHeaders(t *testing.T) {
	type headerParameter struct {
		value    string
		expected string
	}

	var headerParameters = []headerParameter{
		{Location, "Location"},
		{ContentType, "Content-Type"},
		{AccessControlAllowOrigin, "Access-Control-Allow-Origin"},
		{Authorization, "Authorization"},
		{AuthBasic, "Basic"},
		{AuthBearer, "Bearer"},
		{ContentTypeJSON, "application/json"},
	}

	for _, test := range headerParameters {
		testMessage := fmt.Sprintf("HTTP Header %s", test.value)
		t.Run(testMessage, func(t *testing.T) {
			if test.value != test.expected {
				t.Errorf("assertion error, %v != %v", test.value, test.expected)
			}
		})
	}
}
