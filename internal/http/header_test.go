package http

import (
	"fmt"
	"testing"
)

type headerParameter struct {
	value    string
	expected string
}

var headerParameters = []headerParameter{
	{Location, "Location"},
	{ContentType, "Content-Type"},
	{Authorization, "Authorization"},
	{AuthBasic, "Basic"},
	{AuthBearer, "Bearer"},
	{ContentTypeJSON, "application/json"},
}

func Test_HTTPHeaders(t *testing.T) {
	for _, test := range headerParameters {
		testMessage := fmt.Sprintf("%s", test.value)
		t.Run(testMessage, func(t *testing.T) {
			if test.value != test.expected {
				t.Errorf("assertion error, %v != %v", test.value, test.expected)
			}
		})
	}
}
