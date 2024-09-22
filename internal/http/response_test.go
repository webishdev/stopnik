package http

import (
	"fmt"
	"github.com/webishdev/stopnik/log"
	"net/http"
	"net/http/httptest"
	"testing"
)

func Test_SetEncodingHeader(t *testing.T) {
	type encodingParameter struct {
		encodingMethod string
		expected       bool
	}

	var encodingParameters = []encodingParameter{
		{encodingMethod: string(CompressionMethodGZip), expected: true},
		{encodingMethod: "", expected: false},
	}

	for _, test := range encodingParameters {
		testMessage := fmt.Sprintf("Set encoding header with value %s", test.encodingMethod)
		t.Run(testMessage, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, "/foo", nil)
			if test.expected {
				request.Header.Set(AcceptEncoding, test.encodingMethod)
			}

			requestData := NewRequestData(request)

			rr := httptest.NewRecorder()
			responseWriter := NewResponseWriter(rr, requestData)
			responseWriter.SetEncodingHeader()

			contentEncodingHeader := rr.Header().Get(ContentEncoding)

			if test.expected && contentEncodingHeader != test.encodingMethod {
				t.Errorf("expected encoding header to be set")
			}
		})
	}

}

func Test_Write(t *testing.T) {
	type encodingParameter struct {
		encodingMethod string
		expectedBytes  int
		expected       bool
	}

	var encodingParameters = []encodingParameter{
		// unfortunately for a small string the gzipped version is larger because of overhead
		{encodingMethod: string(CompressionMethodGZip), expectedBytes: 71, expected: true},
		{encodingMethod: "", expectedBytes: 49, expected: false},
	}

	for _, test := range encodingParameters {
		testMessage := fmt.Sprintf("Set encoding header with value %s", test.encodingMethod)
		t.Run(testMessage, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, "/foo", nil)
			if test.expected {
				request.Header.Set(AcceptEncoding, test.encodingMethod)
			}

			requestData := NewRequestData(request)

			rr := httptest.NewRecorder()
			responseWriter := NewResponseWriter(rr, requestData)
			responseWriter.SetEncodingHeader()

			value := []byte("I am a simple string which likes to be compressed")
			_, writeError := responseWriter.Write(value)
			if writeError != nil {
				t.Fatal(writeError)
			}

			if rr.Body != nil {
				responseBytes := rr.Body.Bytes()
				log.Info("%v", len(responseBytes))
				if len(responseBytes) != test.expectedBytes {
					t.Errorf("expected %d bytes, got %d", test.expectedBytes, len(responseBytes))
				}
			} else {
				t.Error("response body is empty")
			}

		})
	}

}
