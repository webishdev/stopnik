package http

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
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

			value := []byte("I am a simple string which likes to be compressed")
			_, writeError := responseWriter.Write(value)
			if writeError != nil {
				t.Fatal(writeError)
			}

			if rr.Body == nil {
				t.Fatal("response body is empty")
			}

			body := rr.Body.Bytes()
			if test.expected {
				gzipReader, gzipError := gzip.NewReader(bytes.NewReader(body))
				if gzipError != nil {
					t.Fatal(gzipError)
				}
				body, gzipError = io.ReadAll(gzipReader)
				if gzipError != nil {
					t.Fatal(gzipError)
				}
			}

			if !bytes.Equal(body, value) {
				t.Errorf("expected body %q, got %q", value, body)
			}
		})
	}

}
