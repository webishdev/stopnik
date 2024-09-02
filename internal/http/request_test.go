package http

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"net/url"
	"testing"
)

func Test_RequestData(t *testing.T) {
	type httpParameter struct {
		uri              string
		query            string
		fragment         string
		expectedScheme   string
		expectedHost     string
		expectedPath     string
		expectedQuery    string
		expectedFragment string
	}
	var httpParameters = []httpParameter{
		{"https://moo.com", "", "", "https", "moo.com", "", "", ""},
		{"http://moo.com", "", "", "http", "moo.com", "", "", ""},
		{"http://foo.com/bar", "", "", "http", "foo.com", "/bar", "", ""},
		{"http://foo.com/bar?hello=world", "hello=world", "", "http", "foo.com", "/bar", "?hello=world", ""},
		{"http://foo.com/bar?hello=world#blabla", "hello=world", "blabla", "http", "foo.com", "/bar", "?hello=world", "#blabla"},
	}
	for _, test := range httpParameters {
		testMessage := fmt.Sprintf("Request data for %s", test.uri)
		t.Run(testMessage, func(t *testing.T) {
			testUrl := &url.URL{
				Scheme:      test.expectedScheme,
				Host:        test.expectedHost,
				RawPath:     test.expectedPath,
				RawQuery:    test.query,
				RawFragment: test.fragment,
			}

			var provideTLS *tls.ConnectionState
			if test.expectedScheme == "https" {
				provideTLS = &tls.ConnectionState{}
			}
			request := &http.Request{
				URL:  testUrl,
				Host: test.expectedHost,
				TLS:  provideTLS,
			}

			requestData := NewRequestData(request)

			if requestData.Scheme != test.expectedScheme {
				t.Errorf("Scheme mismatch. Expected: %s, got: %s", test.expectedScheme, requestData.Scheme)
			}

			if requestData.Host != test.expectedHost {
				t.Errorf("Host mismatch. Expected: %s, got: %s", test.expectedHost, request.Host)
			}

			if requestData.Path != test.expectedPath {
				t.Errorf("Path mismatch. Expected: %s, got: %s", test.expectedPath, requestData.Path)
			}

			if requestData.Query != test.expectedQuery {
				t.Errorf("Query mismatch. Expected: %s, got: %s", test.expectedQuery, requestData.Query)
			}

			if requestData.Fragment != test.expectedFragment {
				t.Errorf("Fragment mismatch. Expected: %s, got: %s", test.expectedFragment, requestData.Fragment)
			}

			parsedUrl, parseError := requestData.URL()
			if parseError != nil {
				t.Errorf("Error parsing URL: %s", parseError.Error())
			}

			if parsedUrl.String() == "" {
				t.Errorf("Parsed URL is empty")
			}

			issuer := requestData.IssuerString()
			if issuer == "" {
				t.Errorf("Issuer should not be empty")
			}
		})
	}
}
