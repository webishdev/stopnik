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
		expectedIssuer   string
	}
	var httpParameters = []httpParameter{
		{"https://moo.com", "", "", "https", "moo.com", "", "", "", "https://moo.com"},
		{"http://moo.com", "", "", "http", "moo.com", "", "", "", "http://moo.com"},
		{"http://foo.com/bar", "", "", "http", "foo.com", "/bar", "", "", "http://foo.com"},
		{"https://foo.com/bar?hello=world", "hello=world", "", "https", "foo.com", "/bar", "?hello=world", "", "https://foo.com"},
		{"http://foo.com/bar?hello=world#blabla", "hello=world", "blabla", "http", "foo.com", "/bar", "?hello=world", "#blabla", "http://foo.com"},
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

			if requestData.scheme != test.expectedScheme {
				t.Errorf("Scheme mismatch. Expected: %s, got: %s", test.expectedScheme, requestData.scheme)
			}

			if requestData.host != test.expectedHost {
				t.Errorf("Host mismatch. Expected: %s, got: %s", test.expectedHost, request.Host)
			}

			if requestData.path != test.expectedPath {
				t.Errorf("Path mismatch. Expected: %s, got: %s", test.expectedPath, requestData.path)
			}

			if requestData.query != test.expectedQuery {
				t.Errorf("Query mismatch. Expected: %s, got: %s", test.expectedQuery, requestData.query)
			}

			if requestData.fragment != test.expectedFragment {
				t.Errorf("Fragment mismatch. Expected: %s, got: %s", test.expectedFragment, requestData.fragment)
			}

			parsedUrl, parseError := requestData.URL()
			if parseError != nil {
				t.Errorf("Error parsing URL: %s", parseError.Error())
			}

			if parsedUrl.String() != test.uri {
				t.Errorf("URL mismatch. Expected: %s, got: %s", test.uri, parsedUrl.String())
			}

			issuer := requestData.IssuerString()
			if issuer != test.expectedIssuer {
				t.Errorf("Issuer mismatch. Expected: %s, got: %s", test.expectedIssuer, issuer)
			}
		})
	}
}
