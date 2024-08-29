package assets

import (
	"fmt"
	"github.com/webishdev/stopnik/internal/config"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func Test_Assets(t *testing.T) {
	testConfig := &config.Config{
		Clients: []config.Client{
			{
				Id:           "foo",
				ClientSecret: "d82c4eb5261cb9c8aa9855edd67d1bd10482f41529858d925094d173fa662aa91ff39bc5b188615273484021dfb16fd8284cf684ccf0fc795be3aa2fc1e6c181",
				Redirects:    []string{"https://example.com/callback"},
			},
		},
		Users: []config.User{
			{
				Username: "foo",
				Password: "d82c4eb5261cb9c8aa9855edd67d1bd10482f41529858d925094d173fa662aa91ff39bc5b188615273484021dfb16fd8284cf684ccf0fc795be3aa2fc1e6c181",
			},
		},
	}

	err := testConfig.Setup()
	if err != nil {
		t.Error(err)
	}

	assetsHandler := NewAssetHandler()

	var testAssetsHttpMethods = []string{
		http.MethodPost,
		http.MethodPut,
		http.MethodPatch,
		http.MethodDelete,
	}

	type assetHttpParameter struct {
		path         string
		expectedCode int
		matches      bool
	}

	var testAssetsHttpParameters = []assetHttpParameter{
		{path: "/assets/styles.css", expectedCode: http.StatusOK, matches: true},
		{path: "/assets/stopnik_250.png", expectedCode: http.StatusOK, matches: true},
		{path: "/assets/foo.css", expectedCode: http.StatusNotFound, matches: true},
		{path: "/assets/bar.png", expectedCode: http.StatusNotFound, matches: true},
		{path: "/foo/bar.png", expectedCode: http.StatusNotFound, matches: false},
		{path: "/abc/123.css", expectedCode: http.StatusNotFound, matches: false},
	}

	for _, test := range testAssetsHttpParameters {
		testMessage := fmt.Sprintf("Access assets %s with result %d", test.path, test.expectedCode)
		t.Run(testMessage, func(t *testing.T) {

			httpRequest := &http.Request{
				Method: http.MethodGet,
				URL: &url.URL{
					Path: test.path,
				},
			}
			rr := httptest.NewRecorder()

			assetsHandler.ServeHTTP(rr, httpRequest)

			if rr.Code != test.expectedCode {
				t.Errorf("handler returned wrong status code, %v != %v", rr.Code, test.expectedCode)
			}

		})

		testMessage = fmt.Sprintf("Access assets %s which matches %t", test.path, test.matches)
		t.Run(testMessage, func(t *testing.T) {
			httpRequest := &http.Request{
				URL: &url.URL{
					Path: test.path,
				},
			}

			matches := assetsHandler.Matches(httpRequest)

			if matches != test.matches {
				t.Errorf("matching values is wrong, %v != %v", test.matches, matches)
			}
		})
	}

	for _, method := range testAssetsHttpMethods {
		testMessage := fmt.Sprintf("Assets with unsupported method %s", method)
		t.Run(testMessage, func(t *testing.T) {
			assetsHandler := &Handler{}

			httpRequest := &http.Request{
				Method: method,
			}
			rr := httptest.NewRecorder()

			assetsHandler.ServeHTTP(rr, httpRequest)

			if rr.Code != http.StatusMethodNotAllowed {
				t.Errorf("handler returned wrong status code: got %v want %v", rr.Code, http.StatusMethodNotAllowed)
			}
		})
	}
}
