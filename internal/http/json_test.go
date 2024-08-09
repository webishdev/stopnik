package http

import (
	"net/http/httptest"
	"testing"
)

func Test_SendJson(t *testing.T) {
	type TestData struct {
		Name string `json:"name"`
		Age  int    `json:"age"`
	}

	rr := httptest.NewRecorder()

	data := TestData{
		Name: "alice",
		Age:  20,
	}

	err := SendJson(data, rr)

	if err != nil {
		t.Error(err)
	}

	contentType := rr.Header().Get(ContentType)

	if contentType != ContentTypeJSON {
		t.Errorf("content type should be %s", ContentTypeJSON)
	}

	jsonString := rr.Body.String()

	if jsonString != `{"name":"alice","age":20}` {
		t.Errorf("json string should be %s, but was %s", `{"name":"alice","age":20}`, jsonString)
	}
}
