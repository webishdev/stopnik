package handler

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
)

type TokenHandler struct{}

func (handler *TokenHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log.Printf("%s %s %s\n", r.RemoteAddr, r.Method, r.URL)
	if r.Method == http.MethodPost {
		for k, v := range r.Header {
			log.Printf("%v: %v\n", k, v)
		}

		if r.Body != nil {
			bodyBytes, err := io.ReadAll(r.Body)
			if err != nil {
				fmt.Printf("Body reading error: %v", err)
				return
			}
			log.Printf("POST Body:\n%s\n", bodyBytes)
			defer r.Body.Close()
		}

		t := map[string]interface{}{
			"access_token": 1234,
		}

		bytes, err1 := json.Marshal(t)
		if err1 != nil {
			return
		}
		_, err2 := w.Write(bytes)
		if err2 != nil {
			return
		}
	} else {
		NotFoundHandler(w, r)
	}
}
