package handler

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"
	"tiny-gate/internal/oauth2"
	"tiny-gate/internal/store"
)

type TokenHandler struct {
	accessTokenStore *store.Store[oauth2.AccessToken]
}

func CreateTokenHandler(accessTokenStore *store.Store[oauth2.AccessToken]) *TokenHandler {
	return &TokenHandler{
		accessTokenStore: accessTokenStore,
	}
}

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
			defer func(Body io.ReadCloser) {
				err := Body.Close()
				if err != nil {

				}
			}(r.Body)
		}

		accessToken := oauth2.AccessToken("1234")
		tokenDuration := time.Minute * time.Duration(45)
		handler.accessTokenStore.SetWithDuration(string(accessToken), accessToken, tokenDuration)

		accessTokenResponse := oauth2.AccessTokenResponse{
			AccessToken: accessToken,
			ExpiresIn:   int(tokenDuration / time.Millisecond),
		}

		bytes, err1 := json.Marshal(accessTokenResponse)
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
