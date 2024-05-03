package handler

import (
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/google/uuid"
	"log"
	"net/http"
	"time"
	"tiny-gate/internal/config"
	"tiny-gate/internal/oauth2"
	"tiny-gate/internal/pkce"
	"tiny-gate/internal/store"
)

type TokenHandler struct {
	config           *config.Config
	authSessionStore *store.Store[store.AuthSession]
	accessTokenStore *store.Store[oauth2.AccessToken]
}

func CreateTokenHandler(config *config.Config, authSessionStore *store.Store[store.AuthSession], accessTokenStore *store.Store[oauth2.AccessToken]) *TokenHandler {
	return &TokenHandler{
		config:           config,
		authSessionStore: authSessionStore,
		accessTokenStore: accessTokenStore,
	}
}

func (handler *TokenHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log.Printf("%s %s %s\n", r.RemoteAddr, r.Method, r.URL)
	if r.Method == http.MethodPost {
		for k, v := range r.Header {
			log.Printf("%v: %v\n", k, v)
		}

		//if r.Body != nil {
		//	bodyBytes, err := io.ReadAll(r.Body)
		//	if err != nil {
		//		fmt.Printf("Body reading error: %v", err)
		//		return
		//	}
		//	log.Printf("POST Body:\n%s\n", bodyBytes)
		//	defer func(Body io.ReadCloser) {
		//		err := Body.Close()
		//		if err != nil {
		//
		//		}
		//	}(r.Body)
		//}

		clientId, clientSecret, ok := r.BasicAuth()
		if !ok {
			ForbiddenHandler(w, r)
			return
		}

		client, clientExists := handler.config.GetClient(clientId)
		if !clientExists {
			ForbiddenHandler(w, r)
			return
		}

		codeVerifier := r.PostFormValue("code_verifier") // https://datatracker.ietf.org/doc/html/rfc7636#section-4.1
		if codeVerifier != "" {
			code := r.PostFormValue("code")
			authSession, authSessionExists := handler.authSessionStore.Get(code)
			if !authSessionExists {
				ForbiddenHandler(w, r)
				return
			}
			validPKCE := pkce.ValidatePKCE(pkce.S256, authSession.CodeChallenge, codeVerifier)
			if !validPKCE {
				ForbiddenHandler(w, r)
				return
			}
		}

		secretHash := fmt.Sprintf("%x", sha512.Sum512([]byte(clientSecret)))

		if secretHash != client.Secret {
			ForbiddenHandler(w, r)
			return
		}

		id := uuid.New()
		accessTokenValue := base64.RawURLEncoding.EncodeToString([]byte(id.String()))
		accessToken := oauth2.AccessToken(accessTokenValue)
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
