package handler

import (
	"encoding/json"
	"net/http"
	"stopnik/internal/config"
	"stopnik/internal/oauth2"
	"stopnik/internal/store"
	"strings"
)

type introspectResponse struct {
	Active bool `json:"active"`
}

type IntrospectHandler struct {
	config           *config.Config
	accessTokenStore *store.Store[oauth2.AccessToken]
}

func CreateIntrospectHandler(config *config.Config, accessTokenStore *store.Store[oauth2.AccessToken]) *IntrospectHandler {
	return &IntrospectHandler{
		config:           config,
		accessTokenStore: accessTokenStore,
	}
}

func (handler *IntrospectHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		authorization := r.Header.Get("Authorization")
		if authorization == "" || !strings.Contains(authorization, "Bearer ") {
			ForbiddenHandler(w, r)
			return
		}
		authorizationToken := strings.Replace(authorization, "Bearer ", "", 1)
		_, authorizationTokenExists := handler.accessTokenStore.Get(authorizationToken)
		if !authorizationTokenExists {
			ForbiddenHandler(w, r)
			return
		}

		token := r.PostFormValue("token")
		_, tokenExists := handler.accessTokenStore.Get(token)

		introspectResponse := introspectResponse{
			Active: tokenExists,
		}

		bytes, introspectMarshalError := json.Marshal(introspectResponse)
		if introspectMarshalError != nil {
			return
		}
		_, writeError := w.Write(bytes)
		if writeError != nil {
			return
		}
	} else {
		MethodNotAllowedHandler(w, r)
		return
	}
}
