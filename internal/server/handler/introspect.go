package handler

import (
	"net/http"
	"stopnik/internal/config"
	"stopnik/internal/oauth2"
	"stopnik/internal/store"
	"strings"
)

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
		token := strings.Replace(authorization, "Bearer ", "", 1)
		_, exits := handler.accessTokenStore.Get(token)
		if !exits {
			ForbiddenHandler(w, r)
			return
		}
		NoContentHandler(w, r)
	} else {
		MethodNotAllowedHandler(w, r)
		return
	}
}
