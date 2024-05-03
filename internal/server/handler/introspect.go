package handler

import (
	"net/http"
	"stopnik/internal/config"
	"stopnik/internal/oauth2"
	"stopnik/internal/store"
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

func (h *IntrospectHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	NotFoundHandler(w, r)
}
