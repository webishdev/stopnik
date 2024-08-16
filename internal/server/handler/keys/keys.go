package keys

import (
	"crypto/rsa"
	"crypto/tls"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/webishdev/stopnik/internal/config"
	http2 "github.com/webishdev/stopnik/internal/http"
	errorHandler "github.com/webishdev/stopnik/internal/server/handler/error"
	"github.com/webishdev/stopnik/log"
	"net/http"
	"sync"
)

type Handler struct {
	config       *config.Config
	errorHandler *errorHandler.Handler
	keySet       jwk.Set
	loaded       bool
	mux          *sync.RWMutex
}

func NewKeysHandler(config *config.Config) *Handler {
	return &Handler{
		config:       config,
		errorHandler: errorHandler.NewErrorHandler(),
		keySet:       jwk.NewSet(),
		loaded:       false,
		mux:          &sync.RWMutex{},
	}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log.AccessLogRequest(r)
	if r.Method == http.MethodGet {
		h.mux.Lock()
		defer h.mux.Unlock()
		if !h.loaded {
			keyPair, pairError := tls.LoadX509KeyPair(h.config.Server.TokenKeys.Cert, h.config.Server.TokenKeys.Key)
			if pairError != nil {
				h.errorHandler.InternalServerErrorHandler(w, r)
				return
			}

			privateKey := keyPair.PrivateKey.(*rsa.PrivateKey)
			addKeyError := h.addKey(privateKey)
			if addKeyError != nil {
				h.errorHandler.InternalServerErrorHandler(w, r)
				return
			}

			clientKeysError := h.addClientKeys()
			if clientKeysError != nil {
				h.errorHandler.InternalServerErrorHandler(w, r)
				return
			}

			h.loaded = true
		}

		jsonError := http2.SendJson(h.keySet, w)
		if jsonError != nil {
			h.errorHandler.InternalServerErrorHandler(w, r)
			return
		}
	} else {
		h.errorHandler.MethodNotAllowedHandler(w, r)
		return
	}
}

func (h *Handler) addClientKeys() error {

	for _, client := range h.config.Clients {
		if client.TokenKeys.Cert != "" && client.TokenKeys.Key != "" {
			keyPair, pairError := tls.LoadX509KeyPair(client.TokenKeys.Cert, client.TokenKeys.Key)
			if pairError != nil {
				return pairError
			}

			privateKey := keyPair.PrivateKey.(*rsa.PrivateKey)
			addKeyError := h.addKey(privateKey)
			if addKeyError != nil {
				return addKeyError
			}
		}
	}

	return nil
}

func (h *Handler) addKey(key interface{}) error {
	raw, jwkError := jwk.FromRaw(key)
	if jwkError != nil {
		return jwkError
	}

	setError := raw.Set(jwk.KeyIDKey, "abcd")
	if setError != nil {
		return setError
	}

	addKeyError := h.keySet.AddKey(raw)
	if addKeyError != nil {
		return addKeyError
	}

	return nil
}
