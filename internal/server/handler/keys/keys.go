package keys

import (
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/webishdev/stopnik/internal/config"
	"github.com/webishdev/stopnik/internal/crypto"
	http2 "github.com/webishdev/stopnik/internal/http"
	"github.com/webishdev/stopnik/internal/manager/key"
	errorHandler "github.com/webishdev/stopnik/internal/server/handler/error"
	"github.com/webishdev/stopnik/log"
	"net/http"
	"sync"
)

type Handler struct {
	keyManager   *key.KeyManger
	config       *config.Config
	errorHandler *errorHandler.Handler
	keySet       jwk.Set
	loaded       bool
	mux          *sync.RWMutex
}

func NewKeysHandler(keyManager *key.KeyManger) *Handler {
	currentConfig := config.GetConfigInstance()
	return &Handler{
		keyManager:   keyManager,
		config:       currentConfig,
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
			for _, mangedKey := range h.keyManager.GetAllKeys() {
				addKeyError := h.addKey(mangedKey)
				if addKeyError != nil {
					h.errorHandler.InternalServerErrorHandler(w, r)
					return
				}
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

func (h *Handler) addKey(mangedKey *crypto.ManagedKey) error {
	key := *mangedKey.Key

	addKeyError := h.keySet.AddKey(key)
	if addKeyError != nil {
		return addKeyError
	}

	return nil
}
