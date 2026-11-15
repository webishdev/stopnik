package keys

import (
	"github.com/lestrrat-go/jwx/v4/jwk"
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
	keyManager     *key.Manger
	config         *config.Config
	errorHandler   *errorHandler.Handler
	keySet         jwk.Set
	loaded         bool
	dynamicVersion uint64
	mux            *sync.RWMutex
}

func NewKeysHandler(keyManager *key.Manger) *Handler {
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
		keySet, keySetError := h.getKeySet()
		if keySetError != nil {
			h.errorHandler.InternalServerErrorHandler(w, r, keySetError)
			return
		}

		jsonError := http2.SendJson(keySet, w, r)
		if jsonError != nil {
			h.errorHandler.InternalServerErrorHandler(w, r, jsonError)
			return
		}
	} else {
		h.errorHandler.MethodNotAllowedHandler(w, r)
		return
	}
}

// getKeySet returns the public keys, the set is built again when the dynamic configuration changed,
// as clients with own keys can be added or changed at any time.
func (h *Handler) getKeySet() (jwk.Set, error) {
	dynamicVersion := h.config.GetDynamicVersion()

	h.mux.RLock()
	if h.loaded && h.dynamicVersion == dynamicVersion {
		keySet := h.keySet
		h.mux.RUnlock()
		return keySet, nil
	}
	h.mux.RUnlock()

	h.mux.Lock()
	defer h.mux.Unlock()
	if h.loaded && h.dynamicVersion == dynamicVersion {
		return h.keySet, nil
	}

	// A new set is built and only used when complete, so a failure does not leave a half-filled set
	keySet := jwk.NewSet()
	for _, mangedKey := range h.keyManager.GetAllKeys() {
		addKeyError := addKey(keySet, mangedKey)
		if addKeyError != nil {
			return nil, addKeyError
		}
	}

	h.keySet = keySet
	h.dynamicVersion = dynamicVersion
	h.loaded = true
	return keySet, nil
}

func addKey(keySet jwk.Set, mangedKey *crypto.ManagedKey) error {
	mgmKey := *mangedKey.Key

	publicKey, publicKeyError := mgmKey.PublicKey()
	if publicKeyError != nil {
		return publicKeyError
	}
	addKeyError := keySet.AddKey(publicKey)
	if addKeyError != nil {
		return addKeyError
	}

	return nil
}
