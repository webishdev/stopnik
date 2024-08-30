package manager

import (
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/webishdev/stopnik/internal/config"
	"github.com/webishdev/stopnik/internal/crypto"
	"sync"
)

type DefaultKeyLoader struct {
	keyFallback crypto.ServerSecretLoader
	keyManager  *KeyManger
}

var keyLoaderLock = &sync.Mutex{}
var keyLoaderSingleton *DefaultKeyLoader

func GetDefaultKeyLoaderInstance() *DefaultKeyLoader {
	keyLoaderLock.Lock()
	defer keyLoaderLock.Unlock()
	if keyLoaderSingleton == nil {
		keyLoaderSingleton = &DefaultKeyLoader{
			keyFallback: crypto.NewServerSecretLoader(),
			keyManager:  GetKeyMangerInstance(),
		}
	}
	return keyLoaderSingleton
}

func (defaultKeyLoader *DefaultKeyLoader) LoadKeys(client *config.Client) (*crypto.ManagedKey, bool) {
	key := defaultKeyLoader.keyManager.getClientKey(client)
	if key == nil {
		return nil, false
	}

	return key, true
}

func (defaultKeyLoader *DefaultKeyLoader) GetServerKey() jwt.SignEncryptParseOption {
	return defaultKeyLoader.keyFallback.GetServerKey()
}
