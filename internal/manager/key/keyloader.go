package key

import (
	"github.com/webishdev/stopnik/internal/config"
	"github.com/webishdev/stopnik/internal/crypto"
	"sync"
)

type defaultKeyLoader struct {
	keyManager *Manger
}

var keyLoaderLock = &sync.Mutex{}
var keyLoaderSingleton crypto.KeyLoader

func GetDefaultKeyLoaderInstance() crypto.KeyLoader {
	keyLoaderLock.Lock()
	defer keyLoaderLock.Unlock()
	if keyLoaderSingleton == nil {
		defaultKeyLoader := defaultKeyLoader{
			keyManager: GetKeyMangerInstance(),
		}
		keyLoaderSingleton = &defaultKeyLoader
	}
	return keyLoaderSingleton
}

func (defaultKeyLoader *defaultKeyLoader) LoadKeys(client *config.Client) (*crypto.ManagedKey, bool) {
	key := defaultKeyLoader.keyManager.getClientKey(client)
	if key == nil {
		return nil, false
	}

	return key, true
}
