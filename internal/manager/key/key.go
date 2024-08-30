package key

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/webishdev/stopnik/internal/config"
	"github.com/webishdev/stopnik/internal/crypto"
	"github.com/webishdev/stopnik/internal/store"
	"github.com/webishdev/stopnik/log"
	"sync"
)

type Manger struct {
	keyStore *store.Store[crypto.ManagedKey]
}

var keyManagerLock = &sync.Mutex{}
var keyManagerSingleton *Manger

func GetKeyMangerInstance() *Manger {
	keyManagerLock.Lock()
	defer keyManagerLock.Unlock()
	if keyManagerSingleton == nil {
		currentConfig := config.GetConfigInstance()
		newStore := store.NewStore[crypto.ManagedKey]()
		keyManager := &Manger{
			keyStore: &newStore,
		}

		serverKeyError := keyManager.addSeverKey(currentConfig)
		if serverKeyError != nil {
			log.Error(serverKeyError.Error())
			panic(serverKeyError)
		}

		clientKeyError := keyManager.addClientKeys(currentConfig)
		if clientKeyError != nil {
			panic(clientKeyError)
		}

		keyManagerSingleton = keyManager
	}

	return keyManagerSingleton
}

func (km *Manger) getClientKey(c *config.Client) *crypto.ManagedKey {
	var result *crypto.ManagedKey
	for _, mangedKey := range km.GetAllKeys() {
		if result == nil && mangedKey.Server {
			result = mangedKey
		}
		for _, client := range mangedKey.Clients {
			if client.Id == c.Id {
				result = mangedKey
				break
			}
		}
	}

	return result
}

func (km *Manger) GetAllKeys() []*crypto.ManagedKey {
	keyStore := *km.keyStore
	return keyStore.GetValues()
}

func (km *Manger) addSeverKey(c *config.Config) error {
	if c.Server.PrivateKey != "" {
		privateKey, loadError := crypto.LoadPrivateKey(c.Server.PrivateKey)
		if loadError != nil {
			return loadError
		}

		managedKey, convertError := km.convert(privateKey)
		if convertError != nil {
			return convertError
		}

		managedKey.Server = true
		km.addManagedKey(managedKey)
	}

	return nil
}

func (km *Manger) addClientKeys(c *config.Config) error {

	for _, client := range c.Clients {
		if client.PrivateKey != "" {
			signingPrivateKey, loadError := crypto.LoadPrivateKey(client.PrivateKey)
			if loadError != nil {
				return loadError
			}
			managedKey, convertError := km.convert(signingPrivateKey)
			if convertError != nil {
				return convertError
			}

			managedKey.Clients = []*config.Client{&client}
			km.addManagedKey(managedKey)
		}
	}

	return nil
}

func (km *Manger) addManagedKey(managedKey *crypto.ManagedKey) {
	keyStore := *km.keyStore
	existingKey, exists := keyStore.Get(managedKey.Id)
	if exists {
		mergedKey := &crypto.ManagedKey{
			Id:      managedKey.Id,
			Key:     managedKey.Key,
			Server:  managedKey.Server || existingKey.Server,
			Clients: append(managedKey.Clients, existingKey.Clients...),
		}
		keyStore.Set(mergedKey.Id, mergedKey)
	} else {
		keyStore.Set(managedKey.Id, managedKey)
	}
}

func (km *Manger) convert(signingPrivateKey *crypto.SigningPrivateKey) (*crypto.ManagedKey, error) {
	keyAsBytes, loadError := km.getBytes(signingPrivateKey.PrivateKey)
	if loadError != nil {
		return nil, loadError
	}
	base64String := base64.StdEncoding.EncodeToString(keyAsBytes)
	kid := crypto.Sha1Hash(base64String)

	key, jwkError := jwk.FromRaw(signingPrivateKey.PrivateKey)
	if jwkError != nil {
		return nil, jwkError
	}

	var setError error

	if settError := key.Set(jwk.KeyIDKey, kid); settError != nil {
		return nil, setError
	}

	if settError := key.Set(jwk.AlgorithmKey, signingPrivateKey.SignatureAlgorithm); settError != nil {
		return nil, setError
	}

	if settError := key.Set(jwk.KeyUsageKey, "sig"); settError != nil {
		return nil, setError
	}

	managedKey := &crypto.ManagedKey{
		Id:            kid,
		Key:           &key,
		HashAlgorithm: signingPrivateKey.HashAlgorithm,
		Clients:       []*config.Client{},
	}

	return managedKey, nil
}

func (km *Manger) getBytes(key interface{}) ([]byte, error) {
	switch key := key.(type) {
	case *rsa.PrivateKey:
		return x509.MarshalPKCS8PrivateKey(key)
	case *ecdsa.PrivateKey:
		return x509.MarshalECPrivateKey(key)
	}
	return nil, fmt.Errorf("unknown private key type: %T", key)
}
