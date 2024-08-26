package store

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/webishdev/stopnik/internal/config"
	"github.com/webishdev/stopnik/internal/crypto"
)

type KeyManger struct {
	keyStore *Store[crypto.ManagedKey]
}

type DefaultKeyLoader struct {
	keyFallback crypto.ServerSecretLoader
	keyManager  *KeyManger
}

func NewDefaultKeyLoader(config *config.Config, keyManager *KeyManger) *DefaultKeyLoader {
	return &DefaultKeyLoader{
		keyFallback: crypto.NewServerSecretLoader(config),
		keyManager:  keyManager,
	}
}

func (defaultKeyLoader *DefaultKeyLoader) LoadKeys(client *config.Client) (*crypto.ManagedKey, bool) {
	key := defaultKeyLoader.keyManager.getClientKey(client)
	if key == nil {
		return nil, false
	}

	return key, true
}

func (defaultKeyLoader *DefaultKeyLoader) GetServerSecret() jwt.SignEncryptParseOption {
	return defaultKeyLoader.keyFallback.GetServerSecret()
}

func NewKeyManger(config *config.Config) (*KeyManger, error) {
	newStore := NewStore[crypto.ManagedKey]()
	keyManager := &KeyManger{
		keyStore: &newStore,
	}

	serverKeyError := keyManager.addSeverKey(config)
	if serverKeyError != nil {
		return nil, serverKeyError
	}

	clientKeyError := keyManager.addClientKeys(config)
	if clientKeyError != nil {
		return nil, clientKeyError
	}

	return keyManager, nil
}

func (km *KeyManger) getClientKey(c *config.Client) *crypto.ManagedKey {
	var result *crypto.ManagedKey
	for _, mangedKey := range km.GetAllKeys() {
		if mangedKey.Server {
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

func (km *KeyManger) GetAllKeys() []*crypto.ManagedKey {
	keyStore := *km.keyStore
	return keyStore.GetValues()
}

func (km *KeyManger) addSeverKey(c *config.Config) error {
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

func (km *KeyManger) addClientKeys(c *config.Config) error {

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

func (km *KeyManger) addManagedKey(managedKey *crypto.ManagedKey) {
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

func (km *KeyManger) convert(signingPrivateKey *crypto.SigningPrivateKey) (*crypto.ManagedKey, error) {
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
		Id:      kid,
		Key:     &key,
		Clients: []*config.Client{},
	}

	return managedKey, nil
}

func (km *KeyManger) getBytes(key interface{}) ([]byte, error) {
	switch key := key.(type) {
	case *rsa.PrivateKey:
		return x509.MarshalPKCS8PrivateKey(key)
	case *ecdsa.PrivateKey:
		return x509.MarshalECPrivateKey(key)
	}
	return nil, fmt.Errorf("unknown private key type: %T", key)
}
