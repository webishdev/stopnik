package store

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"github.com/webishdev/stopnik/internal/config"
	"github.com/webishdev/stopnik/internal/crypto"
)

type ManagedKey struct {
	Id  string
	Key interface{}
}

type KeyManger struct {
	keyStore *Store[ManagedKey]
}

func NewKeyManger(config *config.Config) (*KeyManger, error) {
	keyManager := &KeyManger{
		keyStore: NewStore[ManagedKey](),
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

func (km *KeyManger) GetAllKeys() []*ManagedKey {
	return km.keyStore.GetValues()
}

func (km *KeyManger) addSeverKey(config *config.Config) error {
	if config.Server.PrivateKey != "" {
		privateKey, loadError := crypto.LoadPrivateKey(config.Server.PrivateKey)
		if loadError != nil {
			return loadError
		}

		managedKey, convertError := km.convert(privateKey)
		if convertError != nil {
			return convertError
		}

		km.keyStore.Set(managedKey.Id, managedKey)
	}

	return nil
}

func (km *KeyManger) addClientKeys(config *config.Config) error {

	for _, client := range config.Clients {
		if client.PrivateKey != "" {
			privateKey, loadError := crypto.LoadPrivateKey(client.PrivateKey)
			if loadError != nil {
				return loadError
			}
			managedKey, convertError := km.convert(privateKey)
			if convertError != nil {
				return convertError
			}

			km.keyStore.Set(managedKey.Id, managedKey)
		}
	}

	return nil
}

func (km *KeyManger) convert(privateKey interface{}) (*ManagedKey, error) {
	keyAsBytes, loadError := km.getBytes(privateKey)
	if loadError != nil {
		return nil, loadError
	}
	base64String := base64.StdEncoding.EncodeToString(keyAsBytes)
	kid := crypto.Sha1Hash(base64String)

	managedKey := &ManagedKey{
		Id:  kid,
		Key: privateKey,
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
