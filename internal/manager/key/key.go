package key

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/webishdev/stopnik/internal/config"
	"github.com/webishdev/stopnik/internal/crypto"
	"github.com/webishdev/stopnik/internal/store"
	"github.com/webishdev/stopnik/internal/system"
	"github.com/webishdev/stopnik/log"
	"slices"
	"strings"
	"sync"
)

type Manger struct {
	config         *config.Config
	mutex          *sync.Mutex
	serverKey      *crypto.ManagedKey
	keyStore       *store.Store[crypto.ManagedKey]
	dynamicVersion uint64
}

var keyManagerLock = &sync.Mutex{}
var keyManagerSingleton *Manger

func GetKeyMangerInstance() *Manger {
	keyManagerLock.Lock()
	defer keyManagerLock.Unlock()
	if keyManagerSingleton == nil {
		currentConfig := config.GetConfigInstance()
		keyManager := newKeyManager(currentConfig)

		serverKeyError := keyManager.addSeverKey(currentConfig)
		if serverKeyError != nil {
			system.Error(serverKeyError)
		}

		keyManagerSingleton = keyManager
	}

	return keyManagerSingleton
}

func newKeyManager(c *config.Config) *Manger {
	newStore := store.NewStore[crypto.ManagedKey]()
	return &Manger{
		config:   c,
		mutex:    &sync.Mutex{},
		keyStore: &newStore,
	}
}

// ValidateServerKey checks whether the private key of the server referenced by the given config.Config can be loaded.
// When no private key is referenced, nothing is checked, as an ephemeral key will be generated.
func ValidateServerKey(c *config.Config) error {
	if c.Server.PrivateKey == "" {
		return nil
	}
	return newKeyManager(c).addSeverKey(c)
}

// ValidateClientKey checks whether the private key referenced by the given config.Client can be loaded.
func ValidateClientKey(client *config.Client) error {
	return newKeyManager(nil).addClientKey(client)
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

// GetAllKeys returns the server key and the keys of all currently loaded clients.
// Client keys are loaded again, when the dynamic configuration changed.
func (km *Manger) GetAllKeys() []*crypto.ManagedKey {
	km.mutex.Lock()
	defer km.mutex.Unlock()

	if km.config != nil && km.config.GetDynamicVersion() != km.dynamicVersion {
		km.dynamicVersion = km.config.GetDynamicVersion()
		newStore := store.NewStore[crypto.ManagedKey]()
		km.keyStore = &newStore
		if km.serverKey != nil {
			km.addManagedKey(km.serverKey)
		}
		for _, client := range km.config.GetClients() {
			if clientKeyError := km.addClientKey(client); clientKeyError != nil {
				log.Error("Private key for client %s could not be loaded: %v", client.Id, clientKeyError)
			}
		}
	}

	keyStore := *km.keyStore
	return keyStore.GetValues()
}

// addSeverKey loads the private key of the server, which is used for all clients without an own private key.
// When no private key is configured, an ephemeral ECDSA P-256 key is generated,
// so tokens are never signed with the server secret and can always be verified with a key from the JWKS endpoint.
func (km *Manger) addSeverKey(c *config.Config) error {
	var privateKey *crypto.SigningPrivateKey
	if c.Server.PrivateKey != "" {
		loadedPrivateKey, loadError := crypto.LoadPrivateKey(c.Server.PrivateKey)
		if loadError != nil {
			return loadError
		}
		privateKey = loadedPrivateKey
	} else {
		generatedPrivateKey, generateError := crypto.GeneratePrivateKey()
		if generateError != nil {
			return generateError
		}
		log.Warn("No server private key configured, generated an ephemeral key which changes on every restart, configure server.privateKey for production")
		privateKey = generatedPrivateKey
	}

	managedKey, convertError := km.convert(privateKey)
	if convertError != nil {
		return convertError
	}

	managedKey.Server = true
	km.serverKey = managedKey
	km.addManagedKey(managedKey)

	return nil
}

// GetSigningAlgorithms returns the distinct signature algorithms of all currently loaded keys.
func (km *Manger) GetSigningAlgorithms() []jwa.SignatureAlgorithm {
	var signingAlgorithms []jwa.SignatureAlgorithm
	for _, managedKey := range km.GetAllKeys() {
		currentKey := *managedKey.Key
		algorithm, algorithmExists := currentKey.Algorithm()
		if !algorithmExists {
			continue
		}
		signatureAlgorithm, isSignatureAlgorithm := algorithm.(jwa.SignatureAlgorithm)
		if isSignatureAlgorithm && !slices.Contains(signingAlgorithms, signatureAlgorithm) {
			signingAlgorithms = append(signingAlgorithms, signatureAlgorithm)
		}
	}
	slices.SortFunc(signingAlgorithms, func(a jwa.SignatureAlgorithm, b jwa.SignatureAlgorithm) int {
		return strings.Compare(a.String(), b.String())
	})
	return signingAlgorithms
}

func (km *Manger) addClientKey(client *config.Client) error {
	if client.PrivateKey != "" {
		signingPrivateKey, loadError := crypto.LoadPrivateKey(client.PrivateKey)
		if loadError != nil {
			return loadError
		}
		managedKey, convertError := km.convert(signingPrivateKey)
		if convertError != nil {
			return convertError
		}

		managedKey.Clients = []*config.Client{client}
		km.addManagedKey(managedKey)
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

	key, jwkError := jwk.Import[jwk.Key](signingPrivateKey.PrivateKey)
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
