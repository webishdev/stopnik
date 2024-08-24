package validation

import (
	"github.com/webishdev/stopnik/internal/config"
	"github.com/webishdev/stopnik/internal/crypto"
	"github.com/webishdev/stopnik/internal/oauth2"
	"github.com/webishdev/stopnik/log"
	"net/http"
)

type RequestValidator struct {
	config *config.Config
}

func NewRequestValidator(config *config.Config) *RequestValidator {
	return &RequestValidator{config: config}
}

func (validator *RequestValidator) ValidateFormLogin(r *http.Request) (*config.User, bool) {
	if r.Method == http.MethodPost {
		log.Debug("Validating user credentials")

		username := r.PostFormValue("stopnik_username")
		password := r.PostFormValue("stopnik_password")

		if username == "" || password == "" {
			return nil, false
		}

		// When login invalid
		// https://en.wikipedia.org/wiki/Post/Redirect/Get
		// redirect with Status 303
		// When login valid
		user, exists := validator.config.GetUser(username)
		if !exists {
			return nil, false
		}

		passwordHash := crypto.Sha512SaltedHash(password, user.Salt)

		if passwordHash != user.Password {
			return nil, false
		}

		return user, true
	}
	return nil, false
}

func (validator *RequestValidator) ValidateClientCredentials(r *http.Request) (*config.Client, bool, bool) {
	if r.Method == http.MethodPost {
		log.Debug("Validating client credentials")
		// https://datatracker.ietf.org/doc/html/rfc6749#section-2.3.1
		clientId, clientSecret, ok := r.BasicAuth()
		usingFallback := false
		if !ok {
			// Check usingFallback
			log.Warn("Invalid or missing HTTP Basic authentication, using NOT RECOMMENDED usingFallback")
			clientId = r.PostFormValue(oauth2.ParameterClientId)
			clientSecret = r.PostFormValue(oauth2.ParameterClientSecret)
			usingFallback = true
		}

		if clientId == "" || clientSecret == "" {
			return nil, usingFallback, false
		}

		client, clientExists := validator.ValidateClientId(clientId)
		if !clientExists {
			return nil, usingFallback, false
		}

		if !client.PasswordFallbackAllowed && usingFallback {
			log.Warn("Client password usingFallback denied in configuration for client with id %v", client.Id)
			return nil, usingFallback, false
		}

		secretHash := crypto.Sha512SaltedHash(clientSecret, client.Salt)

		if secretHash != client.Secret {
			return nil, usingFallback, false
		}

		return client, usingFallback, true
	}
	return nil, false, false
}

func (validator *RequestValidator) ValidateClientId(clientId string) (*config.Client, bool) {
	return validator.config.GetClient(clientId)
}

func (validator *RequestValidator) ValidateUserPassword(username string, password string) (*config.User, bool) {
	user, exists := validator.config.GetUser(username)
	if !exists {
		return nil, false
	}
	passwordHash := crypto.Sha512Hash(password)
	if passwordHash != user.Password {
		return nil, false
	}

	return user, true
}
