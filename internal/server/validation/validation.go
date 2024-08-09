package validation

import (
	"net/http"
	"stopnik/internal/config"
	"stopnik/internal/crypto"
	"stopnik/internal/oauth2"
	"stopnik/log"
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

		passwordHash := crypto.Sha512Hash(password)
		if passwordHash != user.Password {
			return nil, false
		}

		return user, true
	}
	return nil, false
}

func (validator *RequestValidator) ValidateClientCredentials(r *http.Request) (*config.Client, bool) {
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
			return nil, false
		}

		client, clientExists := validator.ValidateClientId(clientId)
		if !clientExists {
			return nil, false
		}

		if !client.PasswordFallbackAllowed && usingFallback {
			log.Warn("Client password usingFallback denied in configuration for client with id %v", client.Id)
			return nil, false
		}

		secretHash := crypto.Sha512Hash(clientSecret)

		if secretHash != client.Secret {
			return nil, false
		}

		return client, true
	}
	return nil, false
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
