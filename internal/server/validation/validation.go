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

		username := r.PostFormValue("stopnik_username")
		password := r.PostFormValue("stopnik_password")

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
	log.Debug("Validating client credentials")
	// https://datatracker.ietf.org/doc/html/rfc6749#section-2.3.1
	clientId, clientSecret, ok := r.BasicAuth()
	if !ok {
		// Check fallback
		clientId = r.PostFormValue(oauth2.ParameterClientId)
		clientSecret = r.PostFormValue(oauth2.ParameterClientSecret)
	}

	if clientId == "" || clientSecret == "" {
		return nil, false
	}

	client, clientExists := validator.config.GetClient(clientId)
	if !clientExists {
		return nil, false
	}

	secretHash := crypto.Sha512Hash(clientSecret)

	if secretHash != client.Secret {
		return nil, false
	}

	return client, true
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
