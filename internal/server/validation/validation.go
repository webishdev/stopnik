package validation

import (
	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/webishdev/stopnik/internal/config"
	"github.com/webishdev/stopnik/internal/crypto"
	"github.com/webishdev/stopnik/internal/oauth2"
	"github.com/webishdev/stopnik/internal/system"
	"github.com/webishdev/stopnik/log"
	"net/http"
	"time"
)

type RequestValidator struct {
	config             *config.Config
	serverSecretLoader crypto.ServerSecretLoader
}

func NewRequestValidator() *RequestValidator {
	currentConfig := config.GetConfigInstance()
	return &RequestValidator{
		config:             currentConfig,
		serverSecretLoader: crypto.NewServerSecretLoader(),
	}
}

func (validator *RequestValidator) NewLoginToken(id string) string {
	duration := time.Minute * time.Duration(5)
	tokenId := uuid.NewString()
	builder := jwt.NewBuilder().
		JwtID(tokenId).
		Subject(id).
		Expiration(time.Now().Add(duration)).
		IssuedAt(time.Now())

	token, tokenError := builder.Build()
	if tokenError != nil {
		system.Error(tokenError)
	}
	options := validator.serverSecretLoader.GetServerKey()
	tokenString, tokenError := jwt.Sign(token, options)
	if tokenError != nil {
		system.Error(tokenError)
	}

	return string(tokenString)
}

func (validator *RequestValidator) GetLoginToken(loginToken string) (jwt.Token, error) {
	options := validator.serverSecretLoader.GetServerKey()
	token, tokenError := jwt.Parse([]byte(loginToken), options)
	if tokenError != nil {
		return nil, tokenError
	}
	return token, nil
}

func (validator *RequestValidator) ValidateFormLogin(r *http.Request) (*config.User, *string) {
	if r.Method == http.MethodPost {
		log.Debug("Validating user credentials")

		username := r.PostFormValue("stopnik_username")
		password := r.PostFormValue("stopnik_password")
		loginToken := r.PostFormValue("stopnik_auth_session")

		if username == "" || password == "" || loginToken == "" {
			loginError := validator.config.GetInvalidCredentialsMessage()
			return nil, &loginError
		}

		_, tokenError := validator.GetLoginToken(loginToken)
		if tokenError != nil {
			loginError := validator.config.GetExpiredLoginMessage()
			return nil, &loginError
		}

		// When login invalid
		// https://en.wikipedia.org/wiki/Post/Redirect/Get
		// redirect with Status 303
		// When login valid
		user, exists := validator.config.GetUser(username)
		if !exists {
			loginError := validator.config.GetInvalidCredentialsMessage()
			return nil, &loginError
		}

		passwordHash := crypto.Sha512SaltedHash(password, user.Salt)

		if passwordHash != user.Password {
			loginError := validator.config.GetInvalidCredentialsMessage()
			return nil, &loginError
		}

		return user, nil
	}
	loginError := validator.config.GetInvalidCredentialsMessage()
	return nil, &loginError
}

func (validator *RequestValidator) ValidateClientCredentials(r *http.Request) (*config.Client, bool, bool) {
	if r.Method == http.MethodPost {
		log.Debug("Validating client credentials")
		// https://datatracker.ietf.org/doc/html/rfc6749#section-2.3.1
		clientId, clientSecret, ok := r.BasicAuth()
		usingFallback := false
		if !ok {
			// Check usingFallback
			clientId = r.PostFormValue(oauth2.ParameterClientId)
			clientSecret = r.PostFormValue(oauth2.ParameterClientSecret)
			if clientId != "" {
				log.Warn("Invalid or missing HTTP Basic authentication, using NOT RECOMMENDED POST from values")
				usingFallback = true
			}
		}

		if clientId == "" {
			return nil, usingFallback, false
		}

		client, clientExists := validator.ValidateClientId(clientId)
		if !clientExists {
			return nil, usingFallback, false
		}

		if client.GetClientType() == oauth2.CtPublic && clientSecret == "" {
			return client, usingFallback, true
		} else if client.GetClientType() == oauth2.CtPublic && clientSecret != "" {
			return nil, usingFallback, false
		}

		if !client.PasswordFallbackAllowed && usingFallback {
			log.Warn("Client password usingFallback denied in configuration for client with id %v", client.Id)
			return nil, usingFallback, false
		}

		secretHash := crypto.Sha512SaltedHash(clientSecret, client.Salt)

		if secretHash != client.ClientSecret {
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
	passwordHash := crypto.Sha512SaltedHash(password, user.Salt)
	if passwordHash != user.Password {
		return nil, false
	}

	return user, true
}
