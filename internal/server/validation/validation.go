package validation

import (
	"github.com/lestrrat-go/jwx/v4/jwt"
	"github.com/webishdev/stopnik/internal/config"
	"github.com/webishdev/stopnik/internal/crypto"
	"github.com/webishdev/stopnik/internal/oauth2"
	"github.com/webishdev/stopnik/internal/system"
	"github.com/webishdev/stopnik/log"
	"net/http"
	"time"
	"uuid"
)

type now func() time.Time

// crossOriginProtection detects cross-origin form submissions via Sec-Fetch-Site and Origin headers.
var crossOriginProtection = http.NewCrossOriginProtection()

// ValidateSameOrigin returns whether a request was not sent cross-origin.
// Used for login and logout forms, to prevent other sites from logging users in or out (login CSRF).
func ValidateSameOrigin(r *http.Request) bool {
	checkError := crossOriginProtection.Check(r)
	if checkError != nil {
		log.Warn("Rejected cross-origin request: %v", checkError)
		return false
	}
	return true
}

// verifySecret checks passwords and client secrets against their configured hash.
var verifySecret = crypto.VerifySecret

type RequestValidator struct {
	config             *config.Config
	now                now
	serverSecretLoader crypto.ServerSecretLoader
}

func NewRequestValidator() *RequestValidator {
	return newRequestValidator(time.Now)
}

func newRequestValidator(now now) *RequestValidator {
	currentConfig := config.GetConfigInstance()
	return &RequestValidator{
		config:             currentConfig,
		now:                now,
		serverSecretLoader: crypto.NewPurposeServerSecretLoader(crypto.PurposeLoginToken),
	}
}

func (validator *RequestValidator) NewLoginToken(id string) string {
	duration := time.Minute * time.Duration(5)
	tokenId := uuid.New().String()
	builder := jwt.NewBuilder().
		JwtID(tokenId).
		Subject(id).
		Expiration(validator.now().Add(duration)).
		IssuedAt(validator.now())

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
			log.AccessLogInvalidLogin(r, "Account login failed: %s", loginError)
			return nil, &loginError
		}

		_, tokenError := validator.GetLoginToken(loginToken)
		if tokenError != nil {
			loginError := validator.config.GetExpiredLoginMessage()
			log.AccessLogInvalidLogin(r, "Account login failed: %s", loginError)
			return nil, &loginError
		}

		// When login invalid
		// https://en.wikipedia.org/wiki/Post/Redirect/Get
		// redirect with Status 303
		// When login valid
		user, valid := validator.ValidateUserPassword(username, password)
		if !valid {
			loginError := validator.config.GetInvalidCredentialsMessage()
			log.AccessLogInvalidLogin(r, "Account login failed for user %s: %s", username, loginError)
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

		limiterKey := "client:" + clientId
		if credentialLimiter.blocked(limiterKey) {
			log.Warn("Too many failed attempts for client with id %s, client is blocked temporarily", clientId)
			return nil, usingFallback, false
		}

		client, clientExists := validator.ValidateClientId(clientId)
		if !clientExists {
			// Verify anyway, so timing does not reveal whether the client exists
			verifySecret(clientSecret, "", "")
			credentialLimiter.failed(limiterKey)
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

		if !verifySecret(clientSecret, client.Salt, client.ClientSecret) {
			credentialLimiter.failed(limiterKey)
			return nil, usingFallback, false
		}

		credentialLimiter.succeeded(limiterKey)
		return client, usingFallback, true
	}
	return nil, false, false
}

func (validator *RequestValidator) ValidateClientId(clientId string) (*config.Client, bool) {
	return validator.config.GetClient(clientId)
}

func (validator *RequestValidator) ValidateUserPassword(username string, password string) (*config.User, bool) {
	limiterKey := "user:" + username
	if credentialLimiter.blocked(limiterKey) {
		log.Warn("Too many failed login attempts for user %s, user is blocked temporarily", username)
		return nil, false
	}

	user, exists := validator.config.GetUser(username)
	if !exists {
		// Verify anyway, so timing does not reveal whether the user exists
		verifySecret(password, "", "")
		credentialLimiter.failed(limiterKey)
		return nil, false
	}
	if !verifySecret(password, user.Salt, user.Password) {
		credentialLimiter.failed(limiterKey)
		return nil, false
	}

	credentialLimiter.succeeded(limiterKey)
	return user, true
}
