package config

import (
	"bufio"
	"errors"
	"fmt"
	"github.com/google/uuid"
	internalHttp "github.com/webishdev/stopnik/internal/http"
	"github.com/webishdev/stopnik/internal/oauth2"
	"github.com/webishdev/stopnik/internal/system"
	"github.com/webishdev/stopnik/log"
	"io"
	"os"
	"strings"
	"sync"
)

// Keys defines path to TSL certificate and key file.
type Keys struct {
	Cert string `yaml:"cert"`
	Key  string `yaml:"key"`
}

// TLS defines the Go like address to listen to and references the necessary Keys.
type TLS struct {
	Addr string `yaml:"addr"`
	Keys Keys   `yaml:"keys"`
}

// Cookies defines the name for HTTP cookies used by STOPnik.
type Cookies struct {
	AuthName    string `yaml:"authName"`
	MessageName string `yaml:"messageName"`
}

// ForwardAuth defines the configuration related to Traefik Forward Auth,
// only used when ExternalUrl is provided.
type ForwardAuth struct {
	Endpoint      string   `yaml:"endpoint"`
	ExternalUrl   string   `yaml:"externalUrl"`
	ParameterName string   `yaml:"parameterName"`
	Redirects     []string `yaml:"redirects"`
}

// Server defines the main STOPnik server configuration.
type Server struct {
	LogLevel              string      `yaml:"logLevel"`
	Addr                  string      `yaml:"addr"`
	Cookies               Cookies     `yaml:"cookies"`
	Secret                string      `yaml:"secret"`
	PrivateKey            string      `yaml:"privateKey"`
	TLS                   TLS         `yaml:"tls"`
	LogoutRedirect        string      `yaml:"logoutRedirect"`
	IntrospectScope       string      `yaml:"introspectScope"`
	RevokeScope           string      `yaml:"revokeScopeScope"`
	SessionTimeoutSeconds int         `yaml:"sessionTimeoutSeconds"`
	Issuer                string      `yaml:"issuer"`
	ForwardAuth           ForwardAuth `yaml:"forwardAuth"`
}

// UserAddress defines the address for a specific user,
// the definition provided in the YAML file will be mapped into values inside a JSON response.
type UserAddress struct {
	Formatted  string `json:"formatted,omitempty"`
	Street     string `yaml:"street" json:"street_address,omitempty"`
	City       string `yaml:"city" json:"locality,omitempty"`
	PostalCode string `yaml:"postalCode" json:"postal_code,omitempty"`
	Region     string `yaml:"region" json:"region,omitempty"`
	Country    string `yaml:"country" json:"country,omitempty"`
}

// UserProfile defines the profile for a specific user,
// the definition provided in the YAML file will be mapped into values inside a JSON response.
type UserProfile struct {
	Subject           string      `json:"sub,omitempty"`
	Name              string      `json:"name,omitempty"`
	GivenName         string      `yaml:"givenName" json:"given_name,omitempty"`
	FamilyName        string      `yaml:"familyName" json:"family_name,omitempty"`
	Nickname          string      `yaml:"nickname" json:"nickname,omitempty"`
	PreferredUserName string      `yaml:"preferredUserName" json:"preferred_username,omitempty"`
	Email             string      `yaml:"email" json:"email,omitempty"`
	EmailVerified     bool        `yaml:"emailVerified" json:"email_verified,omitempty"`
	Gender            string      `yaml:"gender" json:"gender,omitempty"`
	BirthDate         string      `yaml:"birthDate" json:"birth_date,omitempty"`
	ZoneInfo          string      `yaml:"zoneInfo" json:"zone_info,omitempty"`
	Locale            string      `yaml:"locale" json:"locale,omitempty"`
	PhoneNumber       string      `yaml:"phoneNumber" json:"phone_number,omitempty"`
	PhoneVerified     bool        `yaml:"phoneVerified" json:"phone_verified,omitempty"`
	Website           string      `yaml:"website" json:"website,omitempty"`
	Profile           string      `yaml:"profile" json:"profile,omitempty"`
	ProfilePicture    string      `yaml:"profilePicture" json:"profile_picture,omitempty"`
	Address           UserAddress `yaml:"address" json:"address,omitempty"`
	UpdatedAt         string      `json:"updated_at,omitempty"`
}

// User defines the general user entry in the configuration.
type User struct {
	Username string              `yaml:"username"`
	Password string              `yaml:"password"`
	Salt     string              `yaml:"salt"`
	Profile  UserProfile         `yaml:"profile"`
	Roles    map[string][]string `yaml:"roles"`
}

// Claim defines additional claims with name and value,
// used for a specific Client.
type Claim struct {
	Name  string `yaml:"name"`
	Value string `yaml:"value"`
}

// Client defines the general client entry in the configuration.
type Client struct {
	Id                      string   `yaml:"id"`
	ClientSecret            string   `yaml:"clientSecret"`
	Salt                    string   `yaml:"salt"`
	Oidc                    bool     `yaml:"oidc"`
	AccessTTL               int      `yaml:"accessTTL"`
	RefreshTTL              int      `yaml:"refreshTTL"`
	IdTTL                   int      `yaml:"idTTL"`
	Introspect              bool     `yaml:"introspect"`
	Revoke                  bool     `yaml:"revoke"`
	Redirects               []string `yaml:"redirects"`
	OpaqueToken             bool     `yaml:"opaqueToken"`
	PasswordFallbackAllowed bool     `yaml:"passwordFallbackAllowed"`
	Claims                  []Claim  `yaml:"claims"`
	Audience                []string `yaml:"audience"`
	PrivateKey              string   `yaml:"privateKey"`
	RolesClaim              string   `yaml:"rolesClaim"`
	isForwardAuth           bool
}

// UI defines the general web user interface entry in the configuration.
type UI struct {
	HideFooter                bool   `yaml:"hideFooter"`
	HideLogo                  bool   `yaml:"hideLogo"`
	Title                     string `yaml:"title"`
	FooterText                string `yaml:"footerText"`
	LogoImage                 string `yaml:"logoImage"`
	LogoContentType           string `yaml:"logoContentType"`
	InvalidCredentialsMessage string `yaml:"invalidCredentialsMessage"`
	ExpiredLoginMessage       string `yaml:"expiredLoginMessage"`
}

// Config defines the root entry for the configuration.
type Config struct {
	Server            Server   `yaml:"server"`
	Clients           []Client `yaml:"clients"`
	Users             []User   `yaml:"users"`
	UI                UI       `yaml:"ui"`
	generatedSecret   string
	userMap           map[string]*User
	clientMap         map[string]*Client
	oidc              bool
	logoImage         *[]byte
	forwardAuthClient *Client
}

var configLock = &sync.Mutex{}
var configSingleton *Config

// GetConfigInstance returns the current singleton of Config when it was initialized by Initialize before.
func GetConfigInstance() *Config {
	configLock.Lock()
	defer configLock.Unlock()
	if configSingleton == nil {
		system.CriticalError(errors.New("config not initialized"))
		return nil
	}

	return configSingleton
}

// Initialize initializes a given Config.
// Checks for OIDC configuration on given Client entries.
// Initializes maps for faster Client and User access in the Config.
// Generates a server secret when none was provided.
// Loads a logo image into []byte to use in the web user interface.
// Checks for ForwardAuth settings.
// Sets the singleton for the current Config
func Initialize(config *Config) error {
	configLock.Lock()
	defer configLock.Unlock()

	for _, client := range config.Clients {
		config.oidc = config.oidc || client.Oidc
	}

	config.userMap = setup[User](&config.Users, func(user User) string {
		return user.Username
	})

	config.clientMap = setup[Client](&config.Clients, func(client Client) string {
		return client.Id
	})

	randomString, randomError := generateRandomString(16)
	if randomError != nil {
		log.Error("Could not generate random secret: %v", randomError)
		return randomError
	}
	generatedSecret := randomString
	config.generatedSecret = generatedSecret

	if config.UI.LogoImage != "" {
		file, fileError := os.Open(config.UI.LogoImage)
		if fileError != nil {
			return fileError
		}
		defer func(file *os.File) {
			fileCloseError := file.Close()
			if fileCloseError != nil {
				system.CriticalError(fileCloseError)
			}
		}(file)

		stat, statError := file.Stat()
		if statError != nil {
			return statError
		}

		bs := make([]byte, stat.Size())
		_, bufferError := bufio.NewReader(file).Read(bs)
		if bufferError != nil && bufferError != io.EOF {
			return bufferError
		}

		log.Info("Own logo loaded from %s", config.UI.LogoImage)
		config.logoImage = &bs
	}

	if config.Server.ForwardAuth.ExternalUrl != "" {
		config.forwardAuthClient = &Client{
			Id:            uuid.NewString(),
			isForwardAuth: true,
			Redirects:     config.Server.ForwardAuth.Redirects,
		}
		log.Info("Forward auth client created")
	}

	configSingleton = config

	return nil
}

// Validate validates the current Config and returns an error when necessary values are missing.
func (config *Config) Validate() error {
	if config.Server.Addr == "" {
		return errors.New("no server address provided")
	}

	if config.Server.TLS.Addr != "" && config.Server.TLS.Keys.Key == "" {
		return errors.New("key for TLS is missing")
	}

	if config.Server.TLS.Addr != "" && config.Server.TLS.Keys.Cert == "" {
		return errors.New("certificate for TLS is missing")
	}

	if len(config.Users) == 0 {
		return errors.New("no users configured, add at least one user")
	}

	if len(config.Clients) == 0 {
		return errors.New("no clients configured, add at least one client")
	}

	for userIndex, user := range config.Users {
		if user.Username == "" {
			invalidUser := fmt.Sprintf("user configuration invalid for user %d, missing username %v", userIndex, user)
			return errors.New(invalidUser)
		}

		if len(user.Password) != 128 {
			invalidUser := fmt.Sprintf("user configuration invalid for user %d with username %s, missing password %v", userIndex, user.Username, user)
			return errors.New(invalidUser)
		}
	}

	for clientIndex, client := range config.Clients {
		if client.Id == "" {
			invalidClient := fmt.Sprintf("client configuration invalid for client %d, missing id %v", clientIndex, client)
			return errors.New(invalidClient)
		}

		if len(client.Redirects) == 0 {
			invalidClient := fmt.Sprintf("client configuration invalid, for client %d with id %s, missing redirects, %v", clientIndex, client.Id, client)
			return errors.New(invalidClient)
		}
	}

	return nil
}

// GetUser returns a User for the given username.
// Also returns a bool which indicates, whether the User exists or not.
func (config *Config) GetUser(username string) (*User, bool) {
	value, exists := config.userMap[username]
	return value, exists
}

// GetClient returns a Client for the given clientId.
// Also returns a bool which indicates, whether the Client exists or not.
func (config *Config) GetClient(clientId string) (*Client, bool) {
	value, exists := config.clientMap[clientId]
	if !exists && config.forwardAuthClient != nil && config.forwardAuthClient.Id == clientId {
		return config.forwardAuthClient, true
	}
	return value, exists
}

// GetAuthCookieName returns the name of the authentication cookie.
// When no name is provided a default value will be returned.
func (config *Config) GetAuthCookieName() string {
	return GetOrDefaultString(config.Server.Cookies.AuthName, "stopnik_auth")
}

// GetMessageCookieName returns the name of the message cookie.
// When no name is provided a default value will be returned.
func (config *Config) GetMessageCookieName() string {
	return GetOrDefaultString(config.Server.Cookies.MessageName, "stopnik_message")
}

// GetSessionTimeoutSeconds returns the session timeout in seconds.
// When no session timeout is provided a default value will be returned.
func (config *Config) GetSessionTimeoutSeconds() int {
	return GetOrDefaultInt(config.Server.SessionTimeoutSeconds, 3600)
}

// GetIntrospectScope returns the scope which can be used to introspect tokens.
// When no scope is provided a default value will be returned.
func (config *Config) GetIntrospectScope() string {
	return GetOrDefaultString(config.Server.IntrospectScope, "stopnik:introspect")
}

// GetRevokeScope returns the scope which can be used to revoke tokens.
// When no scope is provided a default value will be returned.
func (config *Config) GetRevokeScope() string {
	return GetOrDefaultString(config.Server.RevokeScope, "stopnik:revoke")
}

// GetServerSecret returns the server secret.
// When no secret is provided a previously generated value will be returned.
func (config *Config) GetServerSecret() string {
	return GetOrDefaultString(config.Server.Secret, config.generatedSecret)
}

// GetHideFooter returns whether the footer should be hidden in the web user interface.
func (config *Config) GetHideFooter() bool {
	return config.UI.HideFooter
}

// GetHideLogo returns whether the logo should be hidden in the web user interface.
func (config *Config) GetHideLogo() bool {
	return config.UI.HideLogo
}

// GetTitle returns whether the title shown in the web user interface.
func (config *Config) GetTitle() string {
	return config.UI.Title
}

// GetFooterText returns whether the text shown in the footer of the web user interface.
// When no footer text is provided a default value will be returned.
func (config *Config) GetFooterText() string {
	return GetOrDefaultString(config.UI.FooterText, "STOPnik")
}

// GetLogoImage returns a pointer to the loaded logo image. Can be nil if no image was provided.
func (config *Config) GetLogoImage() *[]byte {
	return config.logoImage
}

// GetInvalidCredentialsMessage returns the configured invalid credentials message.
// When no invalid credentials message is provided a default value will be returned.
func (config *Config) GetInvalidCredentialsMessage() string {
	return GetOrDefaultString(config.UI.InvalidCredentialsMessage, "Invalid credentials")
}

// GetExpiredLoginMessage returns the configured login expired message.
// When no login expired message is provided a default value will be returned.
func (config *Config) GetExpiredLoginMessage() string {
	return GetOrDefaultString(config.UI.ExpiredLoginMessage, "Login expired, try again")
}

// GetOidc returns whether one of the existing clients has OIDC flag set or not.
func (config *Config) GetOidc() bool {
	return config.oidc
}

// GetIssuer returns the issuer, either by mirroring from request, from Server configuration or default value.
func (config *Config) GetIssuer(requestData *internalHttp.RequestData) string {
	if requestData == nil || requestData.Host == "" || requestData.Scheme == "" {
		return GetOrDefaultString(config.Server.Issuer, "STOPnik")
	}
	return GetOrDefaultString(config.Server.Issuer, requestData.IssuerString())
}

// GetForwardAuthEnabled returns whether Traefik Forward Auth is enabled or not.
// Check in general whether the ForwardAuth ExternalUrl value is set.
func (config *Config) GetForwardAuthEnabled() bool {
	return config.Server.ForwardAuth.ExternalUrl != ""
}

// GetForwardAuthEndpoint returns the endpoint which will use used for Traefik Forward Auth.
// When no endpoint is provided a default value will be returned.
func (config *Config) GetForwardAuthEndpoint() string {
	return GetOrDefaultString(config.Server.ForwardAuth.Endpoint, "/forward")
}

// GetForwardAuthParameterName returns the query parameter name which will use used for Traefik Forward Auth.
// When no query parameter name is provided a default value will be returned.
func (config *Config) GetForwardAuthParameterName() string {
	return GetOrDefaultString(config.Server.ForwardAuth.ParameterName, "forward_id")
}

// GetForwardAuthClient return a Client used for Traefik Forward Auth,
// also returns a bool indicating whether such a Client exists or not.
func (config *Config) GetForwardAuthClient() (*Client, bool) {
	if config.forwardAuthClient != nil && config.forwardAuthClient.Id != "" {
		return config.forwardAuthClient, true
	}
	return nil, false
}

// GetRolesClaim returns the name of the claim uses to provide User roles in a Client.
// When no name is provided a default value will be returned.
func (client *Client) GetRolesClaim() string {
	return GetOrDefaultString(client.RolesClaim, "roles")
}

// GetAccessTTL returns access token time to live.
// When no time to live is provided a default value will be returned.
func (client *Client) GetAccessTTL() int {
	return GetOrDefaultInt(client.AccessTTL, 5)
}

// GetRefreshTTL returns refresh token time to live.
// When no time to live is provided a default value will be returned.
func (client *Client) GetRefreshTTL() int {
	return GetOrDefaultInt(client.RefreshTTL, 0)
}

// GetIdTTL returns id token time to live.
// When no time to live is provided a default value will be returned.
func (client *Client) GetIdTTL() int {
	return GetOrDefaultInt(client.IdTTL, 0)
}

// GetAudience returns the audience value.
// When no audience value is provided a default value will be returned.
func (client *Client) GetAudience() []string {
	return GetOrDefaultStringSlice(client.Audience, []string{"all"})
}

// GetClientType returns the client type value.
// When no client secret is provided the client will be a public client, confidential otherwise.
// See oauth2.ClientType
func (client *Client) GetClientType() oauth2.ClientType {
	if client.ClientSecret == "" {
		return oauth2.CtPublic
	} else {
		return oauth2.CtConfidential
	}
}

// ValidateRedirect return whether the redirect is valid for a given Client or not.
func (client *Client) ValidateRedirect(redirect string) bool {
	return validateRedirect(client.Id, client.Redirects, redirect)
}

// GetPreferredUsername returns the preferred username for a given User, or just the username.
func (user *User) GetPreferredUsername() string {
	if user.Profile.PreferredUserName == "" {
		return user.Username
	} else {
		return user.Profile.PreferredUserName
	}
}

// GetFormattedAddress return the formatted address for a User.
func (user *User) GetFormattedAddress() string {
	userAddress := user.Profile.Address
	var sb strings.Builder
	if userAddress.Street != "" {
		sb.WriteString(userAddress.Street)
		sb.WriteString("\n")
	}
	if userAddress.PostalCode != "" {
		sb.WriteString(userAddress.PostalCode)
		sb.WriteString("\n")
	}
	if userAddress.City != "" {
		sb.WriteString(userAddress.City)
		sb.WriteString("\n")
	}
	return sb.String()
}

// GetRoles returns the roles configured for the User for a given clientId.
func (user *User) GetRoles(clientId string) []string {
	return user.Roles[clientId]
}

func validateRedirect(clientId string, redirects []string, redirect string) bool {
	if redirect == "" {
		log.Error("Redirect provided for client %s was empty", clientId)
		return false
	}

	redirectCount := len(redirects)

	if redirectCount > 0 {
		matchesRedirect := false
		for redirectIndex := range redirectCount {
			clientRedirect := redirects[redirectIndex]
			endsWithWildcard := strings.HasSuffix(clientRedirect, "*")
			var matched bool
			if endsWithWildcard {
				clientRedirect = clientRedirect[:len(clientRedirect)-1]
				matched = strings.HasPrefix(redirect, clientRedirect)
			} else {
				matched = redirect == clientRedirect
			}
			matchesRedirect = matchesRedirect || matched
		}

		return matchesRedirect
	} else {
		log.Error("Client %s has no redirect URI(s) configured!", clientId)
		return false
	}
}
