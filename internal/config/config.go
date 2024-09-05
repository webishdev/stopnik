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
	"regexp"
	"strings"
	"sync"
)

type Keys struct {
	Cert string `yaml:"cert"`
	Key  string `yaml:"key"`
}

type TLS struct {
	Addr string `yaml:"addr"`
	Keys Keys   `yaml:"keys"`
}

type Cookies struct {
	AuthName    string `yaml:"authName"`
	MessageName string `yaml:"messageName"`
}

type ForwardAuth struct {
	Endpoint      string `yaml:"endpoint"`
	ExternalUrl   string `yaml:"externalUrl"`
	ParameterName string `yaml:"parameterName"`
}

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

type UserAddress struct {
	Formatted  string `json:"formatted,omitempty"`
	Street     string `yaml:"street" json:"street_address,omitempty"`
	City       string `yaml:"city" json:"locality,omitempty"`
	PostalCode string `yaml:"postalCode" json:"postal_code,omitempty"`
	Region     string `yaml:"region" json:"region,omitempty"`
	Country    string `yaml:"country" json:"country,omitempty"`
}

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

type User struct {
	Username string              `yaml:"username"`
	Password string              `yaml:"password"`
	Salt     string              `yaml:"salt"`
	Profile  UserProfile         `yaml:"profile"`
	Roles    map[string][]string `yaml:"roles"`
}

type Claim struct {
	Name  string `yaml:"name"`
	Value string `yaml:"value"`
}

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

type UI struct {
	HideFooter      bool   `yaml:"hideFooter"`
	HideLogo        bool   `yaml:"hideLogo"`
	Title           string `yaml:"title"`
	FooterText      string `yaml:"footerText"`
	LogoImage       string `yaml:"logoImage"`
	LogoContentType string `yaml:"logoContentType"`
}

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

func GetConfigInstance() *Config {
	configLock.Lock()
	defer configLock.Unlock()
	if configSingleton == nil {
		system.CriticalError(errors.New("config not initialized"))
	}

	return configSingleton
}

func Initialize(config *Config) error {
	configLock.Lock()
	defer configLock.Unlock()
	for userIndex, user := range config.Users {
		if user.Username == "" || len(user.Password) != 128 {
			invalidUser := fmt.Sprintf("User configuration invalid. User %d %v", userIndex, user)
			return errors.New(invalidUser)
		}
	}

	for clientIndex, client := range config.Clients {
		if client.Id == "" {
			invalidClient := fmt.Sprintf("Client configuration invalid. Client %d is missing an client id, %v", clientIndex, client)
			return errors.New(invalidClient)
		}

		if client.GetClientType() == oauth2.CtConfidential && len(client.ClientSecret) != 128 {
			invalidClient := fmt.Sprintf("Client configuration invalid. Confidential client %d with id %s missing client secret, %v", clientIndex, client.Id, client)
			return errors.New(invalidClient)
		}

		if len(client.Redirects) == 0 {
			invalidClient := fmt.Sprintf("Client is missing redirects. Client %d with id %s, %v", clientIndex, client.Id, client)
			return errors.New(invalidClient)
		}

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

	if config.Server.ForwardAuth.Endpoint != "" {
		config.forwardAuthClient = &Client{
			Id:            uuid.NewString(),
			isForwardAuth: true,
		}
	}

	configSingleton = config

	return nil
}

func (config *Config) GetUser(name string) (*User, bool) {
	value, exists := config.userMap[name]
	return value, exists
}

func (config *Config) GetClient(name string) (*Client, bool) {
	value, exists := config.clientMap[name]
	if !exists && config.forwardAuthClient != nil {
		return config.forwardAuthClient, true
	}
	return value, exists
}

func (config *Config) GetAuthCookieName() string {
	return GetOrDefaultString(config.Server.Cookies.AuthName, "stopnik_auth")
}

func (config *Config) GetMessageCookieName() string {
	return GetOrDefaultString(config.Server.Cookies.MessageName, "stopnik_message")
}

func (config *Config) GetSessionTimeoutSeconds() int {
	return GetOrDefaultInt(config.Server.SessionTimeoutSeconds, 3600)
}

func (config *Config) GetIntrospectScope() string {
	return GetOrDefaultString(config.Server.IntrospectScope, "stopnik:introspect")
}

func (config *Config) GetRevokeScope() string {
	return GetOrDefaultString(config.Server.RevokeScope, "stopnik:revoke")
}

func (config *Config) GetServerSecret() string {
	return GetOrDefaultString(config.Server.Secret, config.generatedSecret)
}

func (config *Config) GetHideFooter() bool {
	return config.UI.HideFooter
}

func (config *Config) GetHideMascot() bool {
	return config.UI.HideLogo
}

func (config *Config) GetTitle() string {
	return config.UI.Title
}

func (config *Config) GetFooterText() string {
	return GetOrDefaultString(config.UI.FooterText, "STOPnik")
}

func (config *Config) GetLogoImage() *[]byte {
	return config.logoImage
}

func (config *Config) GetOidc() bool {
	return config.oidc
}

func (config *Config) GetIssuer(requestData *internalHttp.RequestData) string {
	if requestData == nil || requestData.Host == "" || requestData.Scheme == "" {
		return GetOrDefaultString(config.Server.Issuer, "STOPnik")
	}
	return GetOrDefaultString(config.Server.Issuer, requestData.IssuerString())
}

func (config *Config) GetForwardAuthEnabled() bool {
	return config.Server.ForwardAuth.ExternalUrl != ""
}

func (config *Config) GetForwardAuthEndpoint() string {
	return GetOrDefaultString(config.Server.ForwardAuth.Endpoint, "/forward")
}

func (config *Config) GetForwardAuthParameterName() string {
	return GetOrDefaultString(config.Server.ForwardAuth.ParameterName, "forward_id")
}

func (client *Client) GetRolesClaim() string {
	return GetOrDefaultString(client.RolesClaim, "roles")
}

func (client *Client) GetAccessTTL() int {
	return GetOrDefaultInt(client.AccessTTL, 5)
}

func (client *Client) GetRefreshTTL() int {
	return GetOrDefaultInt(client.RefreshTTL, 0)
}

func (client *Client) GetIdTTL() int {
	return GetOrDefaultInt(client.IdTTL, 0)
}

func (client *Client) GetAudience() []string {
	return GetOrDefaultStringSlice(client.Audience, []string{"all"})
}

func (client *Client) GetClientType() oauth2.ClientType {
	if client.ClientSecret == "" {
		return oauth2.CtPublic
	} else {
		return oauth2.CtConfidential
	}
}

func (client *Client) ValidateRedirect(redirect string) (bool, error) {
	if client.isForwardAuth {
		return true, nil
	}
	return validateRedirect(client.Id, client.Redirects, redirect)
}

func (user *User) GetPreferredUsername() string {
	if user.Profile.PreferredUserName == "" {
		return user.Username
	} else {
		return user.Profile.PreferredUserName
	}
}

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

func (user *User) GetRoles(clientId string) []string {
	return user.Roles[clientId]
}

func validateRedirect(clientId string, redirects []string, redirect string) (bool, error) {
	if redirect == "" {
		log.Error("Redirect provided for client %s was empty", clientId)
		return false, nil
	}

	redirectCount := len(redirects)

	if redirectCount > 0 {
		matchesRedirect := false
		for redirectIndex := range redirectCount {
			clientRedirect := redirects[redirectIndex]
			clientRedirect = strings.Replace(clientRedirect, "/", "\\/", 1)
			clientRedirect = strings.Replace(clientRedirect, ".", "\\.", 1)
			clientRedirect = strings.Replace(clientRedirect, "?", "\\?", 1)
			endsWithWildcard := strings.HasSuffix(clientRedirect, "*")
			if endsWithWildcard {
				clientRedirect = strings.Replace(clientRedirect[:len(clientRedirect)-1], "*", "\\*", 1)
				clientRedirect = clientRedirect + ".*"
			} else {
				clientRedirect = strings.Replace(clientRedirect, "*", "\\*", 1)
			}
			clientRedirect = fmt.Sprintf("^%s$", clientRedirect)
			matched, regexError := regexp.MatchString(clientRedirect, redirect)
			if regexError != nil {
				log.Error("Cloud not match redirect URI %s for client %s", redirect, clientId)
				return false, regexError
			}

			matchesRedirect = matchesRedirect || matched
		}

		return matchesRedirect, nil
	} else {
		log.Error("Client %s has no redirect URI(s) configured!", clientId)
		return false, nil
	}
}
