package admin

import (
	"bytes"
	"fmt"
	"net/url"
	"reflect"
	"slices"
	"strconv"
	"strings"

	"github.com/BurntSushi/toml"
	"github.com/webishdev/stopnik/internal/oauth2"
)

// GrantTypes lists the grant types selectable for a client.
var GrantTypes = []oauth2.GrantType{
	oauth2.GtAuthorizationCode,
	oauth2.GtClientCredentials,
	oauth2.GtPassword,
	oauth2.GtRefreshToken,
	oauth2.GtImplicit,
}

// document is the form model of a dynamic configuration file.
// The documents mirror the TOML keys of the config package, but omit empty values when encoded.
type document interface {
	// key returns the unique key of the entry, used to derive a file name.
	key() string
	// applyForm overwrites the document with the submitted form values, secrets are handled by setSecret.
	applyForm(values url.Values) error
	// setSecret sets an already hashed secret, does nothing for documents without secrets.
	setSecret(hash string)
}

type clientDocument struct {
	Id                      string   `toml:"id"`
	ClientSecret            string   `toml:"clientSecret,omitempty"`
	Salt                    string   `toml:"salt,omitempty"`
	Oidc                    bool     `toml:"oidc,omitempty"`
	AccessTTL               int      `toml:"accessTTL,omitempty"`
	RefreshTTL              int      `toml:"refreshTTL,omitempty"`
	IdTTL                   int      `toml:"idTTL,omitempty"`
	Introspect              bool     `toml:"introspect,omitempty"`
	Revoke                  bool     `toml:"revoke,omitempty"`
	OpaqueToken             bool     `toml:"opaqueToken,omitempty"`
	PasswordFallbackAllowed bool     `toml:"passwordFallbackAllowed,omitempty"`
	PrivateKey              string   `toml:"privateKey,omitempty"`
	Redirects               []string `toml:"redirects,omitempty"`
	Audience                []string `toml:"audience,omitempty"`
	Scopes                  []string `toml:"scopes,omitempty"`
	GrantTypes              []string `toml:"grantTypes,omitempty"`
}

func (doc *clientDocument) key() string {
	return doc.Id
}

func (doc *clientDocument) applyForm(values url.Values) error {
	var ttlErrors []error
	ttl := func(name string) int {
		value, ttlError := formInt(values, name)
		if ttlError != nil {
			ttlErrors = append(ttlErrors, ttlError)
		}
		return value
	}

	doc.Id = strings.TrimSpace(values.Get("id"))
	doc.Oidc = formBool(values, "oidc")
	doc.AccessTTL = ttl("accessTTL")
	doc.RefreshTTL = ttl("refreshTTL")
	doc.IdTTL = ttl("idTTL")
	doc.Introspect = formBool(values, "introspect")
	doc.Revoke = formBool(values, "revoke")
	doc.OpaqueToken = formBool(values, "opaqueToken")
	doc.PasswordFallbackAllowed = formBool(values, "passwordFallbackAllowed")
	doc.PrivateKey = strings.TrimSpace(values.Get("privateKey"))
	doc.Redirects = formLines(values, "redirects")
	doc.Audience = formLines(values, "audience")
	doc.Scopes = formLines(values, "scopes")
	doc.GrantTypes = nil
	for _, grantType := range values["grantTypes"] {
		if grantType != "" {
			doc.GrantTypes = append(doc.GrantTypes, grantType)
		}
	}

	if len(ttlErrors) > 0 {
		return ttlErrors[0]
	}
	return nil
}

func (doc *clientDocument) setSecret(hash string) {
	doc.ClientSecret = hash
	doc.Salt = ""
}

// HasGrantType returns whether the given grant type is selected, used by the template.
func (doc *clientDocument) HasGrantType(grantType oauth2.GrantType) bool {
	return slices.Contains(doc.GrantTypes, string(grantType))
}

type userAddressDocument struct {
	Street     string `toml:"street,omitempty"`
	City       string `toml:"city,omitempty"`
	PostalCode string `toml:"postalCode,omitempty"`
	Region     string `toml:"region,omitempty"`
	Country    string `toml:"country,omitempty"`
}

type userProfileDocument struct {
	GivenName         string `toml:"givenName,omitempty"`
	MiddleName        string `toml:"middleName,omitempty"`
	FamilyName        string `toml:"familyName,omitempty"`
	Nickname          string `toml:"nickname,omitempty"`
	PreferredUserName string `toml:"preferredUserName,omitempty"`
	Gender            string `toml:"gender,omitempty"`
	BirthDate         string `toml:"birthDate,omitempty"`
	ZoneInfo          string `toml:"zoneInfo,omitempty"`
	Locale            string `toml:"locale,omitempty"`
	Website           string `toml:"website,omitempty"`
	Profile           string `toml:"profile,omitempty"`
	Picture           string `toml:"picture,omitempty"`
}

type userInformationDocument struct {
	Email         string               `toml:"email,omitempty"`
	EmailVerified bool                 `toml:"emailVerified,omitempty"`
	PhoneNumber   string               `toml:"phoneNumber,omitempty"`
	PhoneVerified bool                 `toml:"phoneNumberVerified,omitempty"`
	Address       *userAddressDocument `toml:"address,omitempty"`
}

type userDocument struct {
	Username        string                  `toml:"username"`
	Password        string                  `toml:"password,omitempty"`
	Salt            string                  `toml:"salt,omitempty"`
	Admin           bool                    `toml:"admin,omitempty"`
	UserProfile     userProfileDocument     `toml:"userProfile,omitempty"`
	UserInformation userInformationDocument `toml:"userInformation,omitempty"`
}

func (doc *userDocument) key() string {
	return doc.Username
}

func (doc *userDocument) applyForm(values url.Values) error {
	field := func(name string) string {
		return strings.TrimSpace(values.Get(name))
	}

	doc.Username = field("username")
	doc.Admin = formBool(values, "admin")
	doc.UserProfile = userProfileDocument{
		GivenName:         field("givenName"),
		MiddleName:        field("middleName"),
		FamilyName:        field("familyName"),
		Nickname:          field("nickname"),
		PreferredUserName: field("preferredUserName"),
		Gender:            field("gender"),
		BirthDate:         field("birthDate"),
		ZoneInfo:          field("zoneInfo"),
		Locale:            field("locale"),
		Website:           field("website"),
		Profile:           field("profile"),
		Picture:           field("picture"),
	}
	doc.UserInformation = userInformationDocument{
		Email:         field("email"),
		EmailVerified: formBool(values, "emailVerified"),
		PhoneNumber:   field("phoneNumber"),
		PhoneVerified: formBool(values, "phoneNumberVerified"),
	}
	address := userAddressDocument{
		Street:     field("street"),
		City:       field("city"),
		PostalCode: field("postalCode"),
		Region:     field("region"),
		Country:    field("country"),
	}
	if address != (userAddressDocument{}) {
		doc.UserInformation.Address = &address
	}
	return nil
}

func (doc *userDocument) setSecret(hash string) {
	doc.Password = hash
	doc.Salt = ""
}

// Address returns the address of the user or an empty one, used by the template.
func (doc *userDocument) Address() userAddressDocument {
	if doc.UserInformation.Address == nil {
		return userAddressDocument{}
	}
	return *doc.UserInformation.Address
}

type claimDocument struct {
	Name   string   `toml:"name"`
	Value  string   `toml:"value,omitempty"`
	Values []string `toml:"values,omitempty"`
	Scope  string   `toml:"scope,omitempty"`
	Scopes []string `toml:"scopes,omitempty"`
}

// AllScopes returns the single and multiple scopes of the claim, used by the template.
func (claim claimDocument) AllScopes() []string {
	return merge(claim.Scope, claim.Scopes)
}

// maxClaims limits the number of claim rows read from a submitted form.
const maxClaims = 100

type classificationDocument struct {
	User    string          `toml:"user,omitempty"`
	Users   []string        `toml:"users,omitempty"`
	Client  string          `toml:"client,omitempty"`
	Clients []string        `toml:"clients,omitempty"`
	Scope   string          `toml:"scope,omitempty"`
	Scopes  []string        `toml:"scopes,omitempty"`
	Claims  []claimDocument `toml:"claims,omitempty"`
}

func (doc *classificationDocument) key() string {
	return ""
}

// applyForm sets the users, clients and scopes as single value when only one is given, otherwise as list.
// Claim rows without name and values are ignored.
func (doc *classificationDocument) applyForm(values url.Values) error {
	doc.User, doc.Users = split(formLines(values, "users"))
	doc.Client, doc.Clients = split(formLines(values, "clients"))
	doc.Scope, doc.Scopes = split(formLines(values, "scopes"))

	count, countError := formInt(values, "claims")
	if countError != nil {
		return countError
	}
	count = min(count, maxClaims)
	doc.Claims = nil
	for index := range count {
		prefix := fmt.Sprintf("claim.%d.", index)
		claim := claimDocument{
			Name:   strings.TrimSpace(values.Get(prefix + "name")),
			Value:  strings.TrimSpace(values.Get(prefix + "value")),
			Values: formLines(values, prefix+"values"),
		}
		claim.Scope, claim.Scopes = split(formLines(values, prefix+"scopes"))
		if claim.Name == "" && claim.Value == "" && len(claim.Values) == 0 {
			continue
		}
		doc.Claims = append(doc.Claims, claim)
	}
	return nil
}

func (doc *classificationDocument) setSecret(string) {
}

// AllUsers returns the single and multiple users, used by the template.
func (doc *classificationDocument) AllUsers() []string {
	return merge(doc.User, doc.Users)
}

// AllClients returns the single and multiple clients, used by the template.
func (doc *classificationDocument) AllClients() []string {
	return merge(doc.Client, doc.Clients)
}

// AllScopes returns the single and multiple scopes, used by the template.
func (doc *classificationDocument) AllScopes() []string {
	return merge(doc.Scope, doc.Scopes)
}

// newDocument returns an empty document for the given kind.
func newDocument(kind *Kind) document {
	switch kind.Name {
	case "clients":
		return &clientDocument{}
	case "users":
		return &userDocument{}
	default:
		return &classificationDocument{}
	}
}

// decodeDocument decodes the data into the document, keys not part of the document are ignored.
func decodeDocument(data []byte, doc document) error {
	_, decodeError := toml.Decode(string(data), doc)
	return friendlyError(decodeError)
}

// mergeDocument encodes the document and keeps the settings of the existing data which are not part of the document.
// Settings which are part of the document are always replaced, so values removed in the form are removed as well.
func mergeDocument(existing []byte, doc document) ([]byte, error) {
	encoded, encodeError := encodeDocument(doc)
	if encodeError != nil {
		return nil, encodeError
	}

	var base map[string]any
	if decodeError := toml.Unmarshal(existing, &base); decodeError != nil {
		return nil, decodeError
	}
	removeManagedKeys(base, reflect.TypeOf(doc))
	if len(base) == 0 {
		return encoded, nil
	}

	var overlay map[string]any
	if decodeError := toml.Unmarshal(encoded, &overlay); decodeError != nil {
		return nil, decodeError
	}
	mergeMaps(base, overlay)

	var buffer bytes.Buffer
	encoder := toml.NewEncoder(&buffer)
	encoder.Indent = ""
	if mergeError := encoder.Encode(base); mergeError != nil {
		return nil, mergeError
	}
	return buffer.Bytes(), nil
}

// removeManagedKeys removes all keys from values which are defined by the toml tags of the given struct type.
// Nested tables are removed key by key, so unknown keys inside them are kept.
func removeManagedKeys(values map[string]any, structType reflect.Type) {
	for structType.Kind() == reflect.Pointer {
		structType = structType.Elem()
	}
	for index := range structType.NumField() {
		field := structType.Field(index)
		name, _, _ := strings.Cut(field.Tag.Get("toml"), ",")
		if name == "" {
			continue
		}
		fieldType := field.Type
		for fieldType.Kind() == reflect.Pointer {
			fieldType = fieldType.Elem()
		}
		nested, isTable := values[name].(map[string]any)
		if fieldType.Kind() == reflect.Struct && isTable {
			removeManagedKeys(nested, fieldType)
			if len(nested) > 0 {
				continue
			}
		}
		delete(values, name)
	}
}

// mergeMaps copies all values from source into target, nested tables are merged.
func mergeMaps(target map[string]any, source map[string]any) {
	for key, value := range source {
		sourceTable, sourceIsTable := value.(map[string]any)
		targetTable, targetIsTable := target[key].(map[string]any)
		if sourceIsTable && targetIsTable {
			mergeMaps(targetTable, sourceTable)
		} else {
			target[key] = value
		}
	}
}

// encodeDocument encodes the document as TOML.
func encodeDocument(doc document) ([]byte, error) {
	var buffer bytes.Buffer
	encoder := toml.NewEncoder(&buffer)
	encoder.Indent = ""
	if encodeError := encoder.Encode(doc); encodeError != nil {
		return nil, encodeError
	}
	return buffer.Bytes(), nil
}

// formLines returns the non-empty, trimmed lines of a textarea.
func formLines(values url.Values, name string) []string {
	var result []string
	for _, line := range strings.Split(values.Get(name), "\n") {
		if line = strings.TrimSpace(line); line != "" {
			result = append(result, line)
		}
	}
	return result
}

func formBool(values url.Values, name string) bool {
	return values.Get(name) != ""
}

func formInt(values url.Values, name string) (int, error) {
	value := strings.TrimSpace(values.Get(name))
	if value == "" {
		return 0, nil
	}
	result, parseError := strconv.Atoi(value)
	if parseError != nil || result < 0 {
		return 0, fmt.Errorf("%s must be a positive number", name)
	}
	return result, nil
}

// split returns a single value as first result, multiple values as second result.
func split(values []string) (string, []string) {
	if len(values) == 1 {
		return values[0], nil
	}
	return "", values
}

func merge(single string, multiple []string) []string {
	if single == "" {
		return multiple
	}
	return append([]string{single}, multiple...)
}
