package oauth2

import "strings"

// GrantType as described in
// - https://datatracker.ietf.org/doc/html/rfc6749#appendix-A.10
// - https://datatracker.ietf.org/doc/html/rfc7591#section-2
type GrantType string

const (
	GtAuthorizationCode GrantType = "authorization_code"
	GtClientCredentials GrantType = "client_credentials"
	GtPassword          GrantType = "password"
	GtRefreshToken      GrantType = "refresh_token"
	GtImplicit          GrantType = "implicit" // RFC7591
)

var grantTypeMap = map[string]GrantType{
	"authorization_code": GtAuthorizationCode,
	"client_credentials": GtClientCredentials,
	"password":           GtPassword,
	"refresh_token":      GtRefreshToken,
	"implicit":           GtImplicit, // RFC7591
}

// ResponseType as described in https://datatracker.ietf.org/doc/html/rfc6749#appendix-A.3
type ResponseType string

const (
	RtCode              ResponseType = "code"
	RtToken             ResponseType = "token"
	RtPassword          ResponseType = "password" // aka "implicit" grant
	RtClientCredentials ResponseType = "client_credentials"
	RtIdToken           ResponseType = "id_token"
)

var responseTypeMap = map[string]ResponseType{
	"code":               RtCode,
	"token":              RtToken,
	"password":           RtPassword,
	"client_credentials": RtClientCredentials,
	"id_token":           RtIdToken,
}

// ClientType as described in https://datatracker.ietf.org/doc/html/rfc6749#section-2.1
type ClientType string

const (
	CtConfidential ClientType = "confidential"
	CtPublic       ClientType = "public"
)

var clientTypeMap = map[string]ClientType{
	"confidential": CtConfidential,
	"public":       CtPublic,
}

// TokenType as described in https://datatracker.ietf.org/doc/html/rfc6749#section-7.1
type TokenType string

const (
	TtBearer TokenType = "Bearer" // https://www.rfc-editor.org/rfc/rfc6750#section-6.1.1
	TtMAC    TokenType = "mac"    // https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-http-mac-05#section-9.3.1
)

var tokenTypeMap = map[string]TokenType{
	"bearer": TtBearer,
	"mac":    TtMAC,
}

// IntrospectTokenType as described in https://datatracker.ietf.org/doc/html/rfc7662#section-2.1
type IntrospectTokenType string

const (
	ItAccessToken  IntrospectTokenType = "access_token"
	ItRefreshToken IntrospectTokenType = "refresh_token"
)

var introspectTokenTypeMap = map[string]IntrospectTokenType{
	"access_token":  ItAccessToken,
	"refresh_token": ItRefreshToken,
}

func GrantTypeFromString(value string) (GrantType, bool) {
	result, ok := grantTypeMap[strings.ToLower(value)]
	return result, ok
}

func ResponseTypeFromString(value string) (ResponseType, bool) {
	result, ok := responseTypeMap[strings.ToLower(value)]
	return result, ok
}

func ClientTypeFromString(value string) (ClientType, bool) {
	result, ok := clientTypeMap[strings.ToLower(value)]
	return result, ok
}

func TokenTypeFromString(value string) (TokenType, bool) {
	result, ok := tokenTypeMap[strings.ToLower(value)]
	return result, ok
}

func IntrospectTokenTypeFromString(value string) (IntrospectTokenType, bool) {
	result, ok := introspectTokenTypeMap[strings.ToLower(value)]
	return result, ok
}
