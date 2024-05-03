package oauth2

import "strings"

type GrantType string

// GrantType as described in https://datatracker.ietf.org/doc/html/rfc6749#appendix-A.10
const (
	GtAuthorizationCode GrantType = "authorization_code"
	GtClientCredentials GrantType = "client_credentials"
	GtPassword          GrantType = "password"
)

var grantTypeMap = map[string]GrantType{
	"authorization_code": GtAuthorizationCode,
	"client_credentials": GtClientCredentials,
	"password":           GtPassword,
}

// ResponseType as described in https://datatracker.ietf.org/doc/html/rfc6749#appendix-A.3
type ResponseType string

const (
	RtCode              ResponseType = "code"
	RtToken             ResponseType = "token"
	RtPassword          ResponseType = "password" // aka "implicit" grant
	RtClientCredentials ResponseType = "client_credentials"
)

var responseTypeMap = map[string]ResponseType{
	"code":               RtCode,
	"token":              RtToken,
	"password":           RtPassword,
	"client_credentials": RtClientCredentials,
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
	TtBearer TokenType = "bearer"
	TtMAC    TokenType = "mac"
)

var tokenTypeMap = map[string]TokenType{
	"bearer": TtBearer,
	"mac":    TtMAC,
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
