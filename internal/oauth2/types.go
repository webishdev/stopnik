package oauth2

import "strings"

// ResponseType as described in https://datatracker.ietf.org/doc/html/rfc6749#section-3.1.1
type ResponseType string

const (
	CODE               ResponseType = "code"
	TOKEN              ResponseType = "token"
	PASSWORD           ResponseType = "password"
	CLIENT_CREDENTIALS ResponseType = "client_credentials"
)

var responseTypeMap = map[string]ResponseType{
	"code":               CODE,
	"token":              TOKEN,
	"password":           PASSWORD,
	"client_credentials": CLIENT_CREDENTIALS,
}

// ClientType as described in https://datatracker.ietf.org/doc/html/rfc6749#section-2.1
type ClientType string

const (
	CONFIDENTIAL ClientType = "confidential"
	PUBLIC       ClientType = "public"
)

var clientTypeMap = map[string]ClientType{
	"confidential": CONFIDENTIAL,
	"public":       PUBLIC,
}

// TokenType as described in https://datatracker.ietf.org/doc/html/rfc6749#section-7.1
type TokenType string

const (
	BEARER TokenType = "bearer"
	MAC    TokenType = "mac"
)

var tokenTypeMap = map[string]TokenType{
	"bearer": BEARER,
	"mac":    MAC,
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
