package oauth2

import "strings"

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

type ClientType string

const (
	CONFIDENTIAL ClientType = "confidential"
	PUBLIC       ClientType = "public"
)

var clientTypeMap = map[string]ClientType{
	"confidential": CONFIDENTIAL,
	"public":       PUBLIC,
}

func ResponseTypeFromString(value string) (ResponseType, bool) {
	result, ok := responseTypeMap[strings.ToLower(value)]
	return result, ok
}

func ClientTypeFromString(value string) (ClientType, bool) {
	result, ok := clientTypeMap[strings.ToLower(value)]
	return result, ok
}
