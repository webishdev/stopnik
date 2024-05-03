package pkce

import "strings"

// CodeChallengeMethod as described in https://datatracker.ietf.org/doc/html/rfc7636#section-4.3
type CodeChallengeMethod string

const (
	S256  CodeChallengeMethod = "S256"
	PLAIN CodeChallengeMethod = "plain"
)

var codeChallengeMethodMap = map[string]CodeChallengeMethod{
	"S256":  S256,
	"plain": PLAIN,
}

func CodeChallengeMethodFromString(value string) (CodeChallengeMethod, bool) {
	result, ok := codeChallengeMethodMap[strings.ToLower(value)]
	return result, ok
}
