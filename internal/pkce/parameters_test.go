package pkce

import (
	"stopnik/assert"
	"testing"
)

func Test_PKCEParameters(t *testing.T) {
	assert.Equal(t, ParameterCodeChallenge, "code_challenge")
	assert.Equal(t, ParameterCodeChallengeMethod, "code_challenge_method")
	assert.Equal(t, ParameterCodeVerifier, "code_verifier")
}
