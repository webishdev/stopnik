package pkce

import (
	"fmt"
	"testing"
)

type codeChallengeMethodParameter struct {
	value    string
	exists   bool
	expected string
}

var codeChallengeMethodParameters = []codeChallengeMethodParameter{
	{string(S256), true, "S256"},
	{string(PLAIN), true, "plain"},
	{"foo", false, ""},
}

func Test_CodeChallengeMethodFromString(t *testing.T) {

	for _, test := range codeChallengeMethodParameters {
		testMessage := fmt.Sprintf("%s_%v", test.value, test.exists)
		t.Run(testMessage, func(t *testing.T) {
			if grandType, exits := CodeChallengeMethodFromString(test.value); exits != test.exists && string(grandType) != test.expected {
				t.Errorf("Code challenge method %s not found,", test.value)
			}
		})
	}
}
