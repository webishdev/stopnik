package oidc

import (
	"fmt"
	"testing"
)

func Test_PromptTypeFromString(t *testing.T) {
	type parameter struct {
		value    string
		exists   bool
		expected string
	}

	var promptTypeParameters = []parameter{
		{string(PtNone), true, "none"},
		{string(PtLogin), true, "login"},
		{string(PtConsent), true, "consent"},
		{string(PtSelectAccount), true, "select_account"},
		{"foo", false, ""},
	}

	for _, test := range promptTypeParameters {
		testMessage := fmt.Sprintf("Prompt type %s %v", test.value, test.exists)
		t.Run(testMessage, func(t *testing.T) {
			if promptType, exits := PromptTypeFromString(test.value); exits != test.exists && string(promptType) != test.expected {
				t.Errorf("Prompt type %s not found,", test.value)
			}
		})
	}
}
