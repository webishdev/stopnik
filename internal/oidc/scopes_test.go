package oidc

import (
	"fmt"
	"testing"
)

func Test_Scopes(t *testing.T) {
	type scopeParameter struct {
		value    string
		expected string
	}

	var scopeParameters = []scopeParameter{
		{ScopeOpenId, "openid"},
		{ScopeOfflineAccess, "offline_access"},
	}

	for _, test := range scopeParameters {
		testMessage := fmt.Sprintf("OIDC scope %s", test.value)
		t.Run(testMessage, func(t *testing.T) {
			if test.value != test.expected {
				t.Errorf("assertion error, %v != %v", test.value, test.expected)
			}
		})
	}

	type hasScopeParameter struct {
		values   []string
		expected bool
	}

	var hasScopeParameters = []hasScopeParameter{
		{[]string{ScopeOpenId}, true},
		{[]string{ScopeOpenId, ScopeOfflineAccess}, true},
		{[]string{ScopeOpenId, "foo", "bar"}, true},
		{[]string{ScopeOfflineAccess}, false},
		{[]string{ScopeOfflineAccess, "foo"}, false},
		{[]string{ScopeOfflineAccess, "foo", "bar"}, false},
		{[]string{"foo", "bar"}, false},
		{[]string{"foo"}, false},
	}

	for _, test := range hasScopeParameters {
		testMessage := fmt.Sprintf("Has OIDC scope %s", test.values)
		t.Run(testMessage, func(t *testing.T) {
			result := HasOidcScope(test.values)
			if result != test.expected {
				t.Errorf("should have OIDC scopes %v", test.values)
			}
		})
	}
}
