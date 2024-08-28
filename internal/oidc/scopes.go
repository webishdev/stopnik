package oidc

import "slices"

const (
	ScopeOpenId        string = "openid"
	ScopeOfflineAccess string = "offline_access"
)

func HasOidcScope(scopes []string) bool {
	return slices.Contains(scopes, ScopeOpenId)
}
