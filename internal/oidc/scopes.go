package oidc

import "slices"

const (
	ScopeOpenId        string = "openid"
	ScopeOfflineAccess string = "offline_access"
	ScopeProfile       string = "profile"
	ScopeEmail         string = "email"
	ScopeAddress       string = "address"
	ScopePhone         string = "phone"
)

func HasOidcScope(scopes []string) bool {
	return slices.Contains(scopes, ScopeOpenId)
}

func HasOfflineAccessScope(scopes []string) bool {
	return slices.Contains(scopes, ScopeOfflineAccess)
}
