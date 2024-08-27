package endpoint

const (
	Authorization string = "/authorize"
	Token         string = "/token"
	Health        string = "/health"
	Account       string = "/account"
	Logout        string = "/logout"
	Introspect    string = "/introspect"
	Revoke        string = "/revoke"
	Metadata      string = "/.well-known/oauth-authorization-server"
	Keys          string = "/keys"
	OidcDiscovery string = "/.well-known/openid-configuration"
	OidcUserInfo  string = "/userinfo"
)
