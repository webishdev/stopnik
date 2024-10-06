package oidc

const (
	ClaimNonce           string = "nonce"
	ClaimAuthorizedParty string = "azp"
	ClaimAtHash          string = "at_hash"
	ClaimAuthTime        string = "auth_time"
)

// ClaimsParameterMember as described in https://openid.net/specs/openid-connect-core-1_0.html#IndividualClaimsRequests
type ClaimsParameterMember struct {
	Essential bool     `json:"essential,omitempty"`
	Value     string   `json:"value,omitempty"`
	Values    []string `json:"values,omitempty"`
}

// ClaimsParameter provides values for https://openid.net/specs/openid-connect-core-1_0.html#ClaimsParameter
type ClaimsParameter struct {
	UserInfo map[string]*ClaimsParameterMember `json:"userinfo,omitempty"`
	IdToken  map[string]*ClaimsParameterMember `json:"id_token,omitempty"`
}
