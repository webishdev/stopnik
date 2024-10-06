package oidc

const (
	ClaimNonce                string = "nonce"
	ClaimAuthorizedParty      string = "azp"
	ClaimAtHash               string = "at_hash"
	ClaimAuthTime             string = "auth_time"
	ClaimName                 string = "name"
	ClaimGivenName            string = "given_name"
	ClaimMiddleName           string = "middle_name"
	ClaimFamilyName           string = "family_name"
	ClaimNickname             string = "nickname"
	ClaimPreferredUsername    string = "preferred_username"
	ClaimGender               string = "gender"
	ClaimBirthdate            string = "birthdate"
	ClaimZoneInfo             string = "zoneinfo"
	ClaimLocale               string = "locale"
	ClaimWebsite              string = "website"
	ClaimProfile              string = "profile"
	ClaimPicture              string = "picture"
	ClaimEmail                string = "email"
	ClaimEmailVerified        string = "email_verified"
	ClaimPhoneNumber          string = "phone_number"
	ClaimPhoneNumberVerified  string = "phone_number_verified"
	ClaimUpdatedAt            string = "updated_at"
	ClaimAddressFormatted     string = "formatted"
	ClaimAddressStreetAddress string = "street_address"
	ClaimAddressLocality      string = "locality"
	ClaimAddressPostalCode    string = "postal_code"
	ClaimAddressRegion        string = "region"
	ClaimAddressCountry       string = "country"
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

func HasUserInfoClaim(cp *ClaimsParameter, name string) bool {
	if cp != nil && cp.UserInfo != nil {
		_, exists := cp.UserInfo[name]
		return exists
	} else {
		return false
	}
}
