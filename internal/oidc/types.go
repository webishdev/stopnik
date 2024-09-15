package oidc

import (
	"github.com/webishdev/stopnik/internal/config"
	"strings"
)

// PromptType as described in https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
// prompt=create is not supported, as no account can be created by a user in STOPnik
type PromptType string

const (
	PtNone          PromptType = "none"
	PtLogin         PromptType = "login"
	PtConsent       PromptType = "consent"
	PtSelectAccount PromptType = "select_account"
)

var promptTypeMap = map[string]PromptType{
	"none":           PtNone,
	"login":          PtLogin,
	"consent":        PtConsent,
	"select_account": PtSelectAccount,
}

type UserInfoResponse struct {
	config.UserProfile
	config.UserInformation
}

func PromptTypeFromString(value string) (PromptType, bool) {
	result, ok := promptTypeMap[strings.ToLower(value)]
	return result, ok
}
