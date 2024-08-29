package template

import (
	"github.com/webishdev/stopnik/internal/config"
	"strings"
	"testing"
)

func Test_Template(t *testing.T) {
	testConfig := &config.Config{
		Clients: []config.Client{
			{
				Id:           "foo",
				ClientSecret: "d82c4eb5261cb9c8aa9855edd67d1bd10482f41529858d925094d173fa662aa91ff39bc5b188615273484021dfb16fd8284cf684ccf0fc795be3aa2fc1e6c181",
				Redirects:    []string{"https://example.com/callback"},
			},
		},
		Users: []config.User{
			{
				Username: "foo",
				Password: "d82c4eb5261cb9c8aa9855edd67d1bd10482f41529858d925094d173fa662aa91ff39bc5b188615273484021dfb16fd8284cf684ccf0fc795be3aa2fc1e6c181",
			},
		},
	}

	err := testConfig.Initialize()
	if err != nil {
		t.Error(err)
	}

	templateManager := NewTemplateManager()

	t.Run("Login", func(t *testing.T) {
		loginTemplateBuffer := templateManager.LoginTemplate("foo", "/some/post", "")

		result := loginTemplateBuffer.String()

		if len(result) == 0 {
			t.Error("result is empty")
		}

		assertContains(t, result, "<form method=\"POST\" action=\"/some/post\">")
		assertContains(t, result, "<input type=\"hidden\" name=\"stopnik_auth_session\" value=\"foo\" />")
	})

	t.Run("Logout", func(t *testing.T) {
		logoutTemplateBuffer := templateManager.LogoutTemplate("foo", "/some/value")

		result := logoutTemplateBuffer.String()

		if len(result) == 0 {
			t.Error("result is empty")
		}

		assertContains(t, result, "<form method=\"POST\" action=\"logout\">")
		assertContains(t, result, "<input type=\"hidden\" name=\"stopnik_logout_redirect\" value=\"/some/value\" />")
	})
}

func assertContains(t *testing.T, value string, contains string) {
	if !strings.Contains(value, contains) {
		t.Errorf("result %s does not contain %s", value, contains)
	}
}
