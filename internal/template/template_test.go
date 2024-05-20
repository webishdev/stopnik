package template

import (
	"strings"
	"testing"
)

func Test_Template(t *testing.T) {
	t.Run("Login", func(t *testing.T) {
		loginTemplateBuffer := LoginTemplate("foo", "/some/post")

		result := loginTemplateBuffer.String()

		if len(result) == 0 {
			t.Error("result is empty")
		}

		assertContains(t, result, "<form method=\"POST\" action=\"/some/post\">")
		assertContains(t, result, "<input type=\"hidden\" name=\"stopnik_auth_session\" value=\"foo\"")
	})

	t.Run("Logout", func(t *testing.T) {
		logoutTemplateBuffer := LogoutTemplate("foo", "/some/value")

		result := logoutTemplateBuffer.String()

		if len(result) == 0 {
			t.Error("result is empty")
		}

		assertContains(t, result, "<form method=\"POST\" action=\"logout\">")
		assertContains(t, result, "<input type=\"hidden\" name=\"stopnik_auth_session\" value=\"/some/value\"")
	})
}

func assertContains(t *testing.T, value string, contains string) {
	if !strings.Contains(value, contains) {
		t.Errorf("result does not contain %s", contains)
	}
}
