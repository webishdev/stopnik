package template

import (
	"bytes"
	_ "embed"
	"html/template"
)

//go:embed resources/login.html
var loginHtml []byte

func LoginTemplate(id string) (bytes.Buffer, error) {
	var tpl bytes.Buffer

	tmpl, templateParseError := template.New("name").Parse(string(loginHtml))
	if templateParseError != nil {
		return tpl, templateParseError
	}

	data := struct {
		Token string
	}{
		Token: id,
	}

	templateExecuteError := tmpl.Execute(&tpl, data)
	if templateExecuteError != nil {
		return tpl, templateExecuteError
	}

	return tpl, nil
}
