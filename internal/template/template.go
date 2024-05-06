package template

import (
	"bytes"
	_ "embed"
	"html/template"
)

//go:embed resources/header.html
var headerHtml []byte

//go:embed resources/footer.html
var footerHtml []byte

//go:embed resources/login.html
var loginHtml []byte

//go:embed resources/logout.html
var logoutHtml []byte

func addTemplates(main *template.Template) bytes.Buffer {
	var tpl bytes.Buffer

	_, headerParseError := main.New("header").Parse(string(headerHtml))
	if headerParseError != nil {
		panic(headerParseError)
	}

	_, footerParseError := main.New("footer").Parse(string(footerHtml))
	if footerParseError != nil {
		panic(footerParseError)
	}

	return tpl
}

func LoginTemplate(id string, action string) bytes.Buffer {
	var tpl bytes.Buffer

	loginTemplate, loginParseError := template.New("login").Parse(string(loginHtml))
	if loginParseError != nil {
		panic(loginParseError)
	}

	addTemplates(loginTemplate)

	data := struct {
		Action string
		Token  string
	}{
		Action: action,
		Token:  id,
	}

	templateExecuteError := loginTemplate.Execute(&tpl, data)
	if templateExecuteError != nil {
		panic(templateExecuteError)
	}

	return tpl
}

func LogoutTemplate() bytes.Buffer {
	var tpl bytes.Buffer

	logoutTemplate, loginParseError := template.New("logout").Parse(string(logoutHtml))
	if loginParseError != nil {
		panic(loginParseError)
	}

	addTemplates(logoutTemplate)

	templateExecuteError := logoutTemplate.Execute(&tpl, nil)
	if templateExecuteError != nil {
		panic(templateExecuteError)
	}

	return tpl
}
