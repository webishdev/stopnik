package template

import (
	"bytes"
	_ "embed"
	"github.com/webishdev/stopnik/internal/config"
	"html/template"
)

//go:embed resources/header.html
var headerHtml []byte

//go:embed resources/footer.html
var footerHtml []byte

//go:embed resources/mascot.html
var mascotHtml []byte

//go:embed resources/login.html
var loginHtml []byte

//go:embed resources/logout.html
var logoutHtml []byte

type Manager struct {
	config *config.Config
}

func NewTemplateManager(config *config.Config) *Manager {
	return &Manager{config}
}

func addTemplates(main *template.Template) bytes.Buffer {
	var tpl bytes.Buffer

	_, headerParseError := main.New("header").Parse(string(headerHtml))
	if headerParseError != nil {
		panic(headerParseError)
	}

	_, mascotParseError := main.New("mascot").Parse(string(mascotHtml))
	if mascotParseError != nil {
		panic(mascotParseError)
	}

	_, footerParseError := main.New("footer").Parse(string(footerHtml))
	if footerParseError != nil {
		panic(footerParseError)
	}

	return tpl
}

func (templateManager *Manager) LoginTemplate(id string, action string) bytes.Buffer {
	var tpl bytes.Buffer

	loginTemplate, loginParseError := template.New("login").Parse(string(loginHtml))
	if loginParseError != nil {
		panic(loginParseError)
	}

	addTemplates(loginTemplate)

	data := struct {
		Action     string
		Token      string
		HideFooter bool
		HideMascot bool
		ShowTitle  bool
		Title      string
		FooterText string
	}{
		Action:     action,
		Token:      id,
		HideFooter: templateManager.config.GetHideFooter(),
		HideMascot: templateManager.config.GetHideMascot(),
		ShowTitle:  templateManager.config.GetTitle() != "",
		Title:      templateManager.config.GetTitle(),
		FooterText: templateManager.config.GetFooterText(),
	}

	templateExecuteError := loginTemplate.Execute(&tpl, data)
	if templateExecuteError != nil {
		panic(templateExecuteError)
	}

	return tpl
}

func (templateManager *Manager) LogoutTemplate(username string, requestURI string) bytes.Buffer {
	var tpl bytes.Buffer

	logoutTemplate, loginParseError := template.New("logout").Parse(string(logoutHtml))
	if loginParseError != nil {
		panic(loginParseError)
	}

	addTemplates(logoutTemplate)

	data := struct {
		Username   string
		RequestURI string
		HideFooter bool
		HideMascot bool
		ShowTitle  bool
		Title      string
		FooterText string
	}{
		Username:   username,
		RequestURI: requestURI,
		HideFooter: templateManager.config.GetHideFooter(),
		HideMascot: templateManager.config.GetHideMascot(),
		ShowTitle:  templateManager.config.GetTitle() != "",
		Title:      templateManager.config.GetTitle(),
		FooterText: templateManager.config.GetFooterText(),
	}

	templateExecuteError := logoutTemplate.Execute(&tpl, data)
	if templateExecuteError != nil {
		panic(templateExecuteError)
	}

	return tpl
}
