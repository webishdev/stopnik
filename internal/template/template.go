package template

import (
	"bytes"
	_ "embed"
	"github.com/webishdev/stopnik/internal/config"
	"github.com/webishdev/stopnik/internal/system"
	"html/template"
	"sync"
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

var templateManagerLock = &sync.Mutex{}
var templateManagerSingleton *Manager

func GetTemplateManagerInstance() *Manager {
	templateManagerLock.Lock()
	defer templateManagerLock.Unlock()
	if templateManagerSingleton == nil {
		currentConfig := config.GetConfigInstance()
		templateManagerSingleton = &Manager{currentConfig}
	}

	return templateManagerSingleton
}

func addTemplates(main *template.Template) bytes.Buffer {
	var tpl bytes.Buffer

	_, headerParseError := main.New("header").Parse(string(headerHtml))
	if headerParseError != nil {
		system.Error(headerParseError)
	}

	_, mascotParseError := main.New("mascot").Parse(string(mascotHtml))
	if mascotParseError != nil {
		system.Error(mascotParseError)
	}

	_, footerParseError := main.New("footer").Parse(string(footerHtml))
	if footerParseError != nil {
		system.Error(footerParseError)
	}

	return tpl
}

func (templateManager *Manager) LoginTemplate(id string, action string, message string) bytes.Buffer {
	var tpl bytes.Buffer

	loginTemplate, loginParseError := template.New("login").Parse(string(loginHtml))
	if loginParseError != nil {
		system.Error(loginParseError)
	}

	addTemplates(loginTemplate)

	data := struct {
		Action        string
		Token         string
		HideFooter    bool
		HideMascot    bool
		ShowHtmlTitle bool
		HtmlTitle     string
		ShowTitle     bool
		Title         string
		FooterText    string
		ShowMessage   bool
		Message       string
	}{
		Action:        action,
		Token:         id,
		HideFooter:    templateManager.config.GetHideFooter(),
		HideMascot:    templateManager.config.GetHideLogo(),
		ShowHtmlTitle: templateManager.config.GetHtmlTitle() != "",
		HtmlTitle:     templateManager.config.GetHtmlTitle(),
		ShowTitle:     templateManager.config.GetTitle() != "",
		Title:         templateManager.config.GetTitle(),
		FooterText:    templateManager.config.GetFooterText(),
		ShowMessage:   message != "",
		Message:       message,
	}

	templateExecuteError := loginTemplate.Execute(&tpl, data)
	if templateExecuteError != nil {
		system.Error(templateExecuteError)
	}

	return tpl
}

func (templateManager *Manager) LogoutTemplate(username string, requestURI string) bytes.Buffer {
	var tpl bytes.Buffer

	logoutTemplate, loginParseError := template.New("logout").Parse(string(logoutHtml))
	if loginParseError != nil {
		system.Error(loginParseError)
	}

	addTemplates(logoutTemplate)

	data := struct {
		Username      string
		RequestURI    string
		HideFooter    bool
		HideMascot    bool
		ShowHtmlTitle bool
		HtmlTitle     string
		ShowTitle     bool
		Title         string
		FooterText    string
	}{
		Username:      username,
		RequestURI:    requestURI,
		HideFooter:    templateManager.config.GetHideFooter(),
		HideMascot:    templateManager.config.GetHideLogo(),
		ShowHtmlTitle: templateManager.config.GetHtmlTitle() != "",
		HtmlTitle:     templateManager.config.GetHtmlTitle(),
		ShowTitle:     templateManager.config.GetTitle() != "",
		Title:         templateManager.config.GetTitle(),
		FooterText:    templateManager.config.GetFooterText(),
	}

	templateExecuteError := logoutTemplate.Execute(&tpl, data)
	if templateExecuteError != nil {
		system.Error(templateExecuteError)
	}

	return tpl
}
