package admin

import (
	"bytes"
	"embed"
	"html/template"
	"net/http"
	"strings"
	"unicode"

	"github.com/webishdev/stopnik/internal/oauth2"
	"github.com/webishdev/stopnik/log"
)

//go:embed resources
var resources embed.FS

var cssVersion = func() string {
	content, _ := resources.ReadFile("resources/admin.css")
	return hash(content)[:12]
}()

var pages = []string{"index", "list", "client", "user", "classification", "delete", "settings", "notfound", "login"}

var templateFuncs = template.FuncMap{
	// cssVersion changes with the styles, so browsers do not use outdated cached styles
	"cssVersion": func() string {
		return cssVersion
	},
	"lines": func(values []string) string {
		return strings.Join(values, "\n")
	},
	"merge": merge,
	"lower": lowerFirst,
	// remove describes the delete dialog of an entry, the entry is optional and only used for its label
	"remove": func(kind *Kind, id string, hash string, entry *Entry) map[string]any {
		label := ""
		if entry != nil {
			label = entry.Label
		}
		return map[string]any{"Kind": kind, "ID": id, "Hash": hash, "Label": label}
	},
	"switch": func(name string, checked bool, label string, hint string) map[string]any {
		return map[string]any{"Name": name, "Checked": checked, "Label": label, "Hint": hint}
	},
	"text": func(name string, label string, value string, placeholder string) map[string]string {
		return map[string]string{"Name": name, "Label": label, "Value": value, "Placeholder": placeholder}
	},
}

// navItem describes one kind in the navigation and on the overview page.
type navItem struct {
	Kind    *Kind
	Count   int
	Invalid int
	Error   string
}

// pageData is used by all pages, each page only uses the fields relevant for it.
type pageData struct {
	Title    string
	Username string
	Nav      []navItem
	Topics   []*staticTopic
	Kind     *Kind
	Topic    *staticTopic
	Message  string
	Error    string

	Entries []*Entry
	Entry   *Entry

	IsNew      bool
	ID         string
	Hash       string
	Doc        document
	HasSecret  bool
	GrantTypes []oauth2.GrantType
	ClaimRows  []claimDocument

	NoAdmin bool
}

// parseTemplates parses each page together with the shared layout and form parts.
// Links in the pages are prefixed with the basePath.
func parseTemplates(basePath string) (map[string]*template.Template, error) {
	baseFunc := template.FuncMap{"base": func() string {
		return basePath
	}}
	templates := make(map[string]*template.Template, len(pages))
	for _, page := range pages {
		pageTemplate, parseError := template.New(page).Funcs(templateFuncs).Funcs(baseFunc).ParseFS(resources, "resources/layout.html", "resources/icons.html", "resources/"+page+".html")
		if parseError != nil {
			return nil, parseError
		}
		templates[page] = pageTemplate
	}
	return templates, nil
}

// render executes the page into a buffer first, so a failing template results in a clean error response.
// Without a signed-in administrator the page is rendered without navigation, so nothing about the configuration is revealed.
func (handler *Handler) render(w http.ResponseWriter, r *http.Request, page string, status int, data *pageData) {
	layout := "bare"
	if data.Username = signedIn(r); data.Username != "" {
		layout = "layout"
		data.Nav = handler.nav()
		data.Topics = handler.topics
	}
	var buffer bytes.Buffer
	if executeError := handler.templates[page].ExecuteTemplate(&buffer, layout, data); executeError != nil {
		log.Error("Could not render page %s: %v", page, executeError)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, _ = buffer.WriteTo(w)
}

// nav counts the entries of all kinds.
func (handler *Handler) nav() []navItem {
	var items []navItem
	for _, kind := range handler.store.Kinds() {
		item := navItem{Kind: kind}
		entries, listError := handler.store.List(kind)
		if listError != nil {
			item.Error = listError.Error()
		}
		item.Count = len(entries)
		for _, entry := range entries {
			if !entry.Valid() {
				item.Invalid++
			}
		}
		items = append(items, item)
	}
	return items
}

func lowerFirst(value string) string {
	if value == "" {
		return value
	}
	runes := []rune(value)
	runes[0] = unicode.ToLower(runes[0])
	return string(runes)
}
