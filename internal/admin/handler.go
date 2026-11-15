package admin

import (
	"errors"
	"html/template"
	"io/fs"
	"net/http"
	"net/url"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/webishdev/stopnik/internal/config"
	"github.com/webishdev/stopnik/internal/crypto"
	internalHttp "github.com/webishdev/stopnik/internal/http"
	"github.com/webishdev/stopnik/internal/template/assets"
	"github.com/webishdev/stopnik/log"
)

// maxFormSize limits the size of submitted forms.
const maxFormSize = 1 << 20

// Handler serves the admin web user interface.
type Handler struct {
	store     *Store
	topics    []*staticTopic
	templates map[string]*template.Template
	basePath  string
	mux       *http.ServeMux
	routes    http.Handler
	public    map[string]bool
	auth      *authenticator

	invalidCredentialsMessage string
}

// NewHandler creates the admin web user interface for the given Store.
// The optional static configuration is shown read-only, summarized on the overview page and with one page per topic.
// All pages are served below the optional basePath, e.g. /admin.
// Only users with the administrator flag can sign in, all pages except the sign-in page and the assets require a signed-in administrator.
// The returned handler sets security headers and rejects cross-origin requests which modify data.
func NewHandler(store *Store, staticConfig *config.Config, basePath string) (http.Handler, error) {
	basePath = normalizeBasePath(basePath)
	templates, templateError := parseTemplates(basePath)
	if templateError != nil {
		return nil, templateError
	}

	sessionTimeout := defaultSessionTimeout
	invalidCredentialsMessage := "Invalid credentials"
	if staticConfig != nil {
		sessionTimeout = time.Duration(staticConfig.GetSessionTimeoutSeconds()) * time.Second
		invalidCredentialsMessage = staticConfig.GetInvalidCredentialsMessage()
	}

	handler := &Handler{
		store:                     store,
		topics:                    staticTopics(staticConfig, store),
		templates:                 templates,
		basePath:                  basePath,
		mux:                       http.NewServeMux(),
		public:                    map[string]bool{},
		auth:                      newAuthenticator(store, sessionTimeout),
		invalidCredentialsMessage: invalidCredentialsMessage,
	}
	handler.routes = http.StripPrefix(basePath, http.HandlerFunc(handler.requireAdmin))

	handler.handlePublic("GET /login", handler.showLogin)
	handler.handlePublic("POST /login", handler.login)
	for _, asset := range []string{"admin.css", "logo.png", "favicon.ico"} {
		handler.handlePublic("GET /assets/"+asset, handler.assets)
	}
	handler.mux.HandleFunc("POST /logout", handler.logout)
	handler.mux.HandleFunc("GET /{$}", handler.index)
	// literal routes per topic, a /settings/{topic} pattern would conflict with /{kind}/new
	if len(handler.topics) > 0 {
		handler.mux.HandleFunc("GET /settings", func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, handler.basePath+"/settings/"+handler.topics[0].Name, http.StatusSeeOther)
		})
	}
	for _, topic := range handler.topics {
		handler.mux.HandleFunc("GET /settings/"+topic.Name, func(w http.ResponseWriter, r *http.Request) {
			handler.render(w, r, "settings", http.StatusOK, &pageData{Title: topic.Title, Topic: topic})
		})
	}
	handler.mux.HandleFunc("GET /{kind}", handler.withKind(handler.list))
	handler.mux.HandleFunc("GET /{kind}/new", handler.withKind(handler.showForm))
	handler.mux.HandleFunc("POST /{kind}/new", handler.withKind(handler.saveForm))
	handler.mux.HandleFunc("GET /{kind}/{id}", handler.withKind(handler.showForm))
	handler.mux.HandleFunc("POST /{kind}/{id}", handler.withKind(handler.saveForm))
	handler.mux.HandleFunc("GET /{kind}/{id}/delete", handler.withKind(handler.showDelete))
	handler.mux.HandleFunc("POST /{kind}/{id}/delete", handler.withKind(handler.delete))

	return http.NewCrossOriginProtection().Handler(handler), nil
}

func (handler *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set(internalHttp.XFrameOptions, "DENY")
	w.Header().Set(internalHttp.ContentSecurityPolicy, "default-src 'self'; frame-ancestors 'none'")
	w.Header().Set(internalHttp.XContentTypeOptions, "nosniff")
	w.Header().Set(internalHttp.ReferrerPolicy, "no-referrer")
	w.Header().Set(internalHttp.CacheControl, "no-store")
	log.AccessLogRequest(r)
	if handler.basePath != "" {
		if r.URL.Path == handler.basePath {
			http.Redirect(w, r, handler.basePath+"/", http.StatusMovedPermanently)
			return
		}
		if !strings.HasPrefix(r.URL.Path, handler.basePath+"/") {
			handler.notFound(w, r)
			return
		}
	}
	handler.routes.ServeHTTP(w, r)
}

// normalizeBasePath returns the base path with a leading and without a trailing slash, or empty for the root path.
func normalizeBasePath(basePath string) string {
	trimmed := strings.Trim(basePath, "/")
	if trimmed == "" {
		return ""
	}
	return "/" + trimmed
}

// handlePublic registers a route which is available without signing in.
func (handler *Handler) handlePublic(pattern string, handlerFunc http.HandlerFunc) {
	handler.public[pattern] = true
	handler.mux.HandleFunc(pattern, handlerFunc)
}

// requireAdmin serves public routes to everyone, all other routes only to a signed-in administrator.
// Everyone else is redirected to the sign-in page.
func (handler *Handler) requireAdmin(w http.ResponseWriter, r *http.Request) {
	if user, isAdmin := handler.auth.user(r); isAdmin {
		handler.mux.ServeHTTP(w, withUsername(r, user.Username))
		return
	}
	if _, pattern := handler.mux.Handler(r); handler.public[pattern] {
		handler.mux.ServeHTTP(w, r)
		return
	}
	http.Redirect(w, r, handler.basePath+"/login", http.StatusSeeOther)
}

func (handler *Handler) showLogin(w http.ResponseWriter, r *http.Request) {
	if signedIn(r) != "" {
		http.Redirect(w, r, handler.basePath+"/", http.StatusSeeOther)
		return
	}
	handler.renderLogin(w, r, http.StatusOK, "")
}

func (handler *Handler) login(w http.ResponseWriter, r *http.Request) {
	if formError := parseForm(w, r); formError != nil {
		http.Error(w, formError.Error(), http.StatusBadRequest)
		return
	}
	username := r.PostForm.Get("username")
	sessionId, valid := handler.auth.login(username, r.PostForm.Get("password"))
	if !valid {
		log.Info("Failed sign in for user '%s'", username)
		handler.renderLogin(w, r, http.StatusUnauthorized, handler.invalidCredentialsMessage)
		return
	}
	// a new session is used for every sign in, an existing session is ended
	handler.auth.logout(r)
	http.SetCookie(w, sessionCookie(r, handler.basePath, sessionId, int(handler.auth.sessionTimeout.Seconds())))
	log.Info("User '%s' signed in", username)
	http.Redirect(w, r, handler.basePath+"/", http.StatusSeeOther)
}

func (handler *Handler) logout(w http.ResponseWriter, r *http.Request) {
	handler.auth.logout(r)
	http.SetCookie(w, sessionCookie(r, handler.basePath, "", -1))
	log.Info("User '%s' signed out", signedIn(r))
	http.Redirect(w, r, handler.basePath+"/login", http.StatusSeeOther)
}

// renderLogin shows the sign-in page, without any administrator it explains how to create one.
func (handler *Handler) renderLogin(w http.ResponseWriter, r *http.Request, status int, message string) {
	handler.render(w, r, "login", status, &pageData{Title: "Sign in", Error: message, NoAdmin: !handler.store.HasAdmin()})
}

// withKind resolves the kind from the request path, unknown kinds result in 404.
func (handler *Handler) withKind(next func(w http.ResponseWriter, r *http.Request, kind *Kind)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		kind, exists := handler.store.Kind(r.PathValue("kind"))
		if !exists {
			handler.notFound(w, r)
			return
		}
		next(w, r, kind)
	}
}

func (handler *Handler) index(w http.ResponseWriter, r *http.Request) {
	handler.render(w, r, "index", http.StatusOK, &pageData{Title: "Overview"})
}

// assets serves the admin styles and the logo and favicon of the STOPnik web user interface.
func (handler *Handler) assets(w http.ResponseWriter, r *http.Request) {
	var content []byte
	var readError error
	switch name := path.Base(r.URL.Path); name {
	case "admin.css":
		content, readError = fs.ReadFile(resources, "resources/admin.css")
	case "logo.png", "favicon.ico":
		content, readError = fs.ReadFile(assets.GetAssets(), "resources/"+name)
	default:
		handler.notFound(w, r)
		return
	}
	if readError != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	switch path.Ext(r.URL.Path) {
	case ".css":
		w.Header().Set("Content-Type", "text/css; charset=utf-8")
	case ".png":
		w.Header().Set("Content-Type", "image/png")
	case ".ico":
		w.Header().Set("Content-Type", "image/x-icon")
	}
	w.Header().Set(internalHttp.CacheControl, "max-age=3600")
	_, _ = w.Write(content)
}

func (handler *Handler) list(w http.ResponseWriter, r *http.Request, kind *Kind) {
	data := &pageData{Title: kind.Title, Kind: kind}
	entries, listError := handler.store.List(kind)
	if listError != nil {
		data.Error = listError.Error()
	}
	data.Entries = entries

	subject := kind.Singular
	if name := r.URL.Query().Get("name"); name != "" {
		subject += " '" + name + "'"
	}
	switch r.URL.Query().Get("done") {
	case "saved":
		data.Message = subject + " saved"
	case "deleted":
		data.Message = subject + " deleted"
	}
	handler.render(w, r, "list", http.StatusOK, data)
}

func (handler *Handler) showForm(w http.ResponseWriter, r *http.Request, kind *Kind) {
	id := r.PathValue("id")
	data := &pageData{Kind: kind, IsNew: id == "", ID: id, Doc: newDocument(kind)}
	if !data.IsNew {
		entry, content, getError := handler.store.Get(kind, id)
		if getError != nil {
			handler.notFoundOrError(w, r, getError)
			return
		}
		if decodeError := decodeDocument(content, data.Doc); decodeError != nil {
			handler.renderBroken(w, r, kind, entry, decodeError)
			return
		}
		data.Entry = entry
		data.Hash = entry.Hash
		data.Error = entry.Error
	}
	handler.renderForm(w, r, http.StatusOK, data, 1)
}

func (handler *Handler) saveForm(w http.ResponseWriter, r *http.Request, kind *Kind) {
	if formError := parseForm(w, r); formError != nil {
		http.Error(w, formError.Error(), http.StatusBadRequest)
		return
	}
	values := r.PostForm
	id := r.PathValue("id")
	data := &pageData{Kind: kind, IsNew: id == "", ID: id, Hash: values.Get("hash"), Doc: newDocument(kind)}

	// existing entries are decoded first, to keep values not part of the form, like the hashed secret
	var existing []byte
	var existingKey string
	if !data.IsNew {
		entry, content, getError := handler.store.Get(kind, id)
		if getError != nil {
			handler.notFoundOrError(w, r, getError)
			return
		}
		existing, existingKey = content, entry.Key
		if entry.Hash != data.Hash {
			data.Error = ErrConflict.Error()
		} else if decodeError := decodeDocument(content, data.Doc); decodeError != nil {
			handler.renderBroken(w, r, kind, entry, decodeError)
			return
		}
	}

	applyError := data.Doc.applyForm(values)
	if data.Error == "" && applyError != nil {
		data.Error = applyError.Error()
	}
	if doc, isUser := data.Doc.(*userDocument); data.Error == "" && isUser && handler.isOwnUser(r, existingKey) && (!doc.Admin || doc.Username != existingKey) {
		data.Error = ErrOwnAdmin.Error()
	}
	if values.Get("action") == "addClaim" {
		data.Error = ""
		handler.renderForm(w, r, http.StatusOK, data, 2)
		return
	}
	if data.Error != "" {
		handler.renderForm(w, r, http.StatusBadRequest, data, 1)
		return
	}

	if values.Get("removeSecret") != "" {
		data.Doc.setSecret("")
	}
	if secret := values.Get("secret"); secret != "" {
		hashed, hashError := crypto.BcryptHash(secret)
		if hashError != nil {
			data.Error = hashError.Error()
			handler.renderForm(w, r, http.StatusBadRequest, data, 1)
			return
		}
		data.Doc.setSecret(hashed)
	}

	var saveError error
	if data.IsNew {
		saveError = handler.create(kind, data.Doc)
	} else {
		saveError = handler.update(kind, id, existing, data.Doc, data.Hash)
	}
	if saveError != nil {
		data.Error = saveError.Error()
		handler.renderForm(w, r, http.StatusBadRequest, data, 1)
		return
	}
	handler.redirectToList(w, r, kind, "saved", data.Doc.key())
}

// renderForm renders the form of the kind with the given number of empty claim rows.
func (handler *Handler) renderForm(w http.ResponseWriter, r *http.Request, status int, data *pageData, emptyClaims int) {
	if data.IsNew {
		data.Title = "New " + lowerFirst(data.Kind.Singular)
	} else {
		data.Title = "Edit " + lowerFirst(data.Kind.Singular)
	}
	data.GrantTypes = GrantTypes
	switch doc := data.Doc.(type) {
	case *clientDocument:
		data.HasSecret = doc.ClientSecret != ""
	case *userDocument:
		data.HasSecret = doc.Password != ""
	case *classificationDocument:
		data.ClaimRows = append(doc.Claims, make([]claimDocument, emptyClaims)...)
	}
	handler.render(w, r, lowerFirst(data.Kind.Singular), status, data)
}

// renderBroken shows an entry which can not be edited with the form, it can only be deleted.
func (handler *Handler) renderBroken(w http.ResponseWriter, r *http.Request, kind *Kind, entry *Entry, err error) {
	handler.render(w, r, "delete", http.StatusOK, &pageData{
		Title: "Invalid " + lowerFirst(kind.Singular),
		Kind:  kind,
		ID:    entry.ID,
		Hash:  entry.Hash,
		Entry: entry,
		Error: "This " + lowerFirst(kind.Singular) + " can not be edited, it contains invalid settings: " + err.Error(),
	})
}

func (handler *Handler) showDelete(w http.ResponseWriter, r *http.Request, kind *Kind) {
	entry, _, getError := handler.store.Get(kind, r.PathValue("id"))
	if getError != nil {
		handler.notFoundOrError(w, r, getError)
		return
	}
	handler.render(w, r, "delete", http.StatusOK, &pageData{Title: "Delete " + lowerFirst(kind.Singular), Kind: kind, ID: entry.ID, Hash: entry.Hash, Entry: entry})
}

func (handler *Handler) delete(w http.ResponseWriter, r *http.Request, kind *Kind) {
	if formError := parseForm(w, r); formError != nil {
		http.Error(w, formError.Error(), http.StatusBadRequest)
		return
	}
	id := r.PathValue("id")
	entry, _, getError := handler.store.Get(kind, id)
	if getError != nil {
		handler.notFoundOrError(w, r, getError)
		return
	}
	hash := r.PostForm.Get("hash")
	deleteError := ErrOwnAdmin
	if kind.Name != "users" || !handler.isOwnUser(r, entry.Key) {
		deleteError = handler.store.Delete(kind, id, hash)
	}
	if deleteError != nil {
		handler.render(w, r, "delete", http.StatusBadRequest, &pageData{Title: "Delete " + lowerFirst(kind.Singular), Kind: kind, ID: id, Hash: hash, Entry: entry, Error: deleteError.Error()})
		return
	}
	log.Info("Deleted %s from %s", describe(kind, entry.Key), filepath.Join(kind.Dir, id+fileSuffix))
	handler.redirectToList(w, r, kind, "deleted", entry.Key)
}

// isOwnUser returns whether the key of an existing entry belongs to the signed-in administrator.
func (handler *Handler) isOwnUser(r *http.Request, key string) bool {
	return key != "" && key == signedIn(r)
}

func (handler *Handler) create(kind *Kind, doc document) error {
	content, encodeError := encodeDocument(doc)
	if encodeError != nil {
		return encodeError
	}
	id, createError := handler.store.Create(kind, content)
	if createError != nil {
		return createError
	}
	log.Info("Created %s in %s", describe(kind, doc.key()), filepath.Join(kind.Dir, id+fileSuffix))
	return nil
}

func (handler *Handler) update(kind *Kind, id string, existing []byte, doc document, hash string) error {
	content, mergeError := mergeDocument(existing, doc)
	if mergeError != nil {
		return mergeError
	}
	if updateError := handler.store.Update(kind, id, content, hash); updateError != nil {
		return updateError
	}
	log.Info("Updated %s in %s", describe(kind, doc.key()), filepath.Join(kind.Dir, id+fileSuffix))
	return nil
}

func (handler *Handler) notFound(w http.ResponseWriter, r *http.Request) {
	handler.render(w, r, "notfound", http.StatusNotFound, &pageData{Title: "Not found"})
}

func (handler *Handler) notFoundOrError(w http.ResponseWriter, r *http.Request, err error) {
	if errors.Is(err, ErrNotFound) || errors.Is(err, ErrInvalidID) {
		handler.notFound(w, r)
		return
	}
	log.Error("Request %s failed: %v", r.URL.Path, err)
	http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
}

func parseForm(w http.ResponseWriter, r *http.Request) error {
	r.Body = http.MaxBytesReader(w, r.Body, maxFormSize)
	return r.ParseForm()
}

func (handler *Handler) redirectToList(w http.ResponseWriter, r *http.Request, kind *Kind, done string, name string) {
	query := url.Values{"done": {done}}
	if name != "" {
		query.Set("name", name)
	}
	http.Redirect(w, r, handler.basePath+"/"+kind.Name+"?"+query.Encode(), http.StatusSeeOther)
}

// describe returns the kind and the key of an entry for messages, e.g. client 'foo'.
func describe(kind *Kind, key string) string {
	if key == "" {
		return lowerFirst(kind.Singular)
	}
	return lowerFirst(kind.Singular) + " '" + key + "'"
}
