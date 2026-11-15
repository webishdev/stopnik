package admin

import (
	"cmp"
	"strconv"

	"github.com/webishdev/stopnik/internal/config"
)

// Kinds of static fields, they are rendered like the fields of the dynamic forms but read-only.
const (
	fieldText   = "text"
	fieldList   = "list"
	fieldSwitch = "switch"
)

// staticField describes a single read-only value of the static configuration.
// Values not configured stay empty and show their default as Placeholder, like the dynamic forms do.
// Full fields span the whole width of the grid, Unit is shown next to the value.
type staticField struct {
	Kind        string
	Label       string
	Hint        string
	Value       string
	Values      []string
	Placeholder string
	Unit        string
	Checked     bool
	Full        bool
}

// staticGroup groups fields of a topic into one card, Three uses a grid with three columns.
type staticGroup struct {
	Title       string
	Description string
	Three       bool
	Fields      []staticField
}

// staticTopic describes a part of the static configuration, each topic has its own read-only page.
// Summary describes the topic in one line for the overview, State is either empty, "enabled" or "disabled".
type staticTopic struct {
	Name    string
	Title   string
	Summary string
	State   string
	Groups  []staticGroup
}

// staticTopics describes the static configuration, secrets are never shown.
// The directories of the dynamic configuration are taken from the store, as they are already resolved there.
func staticTopics(staticConfig *config.Config, store *Store) []*staticTopic {
	if staticConfig == nil {
		return nil
	}
	server := staticConfig.Server
	forwardAuth := server.ForwardAuth
	ui := staticConfig.UI
	dynamic := staticConfig.Dynamic

	secret := textField("Secret", "Used to sign tokens and to derive keys for cookies.", "")
	secret.Placeholder = "Configured, hidden"
	if server.Secret == "" {
		secret.Placeholder = "Generated at start up"
	}

	sessionTimeout := withDefault("Session timeout", "Lifetime of a login session.", optionalInt(server.SessionTimeoutSeconds), strconv.Itoa(staticConfig.GetSessionTimeoutSeconds()))
	sessionTimeout.Unit = "seconds"
	interval := withDefault("Interval", "How often the directories are checked for changes.", optionalInt(dynamic.Interval), strconv.Itoa(int(staticConfig.GetDynamicInterval().Seconds())))
	interval.Unit = "seconds"

	var directories []staticField
	for _, kind := range store.Kinds() {
		directory := textField(kind.Title, "One file per "+lowerFirst(kind.Singular)+".", kind.Dir)
		directory.Full = true
		directories = append(directories, directory)
	}

	return []*staticTopic{
		{
			Name:    "server",
			Title:   "Server",
			Summary: serverSummary(staticConfig),
			Groups: []staticGroup{
				{
					Title:       "General",
					Description: "Where and how STOPnik is reachable.",
					Fields: []staticField{
						textField("Address", "Address STOPnik listens to.", server.Addr),
						textField("Base path", "Path prefix of all endpoints.", staticConfig.GetBasePath()),
						textField("Issuer", "External URL of STOPnik, used as issuer of the tokens. Required.", server.Issuer),
						withDefault("Log level", "One of debug, info, warn or error.", server.LogLevel, "info"),
						fullWidth(textField("Logout redirect", "Target after a logout without redirect.", server.LogoutRedirect)),
					},
				},
				{
					Title:       "Tokens and sessions",
					Description: "Keys used to sign tokens.",
					Fields: []staticField{
						fullWidth(textField("Private key", "Used to sign tokens, otherwise an ephemeral key is generated on every start.", server.PrivateKey)),
						secret,
						sessionTimeout,
					},
				},
				{
					Title:       "Reserved scopes",
					Description: "Scopes a client needs to use the introspection and revocation endpoints.",
					Fields: []staticField{
						withDefault("Introspect scope", "", server.IntrospectScope, staticConfig.GetIntrospectScope()),
						withDefault("Revoke scope", "", server.RevokeScope, staticConfig.GetRevokeScope()),
					},
				},
			},
		},
		{
			Name:    "cookies",
			Title:   "Cookies",
			Summary: cookiesSummary(staticConfig),
			Groups: []staticGroup{
				{
					Title:       "Names",
					Description: "Names of the cookies set by STOPnik.",
					Three:       true,
					Fields: []staticField{
						withDefault("Authentication", "Login session.", server.Cookies.AuthName, staticConfig.GetAuthCookieName()),
						withDefault("Message", "Messages after a redirect.", server.Cookies.MessageName, staticConfig.GetMessageCookieName()),
						withDefault("Forward auth", "Forward auth session.", server.Cookies.ForwardAuthName, staticConfig.GetForwardAuthCookieName()),
					},
				},
				{
					Title:       "Security",
					Description: "Disable secure cookies only for local development without HTTPS.",
					Fields: []staticField{
						toggle("Secure cookies", "Cookies are only sent via HTTPS.", staticConfig.GetSecureCookie()),
					},
				},
			},
		},
		{
			Name:    "tls",
			Title:   "TLS",
			Summary: tlsSummary(staticConfig),
			State:   enabledState(server.TLS.Addr != ""),
			Groups: []staticGroup{
				{
					Title:       "TLS",
					Description: "STOPnik additionally listens with TLS when an address is configured.",
					Fields: []staticField{
						fullWidth(withDefault("Address", "Address STOPnik listens to with TLS.", server.TLS.Addr, "Disabled")),
						textField("Certificate", "Certificate file.", server.TLS.Keys.Cert),
						textField("Key", "Key file of the certificate.", server.TLS.Keys.Key),
					},
				},
			},
		},
		{
			Name:    "forward-auth",
			Title:   "Forward auth",
			Summary: forwardAuthSummary(staticConfig),
			State:   enabledState(staticConfig.GetForwardAuthEnabled()),
			Groups: []staticGroup{
				{
					Title:       "General",
					Description: "Authentication for applications behind a reverse proxy like Traefik.",
					Fields: []staticField{
						fullWidth(toggle("Forward auth", "Requires an external URL.", staticConfig.GetForwardAuthEnabled())),
						fullWidth(textField("External URL", "URL under which STOPnik is reachable through the reverse proxy.", forwardAuth.ExternalUrl)),
						withDefault("Endpoint", "Endpoint called by the reverse proxy.", forwardAuth.Endpoint, staticConfig.GetForwardAuthEndpoint()),
						withDefault("Parameter name", "Query parameter used during forward auth.", forwardAuth.ParameterName, staticConfig.GetForwardAuthParameterName()),
					},
				},
				{
					Title:       "Redirects",
					Description: "Allowed redirects after a login.",
					Fields: []staticField{
						listField("Redirect URIs", "A trailing * allows all paths below.", forwardAuth.Redirects),
					},
				},
			},
		},
		{
			Name:    "ui",
			Title:   "User interface",
			Summary: cmp.Or(ui.Title, "Default appearance"),
			Groups: []staticGroup{
				{
					Title:       "Texts",
					Description: "Texts shown on the login page.",
					Fields: []staticField{
						textField("Title", "Shown above the login form.", ui.Title),
						textField("HTML title", "Shown in the browser tab.", ui.HtmlTitle),
						fullWidth(withDefault("Footer text", "", ui.FooterText, staticConfig.GetFooterText())),
						withDefault("Invalid credentials", "Message after a failed login.", ui.InvalidCredentialsMessage, staticConfig.GetInvalidCredentialsMessage()),
						withDefault("Expired login", "Message when the login form expired.", ui.ExpiredLoginMessage, staticConfig.GetExpiredLoginMessage()),
					},
				},
				{
					Title:       "Appearance",
					Description: "Logo and footer of the login page.",
					Fields: []staticField{
						toggle("Hide footer", "", ui.HideFooter),
						toggle("Hide logo", "", ui.HideLogo),
						fullWidth(textField("Logo image", "Replaces the STOPnik logo.", ui.LogoImage)),
					},
				},
			},
		},
		{
			Name:    "dynamic",
			Title:   "Dynamic configuration",
			Summary: dynamicSummary(staticConfig),
			State:   enabledState(dynamic.Watch),
			Groups: []staticGroup{
				{
					Title:       "Reload",
					Description: "Changed clients, users and classifications are applied without restart.",
					Fields: []staticField{
						toggle("Watch for changes", "", dynamic.Watch),
						interval,
					},
				},
				{
					Title:       "Directories",
					Description: "Managed by this admin web user interface.",
					Fields:      directories,
				},
			},
		},
	}
}

func serverSummary(staticConfig *config.Config) string {
	summary := "Listening on " + cmp.Or(staticConfig.Server.Addr, "default address")
	if basePath := staticConfig.GetBasePath(); basePath != "" {
		summary += " under " + basePath
	}
	return summary
}

func cookiesSummary(staticConfig *config.Config) string {
	if staticConfig.GetSecureCookie() {
		return "Secure cookies, only sent via HTTPS"
	}
	return "Cookies also sent without HTTPS"
}

func tlsSummary(staticConfig *config.Config) string {
	if staticConfig.Server.TLS.Addr == "" {
		return "Disabled"
	}
	return "Listening on " + staticConfig.Server.TLS.Addr
}

func forwardAuthSummary(staticConfig *config.Config) string {
	if !staticConfig.GetForwardAuthEnabled() {
		return "Disabled"
	}
	return "Enabled for " + count(len(staticConfig.Server.ForwardAuth.Redirects), "redirect")
}

func dynamicSummary(staticConfig *config.Config) string {
	if !staticConfig.Dynamic.Watch {
		return "Loaded once at start up"
	}
	return "Checked for changes every " + staticConfig.GetDynamicInterval().String()
}

func enabledState(enabled bool) string {
	if enabled {
		return "enabled"
	}
	return "disabled"
}

func textField(label string, hint string, value string) staticField {
	return staticField{Kind: fieldText, Label: label, Hint: hint, Value: value}
}

// withDefault shows the default as placeholder when no value is configured.
func withDefault(label string, hint string, value string, defaultValue string) staticField {
	field := textField(label, hint, value)
	field.Placeholder = defaultValue
	return field
}

func listField(label string, hint string, values []string) staticField {
	return staticField{Kind: fieldList, Label: label, Hint: hint, Values: values, Full: true}
}

func toggle(label string, hint string, checked bool) staticField {
	return staticField{Kind: fieldSwitch, Label: label, Hint: hint, Checked: checked}
}

func fullWidth(field staticField) staticField {
	field.Full = true
	return field
}

// optionalInt returns an empty string for 0, which means the value is not configured.
func optionalInt(value int) string {
	if value == 0 {
		return ""
	}
	return strconv.Itoa(value)
}

// count returns the number with the noun in singular or plural, e.g. 2 redirects.
func count(number int, noun string) string {
	if number == 1 {
		return "1 " + noun
	}
	return strconv.Itoa(number) + " " + noun + "s"
}
