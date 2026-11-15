# Configuration

**STOPnik** configuration is split into a static and a dynamic part, both written in [TOML](https://toml.io/).

- The **static configuration** contains the [`server`](#server-configuration) and [`ui`](#user-interface-configuration) settings.
  It is loaded, validated and applied once while **STOPnik** starts. Changes require a restart.
- The **dynamic configuration** contains [clients](#clients), [users](#users) and [classifications](#classification).
  Each entry is a single TOML file inside the folders `client.d`, `user.d` and `classification.d`.

By default **STOPnik** will use the configuration directory `.config/default` relative to the working directory,
another directory can be used with the [`-config-dir`](../advanced/cmd.md#configuration-directory) parameter.
The configuration directory contains the static configuration file `config.toml`
and the dynamic configuration folders `client.d`, `user.d` and `classification.d`, e.g.

```
.config/default/
├── config.toml
├── client.d/
│   └── testclient.toml
├── user.d/
│   └── foo.toml
└── classification.d/
    └── foo-testclient.toml
```

The possible configuration options are listed in the next sections.

## Dynamic configuration

All `*.toml` files inside the dynamic configuration folders are loaded during start up, in alphabetical order.
Every file is loaded and validated on its own, including referenced private keys of clients.

- A valid file is applied.
- An invalid file is skipped and a warning is logged, all other files are still applied.
- When a client id or username is defined in more than one file, the first file wins and the other ones are skipped.

When `watch` is enabled in the [`dynamic`](#dynamic-configuration-settings) settings, the folders are checked for changes,
by default every 2 seconds.

- A new or changed file is loaded, validated and applied, existing sessions and tokens stay valid.
- When a changed file becomes invalid, a warning is logged and the previously loaded entry stays active.
- When a file is removed, its entry is removed as well.

So to add a new user, just create a new TOML file in `user.d`.

:::warning

As **STOPnik** is under heavy development right now, the configuration may change.

:::

## Static configuration file

The static configuration file (`config.toml` inside the configuration directory) may contain different root options which are described here as followed

| Property                                         | Description                          | Required |
|--------------------------------------------------|--------------------------------------|----------|
| [`server`](#server-configuration)                | Server configuration                 | Yes      |
| [`ui`](#user-interface-configuration)            | User interface configuration         | No       |
| [`dynamic`](#dynamic-configuration-settings)     | Dynamic configuration settings       | No       |

### Server configuration

Root entry named `server`

| Property                      | Description                                                                                       | Required |
|-------------------------------|---------------------------------------------------------------------------------------------------|----------|
| `logLevel`                    | Log level                                                                                         | No       |
| `addr`                        | [Go like address](https://pkg.go.dev/net#Dial), may contain IP and port                           | Yes      |
| `basePath`                    | Path prefix for all endpoints, see [Base path](#base-path)                                        | No       |
| [`cookies`](#cookies)         | Configuration related to cookie names                                                             | No       |
| `secureCookie`                | Only send cookies via HTTPS, defaults to `true`                                                   | No       |
| `secret`                      | Server secret, see [Keys and secret](#keys-and-secret)                                            | No       |
| `privateKey`                  | General RSA or EC private key (can be overwritten for each client) to sign tokens                 | No       |
| [`tls`](#tls)                 | Configuration for TLS                                                                             | No       |
| `logoutRedirect`              | Where to redirect user after logout                                                               | No       |
| `introspectScope`             | Scope which allows token introspection                                                            | No       |
| `revokeScopeScope`            | Scope which allows token revocation                                                               | No       |
| `sessionTimeoutSeconds`       | Seconds until session will end                                                                    | No       |
| `issuer`                      | External URL of **STOPnik**, see [Issuer](#issuer)                                                | Yes      |
| [`forwardAuth`](#forwardauth) | [Traefik ForwardAuth](https://doc.traefik.io/traefik/middlewares/http/forwardauth/) configuration | No       |

#### Issuer

The issuer is the external URL of **STOPnik** as seen by clients, e.g. `https://auth.example.com`.
It is used as `iss` value in tokens and all URLs in the metadata endpoints are derived from it.
The issuer is never derived from the `Host` header of a request, as it can be manipulated by a client.

- `issuer` is required, **STOPnik** does not start without it.
- It must be an absolute URL with the scheme `https` or `http`, without query, fragment or user information.
- `http` is meant for local development, for other hosts than `localhost`, `127.0.0.1` and `[::1]`
  **STOPnik** logs a warning on startup.

The configured `issuer` is used as it is.
When a [base path](#base-path) is configured, the endpoint URLs are `issuer` + endpoint path when the `issuer` already ends with
the base path (e.g. `https://example.com/auth/token`), and `issuer` + base path + endpoint path otherwise.

#### Keys and secret

Access, refresh and ID tokens are always signed with a private key, never with the server `secret`,
so every token can be verified with a public key from the `/keys` endpoint.

- A client with its own `privateKey` uses this key.
- All other clients use the server `privateKey`.
- When no server `privateKey` is configured, **STOPnik** generates an ephemeral ECDSA P-256 key on startup
  and logs a warning. Tokens signed with it become invalid after a restart, so configure `privateKey` for production.

The discovery endpoint only advertises the signature algorithms of the loaded keys.

The `secret` is only used to protect cookies and the login form, separate keys are derived from it for each purpose.
When no `secret` is configured, a random secret is generated on every start, which invalidates all sessions after a restart.

#### Base path

With `basePath` all endpoints are served below the given path, e.g. with `basePath: /auth`
the account page is available at `/auth/account` and the OIDC discovery at `/auth/.well-known/openid-configuration`.
This allows running **STOPnik** behind a reverse proxy on a sub path, without stripping the prefix in the proxy.

The URLs in the metadata endpoints (see [Issuer](#issuer)) and the `/authorize` URL used for [ForwardAuth](#forwardauth) contain the base path,
the cookies of **STOPnik** are restricted to the base path.
The ForwardAuth cookie is still set for `/`, as it is used for the protected application.

When `basePath` is not set or set to `/`, all endpoints are served from the root path.

#### Secure cookies

By default, all cookies are marked as `Secure` and will only be sent by browsers via HTTPS (and for `localhost`).
Set `secureCookie: false` only for local development via plain HTTP on other hosts than `localhost`.

#### TLS

Public and private keys to sign tokens

Entry `server.tls`

| Property            | Description                                                             | Required |
|---------------------|-------------------------------------------------------------------------|----------|
| `addr`              | [Go like address](https://pkg.go.dev/net#Dial), may contain IP and port | Yes      |
| [`keys`](#tls-keys) | Public and private keys for TLS                                         | Yes      |

##### TLS keys

Public and private keys for TLS

Entry `server.tls.keys`

| Property | Description      | Required |
|----------|------------------|----------|
| `cert`   | Certificate file | Yes      |
| `key`    | Key file         | Yes      |

#### Cookies

Public and private keys to sign tokens

Entry `server.cookies`

| Property          | Description                                         | Required |
|-------------------|-----------------------------------------------------|----------|
| `authName`        | Name of the authorization cookie                    | No       |
| `messageName`     | Name of internal message cookie                     | No       |
| `forwardAuthName` | Name of internal [ForwardAuth](#forwardauth) cookie | No       |

#### ForwardAuth

**STOPnik** supports [Traefik ForwardAuth](https://doc.traefik.io/traefik/middlewares/http/forwardauth/) out of the box.

Entry `server.forwardAuth`

| Property        | Description                                         | Required |
|-----------------|-----------------------------------------------------|----------|
| `enabled`       | Whether to enable ForwardAuth or not                | No       |
| `endpoint`      | Internal endpoint to be called by Traefik           | No       |
| `externalUrl`   | URL of **STOPnik** to redirect the user for a login | No       |
| `parameterName` | URL parameter used by **STOPnik** for ForwardAuth   | No       |
| `redirects`     | List of redirects URIs, see below                   | No       |

ForwardAuth redirects the user back to the originally requested URL of the protected application,
so the `redirects` of ForwardAuth are matched differently than the [redirects of clients](#redirects).

- Scheme and host (including the port) must match exactly, the query is ignored.
- A redirect ending with `*` matches the path before the `*` and everything below it,
  e.g. `https://app.example.com/app/*` matches `/app/` and `/app/page`, but not `/application`.
- Paths containing `.` or `..` segments, encoded dots or slashes (`%2e`, `%2f`) or backslashes are rejected.

:::warning

The ForwardAuth endpoint trusts the `X-Forwarded-Proto`, `X-Forwarded-Host` and `X-Forwarded-Uri` headers.
Make sure the endpoint is only reachable through Traefik and not directly by clients.

:::

### User interface configuration

Root entry named `ui`

| Property                    | Description                             | Required |
|-----------------------------|-----------------------------------------|----------|
| `hideFooter`                | Will hide the **STOPnik** footer        | No       |
| `hideLogo`                  | Will hide the **STOPnik** logo          | No       |
| `htmlTitle`                 | HTML page title                         | No       |
| `title`                     | Title displayed above the forms         | No       |
| `footerText`                | The footer text                         | No       |
| `logoImage`                 | Path of additional logo image           | No       |
| `invalidCredentialsMessage` | Message to show for invalid credentials | No       |
| `expiredLoginMessage`       | Message to show when login expired      | No       |

### Dynamic configuration settings

Root entry named `dynamic`

| Property   | Description                                         | Required |
|------------|-----------------------------------------------------|----------|
| `watch`    | Watch the dynamic configuration folders for changes | No       |
| `interval` | Seconds between checks for changes, defaults to `2` | No       |

The dynamic configuration folders are always `client.d`, `user.d` and `classification.d` inside the configuration directory.

```toml
[dynamic]
watch = true
interval = 5
```

## Dynamic configuration files

### Clients

Each file inside `client.d` defines exactly one client, e.g. `client.d/testclient.toml`

```toml
id = "testclient"
clientSecret = "$2a$10$xchSl0M6Yk43/6Lvvqzx5..sWJcgOp1wCPYUOVPGW4XBh.duYU4I6"
redirects = ["https://oauth.pstmn.io/v1/callback"]
```

A client file may contain the following options

| Property                  | Description                                             | Required |
|---------------------------|---------------------------------------------------------|----------|
| `id`                      | The id of the client                                    | Yes      |
| `clientSecret`            | bcrypt or SHA512 hashed secret                          | No       |
| `salt`                    | Optional salt, only used for SHA512 hashed secrets      | No       |
| `oidc`                    | Flag to allow an client to handle OpenId Connect        | No       |
| `accessTTL`               | Access token time to live                               | No       |
| `refreshTTL`              | Refresh token time to live                              | No       |
| `idTTL`                   | OpenId Connect ID token time to live                    | No       |
| `introspect`              | Introspection scope                                     | No       |
| `revoke`                  | Revocation scope                                        | No       |
| `redirects`               | List of redirects URIs, see [Redirects](#redirects)     | Yes      |
| `opaqueToken`             | Use opaque token                                        | No       |
| `passwordFallbackAllowed` | Form auth allowed                                       | No       |
| `audience`                | Audience                                                | No       |
| `privateKey`              | RSA or EC private key to sign tokens                    | No       |
| `scopes`                  | List of scopes the client is allowed to request         | No       |
| `grantTypes`              | List of grant types the client is allowed to use        | No       |

For `clientSecret` and `salt` see, [Command line - Password](../advanced/cmd.md#password)

If no `clientSecret` is provided, the client is handled as public client, otherwise it will become a confidential client.

The OpenId Connect endpoints (discovery and user info) are only available while at least one loaded client has `oidc` enabled.
Public clients must use [PKCE](https://datatracker.ietf.org/doc/html/rfc7636) for the authorization code grant.

#### Redirects

The `redirect_uri` of an authorization request must be identical to one of the configured `redirects`,
as required by [RFC 9700](https://datatracker.ietf.org/doc/html/rfc9700#section-2.1).
This includes the query, a trailing slash and upper and lower case. Wildcards are not supported.

- A redirect must be an absolute URL with scheme and host.
- A redirect must not contain a `*`, a fragment or user information, such a client is rejected as invalid.
- For redirects to the loopback addresses `http://127.0.0.1` and `http://[::1]` the port is ignored,
  as described in [RFC 8252](https://datatracker.ietf.org/doc/html/rfc8252#section-7.3). This does not apply to `localhost`.

#### Scopes

When `scopes` is not configured, a client may only request its default scopes.

- A client with `oidc` enabled may request the OpenId Connect scopes
  `openid`, `profile`, `email`, `address`, `phone` and `offline_access`.
- All other clients may not request any scope.

When `scopes` is configured, a client may only request the listed scopes, the default scopes are no longer applied.
So do not forget to list scopes like `openid` or `offline_access` when using OpenId Connect.
The reserved scopes for token introspection and revocation (`server.introspectScope`, `server.revokeScopeScope`,
by default `stopnik:introspect` and `stopnik:revoke`) always have to be listed explicitly.

Requests for scopes which are not allowed are rejected with `invalid_scope`.

#### Grant types

When `grantTypes` is not configured, a client may only use the grant types `authorization_code` and `refresh_token`.

When `grantTypes` is configured, a client may only use the listed grant types.
Possible values are `authorization_code`, `implicit`, `password`, `client_credentials` and `refresh_token`.
Public clients can never use `client_credentials`.

The grant types `implicit` and `password` are deprecated and removed in OAuth 2.1,
**STOPnik** logs a warning for each client which lists them.

Requests for grant types which are not allowed are rejected with `unauthorized_client`.

The metadata endpoints list the grant types and response types, which at least one of the loaded clients is allowed to use.

### Users

Each file inside `user.d` defines exactly one user, e.g. `user.d/foo.toml`

```toml
username = "foo"
password = "$2a$10$xchSl0M6Yk43/6Lvvqzx5..sWJcgOp1wCPYUOVPGW4XBh.duYU4I6"

[userProfile]
givenName = "John"
familyName = "Doe"
```

A user file may contain the following options

| Property                               | Description                                                     | Required |
|----------------------------------------|-----------------------------------------------------------------|----------|
| `username`                             | Username                                                        | Yes      |
| `password`                             | bcrypt or SHA512 hashed password                                | Yes      |
| `salt`                                 | Optional salt, only used for SHA512 hashed passwords            | No       |
| `admin`                                | Allows the user to sign in to the admin web user interface      | No       |
| [`userProfile`](#user-profile)         | User profile which will be used for OpenId Connect UserInfo     | No       |
| [`userInformation`](#user-information) | User information which will be used for OpenId Connect UserInfo | No       |

For `password` and `salt` see, [Command line - Password](../advanced/cmd.md#password)

The `admin` property is only used by the [admin web user interface](../advanced/cmd.md#admin-web-user-interface),
**STOPnik** itself ignores it.

After 10 failed login attempts within 5 minutes, further logins for the username are blocked for the rest of the 5 minutes.
The same applies to failed client authentications for a client id.

#### User profile

User profile which will be used for OpenId Connect UserInfo

Entry `userProfile`

Each entry may contain the following options

| Property            | Description         | Required |
|---------------------|---------------------|----------|
| `givenName`         | Given name          | No       |
| `familyName`        | Family name         | No       |
| `nickname`          | Nickname            | No       |
| `preferredUserName` | Preferred username  | No       |
| `gender`            | Gender              | No       |
| `birthDate`         | Birthdate           | No       |
| `zoneInfo`          | Zone information    | No       |
| `locale`            | locale              | No       |
| `website`           | Website URL         | No       |
| `profile`           | Profile URL         | No       |
| `picture`           | Profile picture URL | No       |

#### User information

User information which will be used for OpenId Connect UserInfo

Entry `userInformation`

Each entry may contain the following options

| Property                   | Description                      | Required |
|----------------------------|----------------------------------|----------|
| `email`                    | E-Mail address                   | No       |
| `emailVerified`            | E-Mail address verification flag | No       |
| `phoneNumber`              | Phone number                     | No       |
| `phoneVerified`            | Phone number verification flag   | No       |
| [`address`](#user-address) | User address                     | No       |

#### User address

User address which will be used for OpenId Connect UserInfo

Entry `userInformation.address`

Each entry may contain the following options

| Property     | Description | Required |
|--------------|-------------|----------|
| `street`     | Street      | No       |
| `city`       | City        | No       |
| `postalCode` | Postal code | No       |
| `region`     | Region      | No       |
| `country`    | Country     | No       |

### Classification

Each file inside `classification.d` defines exactly one classification, e.g. `classification.d/foo-testclient.toml`

```toml
user = "foo"
client = "testclient"

[[claims]]
name = "role"
values = ["admin", "user"]
```

A classification entry allows to add specific claims to access token (if is a JWT), to ID token and to the user info endpoint described in [OpenID Connect Core 1.0](../advanced/endpoints.md#openid-connect-core-10)

When `scope` or `scopes` are used, the listed `claims` will only be returned if the scope was requested.

A classification file may contain the following options

| Property            | Description       | Required |
|---------------------|-------------------|----------|
| `user`              | A specific user   | No       |
| `users`             | List of users     | No       |
| `client`            | A specific client | No       |
| `clients`           | List of clients   | No       |
| `scope`             | A specific scope  | No       |
| `scopes`            | List of scopes    | No       |
| [`claims`](#claims) | List of claims    | No       |

The options for `user` + `users`, `client` + `clients`, `scope` + `scopes` will be merged into one specific list.

So the single value may be considered as shortcut, if you do not need a list at all.

Values for `user` + `users`, `client` + `clients`, `scope` + `scopes` will be used in a distinct manner.

#### Claims

List of client claims

Entry `claims`

Each entry may contain the following options

| Property | Description      | Required                  |
|----------|------------------|---------------------------|
| `name`   | Name             | Yes                       |
| `scope`  | A specific scope | No                        |
| `scopes` | List of scopes   | No                        |
| `value`  | A specific value | Yes, if `values` not used |
| `values` | List of value    | Yes, if `value` not used  |

The options for `scope` + `scopes` will be merged into one list.

So the single value may be considered as shortcut, if you do not need a list at all.

Values for `scope` + `scopes` will be used in a distinct manner.

When claim scopes are used, the listed claims will only be returned if the scope was requested.

If the parent classification has set scopes the scopes are used in addition to the claim scopes.

## Examples

### Minimal configuration

The minimal configuration only defines the HTTP port **STOPnik** should listen on, the issuer, one client and one user.

It can be found in the repository at

https://github.com/webishdev/stopnik/tree/main/.config/minimal

Client secret and user password are both the bcrypt hash for `bar`.

After starting locally with this configuration, **STOPnik** will be accessible at

- http://localhost:8080/account
- http://localhost:8080/health

`.config/minimal/config.toml`

```toml
[server]
addr = ":8080"
issuer = "http://localhost:8080"
```

`.config/minimal/client.d/testclient.toml`

```toml
id = "testclient"
clientSecret = "$2a$10$xchSl0M6Yk43/6Lvvqzx5..sWJcgOp1wCPYUOVPGW4XBh.duYU4I6"
redirects = ["https://oauth.pstmn.io/v1/callback"]
```

`.config/minimal/user.d/foo.toml`

```toml
username = "foo"
password = "$2a$10$xchSl0M6Yk43/6Lvvqzx5..sWJcgOp1wCPYUOVPGW4XBh.duYU4I6"
```

### Development configuration

The configuration used during development can be found in the repository.

https://github.com/webishdev/stopnik/tree/main/.config/default

This configuration uses self-singed TLS certificates, keys and a privates key located in the `.test_files` folder
and watches the dynamic configuration for changes.

Further examples are available in `.config/oidc-conformance` (used for the OpenID Connect conformance tests) and `.config/exoknox`.
