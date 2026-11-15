# Endpoints

**STOPnik** provides the following endpoints.
When `server.basePath` is configured, all endpoints are prefixed with it, e.g. `/auth/account`.

## STOPnik

### Account

This endpoint will provide a login or logout form.

- `/account`

### Logout

This endpoint will logout the current user and redirect when a redirect is configured.

A redirect provided by the logout form is only used, when it is a path on **STOPnik** itself,
otherwise the configured `server.logoutRedirect` is used.

- `/logout`

### Health

This endpoint will return a `JSON` which either contains only a `ping` - `pong` or additional user details.

User details are only provided when the health endpoint is called with a valid access token.

- `/health`

### ForwardAuth

**STOPnik** supports [Traefik ForwardAuth](https://doc.traefik.io/traefik/middlewares/http/forwardauth/) out of the box.

This endpoint depends on the provided configuration and is only available when `server.forwardAuth.externalUrl` is set.

The endpoint must only be reachable through Traefik, as it trusts the `X-Forwarded-*` headers.

- `/forward`

## OAuth 2.0

### The OAuth 2.0 Authorization Framework

[RFC 6749](https://datatracker.ietf.org/doc/html/rfc6749)

- `/authorize`
- `/token`

Following the [OAuth 2.0 Security Best Current Practice](https://datatracker.ietf.org/doc/html/rfc9700)

- an authorization code is a random value created after the login, it expires after 60 seconds and can only be redeemed once,
  by the client it was issued to and with the same `redirect_uri` used for the authorization request
- when an authorization code is redeemed again, all tokens issued for it are revoked
- [PKCE](https://datatracker.ietf.org/doc/html/rfc7636) with the method `S256` is required by default, see [PKCE](../introduction/config.md#pkce)
- refresh tokens are rotated, each refresh token can only be used once and a new refresh token is returned
- when a used refresh token is presented again, all access and refresh tokens of the same authorization are revoked
- a refresh token can only be used by the client it was issued to, the optional `scope` parameter may narrow the original scope
- the authorization endpoint only creates the tokens the `response_type` needs, the implicit and the client credentials
  grant never issue refresh tokens
- tokens of the implicit grant are returned in the fragment of the redirect URI, not in the query
- the supported `response_type` values are `code`, `token`, `id_token` and `id_token token`,
  hybrid flows like `code id_token` and duplicate values are rejected with `unsupported_response_type`
- `id_token` and `id_token token` require a client with `oidc` enabled, the `openid` scope and a `nonce`,
  for `id_token token` the ID token contains the `at_hash` of the access token
- request objects (`request` parameter) are not supported and rejected with `request_not_supported`

Errors of the token endpoint follow [RFC 6749](https://datatracker.ietf.org/doc/html/rfc6749#section-5.2),
a failed client authentication with HTTP Basic is answered with `401` and `WWW-Authenticate: Basic realm="STOPnik"`.
Token responses are sent with `Cache-Control: no-store` and `Pragma: no-cache`.

### OAuth 2.0 Token Introspection

[RFC 7662](https://datatracker.ietf.org/doc/html/rfc7662)

- `/introspect`

A failed authentication is answered with `401` and `invalid_client`, an access token without the introspect scope with `403` and `insufficient_scope`.

Introspection is allowed for

- confidential clients with `introspect` enabled, they may introspect tokens of all clients,
  public clients are rejected with `401` and clients without `introspect` with `403`
- access tokens containing the introspect scope (`server.introspectScope`)

Active tokens are returned with `scope`, `client_id`, `username`, `token_type`, `exp`, `iat`, `sub`, `aud` and `iss`.

### OAuth 2.0 Token Revocation 

[RFC 7009](https://datatracker.ietf.org/doc/html/rfc7009)

- `/revoke`

A failed authentication is answered with `401` and `invalid_client`, an access token without the revoke scope with `403` and `insufficient_scope`.

- Every client, including public clients, may revoke tokens which were issued to it, the `revoke` flag is not required.
  Requests for tokens of other clients are answered with `200`, but the token stays valid.
- Access tokens containing the revoke scope (`server.revokeScope`) of a client with `revoke` enabled
  may revoke tokens of all clients.
- Revoking a refresh token also revokes all access tokens issued for the same authorization.

### OAuth 2.0 Authorization Server Metadata

[RFC 8414](https://datatracker.ietf.org/doc/html/rfc8414)

- `/.well-known/oauth-authorization-server`
- `/keys`

## OpenId Connect

OpenId Connect endpoint are only available, when one of the clients has the `oidc` flag set.

### OpenID Connect Discovery 1.0

[OpenID Connect Discovery 1.0](https://openid.net/specs/openid-connect-discovery-1_0.html)

- `/.well-known/openid-configuration`
- `/keys`

### OpenID Connect Core 1.0

[OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html)

- `/userinfo`