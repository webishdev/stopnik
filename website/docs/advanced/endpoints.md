# Endpoints

**STOPnik** provides the following endpoints

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

- an authorization code can only be redeemed once, by the client it was issued to and with the same `redirect_uri` used for the authorization request
- when a `code_challenge` was provided, the `code_verifier` is required, public clients must use [PKCE](https://datatracker.ietf.org/doc/html/rfc7636)
- refresh tokens are rotated, each refresh token can only be used once and a new refresh token is returned
- tokens of the implicit grant are returned in the fragment of the redirect URI, not in the query
- request objects (`request` parameter) are not supported and rejected with `request_not_supported`

### OAuth 2.0 Token Introspection

[RFC 7662](https://datatracker.ietf.org/doc/html/rfc7662)

- `/introspect`

### OAuth 2.0 Token Revocation 

[RFC 7009](https://datatracker.ietf.org/doc/html/rfc7009)

- `/revoke`

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