# Endpoints

**STOPnik** provides the following endpoints

## STOPnik

### Account

This endpoint will provide a login or logout form.

- `/account`

### Logout

This endpoint will logout the current user and redirect when a redirect is configured.

- `/logout`

### Health

This endpoint will return a `JSON` which either contains only a `ping` - `pong` or additional user details.

User details are only provided when the health endpoint is called with a valid access token.

- `/health`

### ForwardAuth

**STOPnik** supports [Traefik ForwardAuth](https://doc.traefik.io/traefik/middlewares/http/forwardauth/) out of the box.

This endpoint depends on the provided configuration and is only available when `server.forwardAuth.externalUrl` is set.

- `/forward`

## OAuth 2.0

### The OAuth 2.0 Authorization Framework

[RFC 6749](https://datatracker.ietf.org/doc/html/rfc6749)

- `/authorize`
- `/token`

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