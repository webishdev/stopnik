---
sidebar_position: 2
---
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

## OAuth 2.0

### The OAuth 2.0 Authorization Framework

[The OAuth 2.0 Authorization Framework](https://datatracker.ietf.org/doc/html/rfc6749)

- `/authorize`
- `/token`

### OAuth 2.0 Token Introspection

[OAuth 2.0 Token Introspection](https://datatracker.ietf.org/doc/html/rfc7662)

- `/introspect`

### OAuth 2.0 Token Revocation 

[OAuth 2.0 Token Revocation](https://datatracker.ietf.org/doc/html/rfc7009)

- `/revoke`

### OAuth 2.0 Authorization Server Metadata

[OAuth 2.0 Authorization Server Metadata](https://datatracker.ietf.org/doc/html/rfc8414)

- `/.well-known/oauth-authorization-server`
- `/keys`

## OpenId Connect

### OpenID Connect Discovery 1.0

[OpenID Connect Discovery 1.0](https://openid.net/specs/openid-connect-discovery-1_0.html)

- `/.well-known/openid-configuration`
- `/keys`

### OpenID Connect Core 1.0

[OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html)

- `/userinfo`