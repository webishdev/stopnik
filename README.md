
<p align="center">
    <picture>
      <source media="(prefers-color-scheme: dark)" srcset="docs/content/assets/stopnik_250.png">
      <source media="(prefers-color-scheme: light)" srcset="docs/content/assets/stopnik_250.png">
      <img alt="STOPnik" title="Traefik" src="docs/content/assets/stopnik_250.png">
    </picture>
</p>

# STOPnik

The simple and small `OAuth2 | OpenId Connect` server that secures applications without hassle.

**STOPnik** does not have any persistence layer and will only work in-memory with the clients and users defined in the
configuration file (`YAML`).
When restarted, all issued tokens will become invalid/forgotten by **STOPnik**.

This project was used to
learn [OAuth 2.0](https://datatracker.ietf.org/doc/html/rfc6749), [OpenId Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0-final.html)
and [Go](https://go.dev/).

The logo mascot was mostly inspired by the nice work of [gopherize.me](https://github.com/matryer/gopherize.me) and redrawn by hand as a vector graphic with additional body and a cool hat.

![build](https://github.com/giftkugel/stopnik/actions/workflows/build.yml/badge.svg)

## STOPnik alternatives

The awesome work of other servers is very appreciated, most of them were the inspiration for this small project! ♥️

They add features like persistence and access to user directories like LDAP.

- [dex](https://github.com/dexidp/dex)
- [Keycloak](https://github.com/keycloak/keycloak)
- [ORY Hydra](https://github.com/ory/hydra)
- [authentik](https://github.com/goauthentik/authentik)
- [ZITADEL](https://github.com/zitadel/zitadel)
- [Spring authorization server](https://github.com/spring-projects/spring-authorization-server)
- [Node OIDC provider](https://github.com/panva/node-oidc-provider)

## Related specifications

| RFC                                                                                                  | Implementation |
|:-----------------------------------------------------------------------------------------------------|:--------------:|
| [The OAuth 2.0 Authorization Framework](https://datatracker.ietf.org/doc/html/rfc6749)               |      Yes       | 
| [Proof Key for Code Exchange by OAuth Public Clients](https://datatracker.ietf.org/doc/html/rfc7636) |      Yes       |
| [OAuth 2.0 Token Introspection](https://datatracker.ietf.org/doc/html/rfc7662)                       |      Yes       |
| [OAuth 2.0 Token Revocation](https://datatracker.ietf.org/doc/html/rfc7009)                          |      Yes       |
| [JSON Web Token (JWT)](https://datatracker.ietf.org/doc/html/rfc7519)                                | By dependency  |
| [OAuth 2.0 Device Authorization Grant](https://datatracker.ietf.org/doc/html/rfc8628)                |    Planned     |
| [Resource Indicators for OAuth 2.0](https://datatracker.ietf.org/doc/html/rfc8707)                   |    Planned     |
| [OAuth 2.0 Authorization Server Issuer Identification](https://datatracker.ietf.org/doc/html/rfc9207) | Planned |