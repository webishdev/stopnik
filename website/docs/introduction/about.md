# About
 
**STOPnik** is a small, fast and secure authorization server with an minimal amount of dependencies.

### Dependencies

Currently, **STOPnik** only depends on

- [github.com/google/uuid v1.6.0](https://pkg.go.dev/github.com/google/uuid@v1.6.0)
- [github.com/lestrrat-go/jwx/v2  v2.1.1](https://pkg.go.dev/github.com/lestrrat-go/jwx/v2@v2.1.1)
- [gopkg.in/yaml.v3 v3.0.1](https://pkg.go.dev/gopkg.in/yaml.v3@v3.0.1)

## Related specifications

| RFC                                                                                                                                 | Implementation |
|:------------------------------------------------------------------------------------------------------------------------------------|:--------------:|
| [The OAuth 2.0 Authorization Framework](https://datatracker.ietf.org/doc/html/rfc6749)                                              |      Yes       | 
| [Proof Key for Code Exchange by OAuth Public Clients](https://datatracker.ietf.org/doc/html/rfc7636)                                |      Yes       |
| [OAuth 2.0 Token Introspection](https://datatracker.ietf.org/doc/html/rfc7662)                                                      |      Yes       |
| [OAuth 2.0 Token Revocation](https://datatracker.ietf.org/doc/html/rfc7009)                                                         |      Yes       |
| [JSON Web Token (JWT) Profile for OAuth 2.0 Client Authentication and Authorization Grants](https://www.rfc-editor.org/rfc/rfc7523) |      Yes       |
| [JSON Web Token (JWT)](https://datatracker.ietf.org/doc/html/rfc7519)                                                               |   Dependency   |
| [OAuth 2.0 Authorization Server Metadata](https://datatracker.ietf.org/doc/html/rfc8414)                                            |    Planned     |
| [OAuth 2.0 Device Authorization Grant](https://datatracker.ietf.org/doc/html/rfc8628)                                               |    Planned     |
| [Resource Indicators for OAuth 2.0](https://datatracker.ietf.org/doc/html/rfc8707)                                                  |    Planned     |
| [OAuth 2.0 Authorization Server Issuer Identification](https://datatracker.ietf.org/doc/html/rfc9207)                               |    Planned     |
| [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html)                                                    |    Planned     |
| [OpenID Connect Discovery 1.0](https://openid.net/specs/openid-connect-discovery-1_0.html)                                          |    Planned     |
| [OpenID Connect Session Management 1.0](https://openid.net/specs/openid-connect-session-1_0.html)                                   |    Planned     |
| [OpenID Connect Front-Channel Logout 1.0](https://openid.net/specs/openid-connect-frontchannel-1_0.html)                            |    Planned     |

## Why STOPnik exists?

In general this project was started to learn [OAuth2](https://datatracker.ietf.org/doc/html/rfc6749), [OpenId Connect](https://openid.net/specs/openid-connect-core-1_0.html) and [Go](https://go.dev/).
Furthermore, it was also created to be used in a Homelab and VPS to replace the current Keycloak,
which adds too much load to the VPS and has to many configuration possibilities.

**STOPnik** does not have any persistence layer and will only work in-memory with the clients and users defined in the
configuration file (`YAML`).
When restarted, all issued tokens will become invalid/forgotten by **STOPnik**.

You still may consider using another authorization server.

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