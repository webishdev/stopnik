---
sidebar_position: 1
---
# Why STOPnik exists?

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