<p align="center">
    <picture>
      <img alt="STOPnik" title="STOPnik" src="docs/content/assets/stopnik_250.png">
    </picture>
</p>

# STOPnik

The simple and small `OAuth2 | OpenId Connect` server that secures applications without hassle.

**STOPnik** does not have any persistence layer and will only work in-memory with the clients and users defined in the configuration file (`YAML`).
When restarted, all issued tokens will become invalid/forgotten by **STOPnik**.

This project was used to learn [OAuth 2.0](https://datatracker.ietf.org/doc/html/rfc6749), [OpenId Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0-final.html) and [Go](https://go.dev/).

![build](https://github.com/giftkugel/stopnik/actions/workflows/build.yml/badge.svg)

## STOPnik alternatives with persistence layer

The awesome work of other servers is very appreciated, most of them were the inspiration for this small project! ♥️

- [dex](https://github.com/dexidp/dex)
- [Keycloak](https://github.com/keycloak/keycloak)
- [ORY Hydra](https://github.com/ory/hydra)
- [authentik](https://github.com/goauthentik/authentik)
- [ZITADEL](https://github.com/zitadel/zitadel)
- [Spring authorization server](https://github.com/spring-projects/spring-authorization-server)
- [Node OIDC provider](https://github.com/panva/node-oidc-provider)
