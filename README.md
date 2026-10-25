<p align="center">
    <picture>
      <source media="(prefers-color-scheme: dark)" srcset="docs/content/assets/stopnik_250.png">
      <source media="(prefers-color-scheme: light)" srcset="docs/content/assets/stopnik_250.png">
      <img alt="STOPnik" title="STOPnik" src="docs/content/assets/stopnik_250.png">
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

The logo mascot was mostly inspired by the nice work of [gopherize.me](https://github.com/matryer/gopherize.me) and
redrawn by hand as a vector graphic with additional body and a cool hat.

![build](https://github.com/webishdev/stopnik/actions/workflows/build.yml/badge.svg)
[![report](https://goreportcard.com/badge/github.com/webishdev/stopnik)](https://goreportcard.com/report/github.com/webishdev/stopnik)

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

| Specifications                                                                                                                      | Implementation |
|:------------------------------------------------------------------------------------------------------------------------------------|:--------------:|
| [The OAuth 2.0 Authorization Framework](https://datatracker.ietf.org/doc/html/rfc6749)                                              |      Yes       | 
| [Proof Key for Code Exchange by OAuth Public Clients](https://datatracker.ietf.org/doc/html/rfc7636)                                |      Yes       |
| [OAuth 2.0 Token Introspection](https://datatracker.ietf.org/doc/html/rfc7662)                                                      |      Yes       |
| [OAuth 2.0 Token Revocation](https://datatracker.ietf.org/doc/html/rfc7009)                                                         |      Yes       |
| [JSON Web Token (JWT) Profile for OAuth 2.0 Client Authentication and Authorization Grants](https://www.rfc-editor.org/rfc/rfc7523) |      Yes       |
| [JSON Web Token (JWT)](https://datatracker.ietf.org/doc/html/rfc7519)                                                               |   Dependency   |
| [OAuth 2.0 Authorization Server Metadata](https://datatracker.ietf.org/doc/html/rfc8414)                                            |   Partially    |
| [OAuth 2.0 Device Authorization Grant](https://datatracker.ietf.org/doc/html/rfc8628)                                               |    Planned     |
| [The OAuth 2.0 Authorization Framework: Bearer Token Usage](https://datatracker.ietf.org/doc/html/rfc6750)                          |    Planned     |
| [Resource Indicators for OAuth 2.0](https://datatracker.ietf.org/doc/html/rfc8707)                                                  |    Planned     |
| [OAuth 2.0 Authorization Server Issuer Identification](https://datatracker.ietf.org/doc/html/rfc9207)                               |    Planned     |
| [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html)                                                    |   Partially    |
| [OpenID Connect Discovery 1.0](https://openid.net/specs/openid-connect-discovery-1_0.html)                                          |   Partially    |
| [OpenID Connect Session Management 1.0](https://openid.net/specs/openid-connect-session-1_0.html)                                   |    Planned     |
| [OpenID Connect Front-Channel Logout 1.0](https://openid.net/specs/openid-connect-frontchannel-1_0.html)                            |    Planned     |

## Documentation

More details about **STOPnik** can be found at https://stopnik.webish.dev/

## Run with Docker

Docker images for `linux/amd64` and `linux/arm64` are published to the GitHub Container Registry with every release.

The image expects the configuration file at `/config.yml`, e.g. to run with the [minimal configuration](minimal-config.yml)

```bash
docker run --rm -p 8080:8080 -v "$(pwd)/minimal-config.yml:/config.yml:ro" ghcr.io/webishdev/stopnik:latest
```

Prebuilt binaries for Linux, macOS and Windows can be downloaded from the [releases](https://github.com/webishdev/stopnik/releases).

## Build

Requires [Git](https://git-scm.com/), [Go >=1.27](https://go.dev/) and [Make](https://www.gnu.org/software/make/) to be installed.

To build **STOPnik** the repository should be cloned and the build command executed.

```bash
git clone https://github.com/webishdev/stopnik.git
cd stopnik
go build ./cmd/stopnik
```

And then start **STOPnik** with

```bash
./stopnik
```

By default the configuration is read from `config.yml` in the current folder, another file can be used with `./stopnik -file my-config.yml`.

Release binaries for specific platforms are built with the `Makefile` into the `bin` folder, e.g.

```bash
make build-macos-arm               # a single platform, see make help for all of them
make build-all VERSION=v1.0.0      # all supported platforms
```

All available targets are listed with `make help`.

## Test

Execute tests inside the repository root folder with

```bash
make test
```

To get access to the HTML coverage report execute

```bash
make coverage
```

The coverage report will be created in the `.test_coverage` folder.

## Lint

The code is checked with [golangci-lint](https://golangci-lint.run/), which is managed as a Go tool in `go.mod`, so no separate installation is needed.

```bash
make lint
```

## Release

Releases are created by publishing a new release with a `vX.Y.Z` tag on GitHub.
The [release workflow](.github/workflows/release.yml) then runs the tests and linter, builds the binaries for all platforms,
pushes the Docker images and attaches the archives with their `SHA256SUMS` to the release.

## License

The project is licensed under the [Apache License, Version 2.0](LICENSE).
