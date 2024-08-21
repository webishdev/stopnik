# Stopnik Notes

Just a few notes taken during development

[OAuth 2.0 Specification, RFC6749](https://datatracker.ietf.org/doc/html/rfc6749)

## Good websites

- [OAuth 2.x and OpenID Connect sequence diagrams](https://www.gabriel.urdhr.fr/2023/02/06/oauth2-diagrams)
- [Diagrams of All The OpenID Connect Flows](https://darutk.medium.com/diagrams-of-all-the-openid-connect-flows-6968e3990660)

## Create private keys and self-signed certificates

See https://superuser.com/a/226229

```bash
openssl req -new -newkey rsa:4096 -days 365 -nodes -x509 -subj "/C=DE/ST=NRW/L=Dortmund/O=STOPnik/CN=www.example.com" -keyout www.example.com.key -out www.example.com.cert
```

```bash
openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -days 365 -nodes -x509 -subj "/C=DE/ST=NRW/L=Dortmund/O=STOPnik/CN=www.example.com" -keyout www.example.com.key -out www.example.com.cert
```

### RSA
```bash
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out rsakey.pem
```

```bash
openssl ecparam -name prime256v1 -genkey -noout -out ecdsakey.pem
```

## OAuth 2.0 Endpoints

### [Authorization Endpoint](https://datatracker.ietf.org/doc/html/rfc6749#section-3.1)

#### Request
- Endpoint URL is out of scope, can be chosen by the implementation
- How identity of the user (resource owner) is validated is up to the implementation
- **MUST** support `GET`, **MAY** support `POST`
- Unknown parameters are skipped
- Request and response parameters **MUST NOT** not be included more then once
- Query of the URL (after `?` before `#`) **MAY** be `application/x-www-form-urlencoded` encoded
- `response_type` is a required URL parameter, which is an enumeration of `code` (authorization code grant) or `token` (implicit grant)
- **SHOULD** be TLS

##### Authorization Code Grant
| Query parameter | Required | Comment |
| --- | --- | --- |
| response_type | ☑️ | value is `code` |
| client_id | ☑️ | |
| redirect_uri | ✖️ | |
| scope | ✖️ | |
| state | ✖️ | |
| code_challenge | ✖️ | PKCE |
| code_challenge_method | ✖️ | PKCE |

##### Authorization Code Grant
| Query parameter | Required | Comment |
| --- | --- | --- |
| response_type | ☑️ | value is `code` |
| client_id | ☑️ | |
| redirect_uri | ✖️ | |
| scope | ✖️ | |
| state | ✖️ | |
| code_challenge | ✖️ | PKCE |
| code_challenge_method | ✖️ | PKCE |

#### Response (after login)
- After successfully verifying the identity of the user (resource owner), the implementation redirects to either the configured (in some configuration) or provided (with `redirect_uri` parameter) URL
- The URL for redirection is absolute
- Redirect with `Location` header

#### Flow
- HTTP `GET` /authorize (OAuth Authorization Request)
- Show HTML page to login
- HTTP `POST` the login credentials (where ever the implementation needs to)
- HTTP 302? response to redirect with `Location` header (OAuth Authorization Response)

### [Token Endpoint](https://datatracker.ietf.org/doc/html/rfc6749#section-3.2)
