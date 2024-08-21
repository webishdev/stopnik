---
sidebar_position: 3
---
# Configuration

**STOPnik** configuration is a simple `YAML` file.

The possible configuration options are listed in the next section.

## Configuration file

The configuration file (e.g. `config.yml`) may contain different root options which are described here as followed

| Property  | Description                  |
|-----------|------------------------------|
| `server`  | General server configuration |
| `clients` | List of clients              |
| `users`   | List of users                |

### General server configuration 

Root entry named `server`

| Property         | Description                                                        |
|------------------|--------------------------------------------------------------------|
| `logLevel`       | Log level                                                          |
| `authCookieName` | Name of the cookie which will be used                              |
| `logoutRedirect` | Where to redirect user after logout                                |
| `addr`           | Go like address, may contain IP and port                           |
| `secret`         | Server secret                                                      |
| `privateKey`     | General RSA or EC private key (can be overwritten for each client) |
| `tls`            | Configuration for TLS                                              |


#### Token keys

Public and private keys to sign tokens

Entry `server`.`tokenKeys`

| Property | Description      |
|----------|------------------|
| `cert`   | Certificate file |
| `key`    | Key file         |


#### TLS

Public and private keys to sign tokens

Entry `server`.`tls`

| Property | Description                              |
|----------|------------------------------------------|
| `addr`   | Go like address, may contain IP and port |
| `keys`   | Public and private keys for TLS          |

##### TLS keys

Public and private keys for TLS

Entry `tls`.`keys`

| Property | Description      |
|----------|------------------|
| `cert`   | Certificate file |
| `key`    | Key file         |

### Clients

List of clients

Root entry `clients`

Each entry may contain the following options

| Property                  | Description                |
|---------------------------|----------------------------|
| `id`                      | The id of the client       |
| `secret`                  | SHA512 hashed secret       |
| `type`                    | TODO                       |
| `accessTTL`               | Access token time to live  |
| `refreshTTL`              | Refresh token time to live |
| `introspect`              | Introspection scope        |
| `revoke`                  | Revocation scope           |
| `redirects`               | List of redirects URIs     |
| `opaqueToken`             | Use opaque token           |
| `passwordFallbackAllowed` | Form auth allowed          |
| `claims`                  | List of claims             |
| `issuer`                  | Issuer                     |
| `audience`                | Audience                   |
| `privateKey`              | RSA or EC private key      |
| `sessionTimeoutSeconds`   | Session timeout in seconds |            |                       |

#### Claims

List of claims

Entry `clients[n]`.`calims`

Each entry may contain the following options

| Property | Description |
|----------|-------------|
| `name`   | Name        |
| `value`  | Value       |

### Users

List of users

Root entry `users`

Each entry may contain the following options

| Property   | Description            |
|------------|------------------------|
| `username` | Username               |
| `password` | SHA512 hashed password |

## Example

The shown `config.yml` is used during development and can be found [here](https://github.com/webishdev/stopnik/blob/main/config.yml) in the repository.

To be able to use it, the referenced `server.crt` and `server.key` must be created as self-signed certificate.

```yaml
server:
  #logLevel: error
  authCookieName: stopnik_auth
  #logoutRedirect: http://localhost:8080
  secret: WRYldij9ebtDZ5VJSsxNAfCZ
  privateKey: rsakey.pem
  addr: :8080
  tls:
    addr: :8081
    keys:
      cert: server.crt
      key: server.key
ui:
#  hideFooter: true
#  hideMascot: true
#  footerText: Some nice line!
#  title: Test realm
clients:
- id: testclient
  secret: d82c4eb5261cb9c8aa9855edd67d1bd10482f41529858d925094d173fa662aa91ff39bc5b188615273484021dfb16fd8284cf684ccf0fc795be3aa2fc1e6c181
  accessTTL: 5
  refreshTTL: 15
  type: confidential
  redirects:
    - https://oauth.pstmn.io/v1/callback
  claims:
    - name: foo
      value: bar
- id: testclient2
  secret: d82c4eb5261cb9c8aa9855edd67d1bd10482f41529858d925094d173fa662aa91ff39bc5b188615273484021dfb16fd8284cf684ccf0fc795be3aa2fc1e6c181
  accessTTL: 5
  refreshTTL: 15
  opaqueToken: true
  type: confidential
  privateKey: ecdsakey.pem
  redirects:
    - https://oauth.pstmn.io/v1/callback
users:
- username: foo
  password: d82c4eb5261cb9c8aa9855edd67d1bd10482f41529858d925094d173fa662aa91ff39bc5b188615273484021dfb16fd8284cf684ccf0fc795be3aa2fc1e6c181
```