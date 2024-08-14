---
sidebar_position: 3
---
# Configuration

**STOPnik** configuration is a simple `YAML` file.

The possible configuration options are listed in the next section.

## `config.yml`

The configuration file may contain different root options which are described here as followed

| Property  | Description                  |
|-----------|------------------------------|
| `server`  | General server configuration |
| `clients` | List of clients              |
| `users`   | List of users                |

### `server`

General server configuration

| Property         | Description                              |
|------------------|------------------------------------------|
| `logLevel`       | Log level                                |
| `authCookieName` | Name of the cookie which will be used    |
| `logoutRedirect` | Where to redirect user after logout      |
| `addr`           | Go like address, may contain IP and port |
| `secret`         | Server secret                            |
| `tokenKeys`      | Public and private keys to sign tokens   |
| `tls`            | Configuration for TLS                    |

# `tokenKeys`

Public and private keys to sign tokens

| Property | Description      |
|----------|------------------|
| `cert`   | Certificate file |
| `key`    | Key file         |


# `tls`

Public and private keys to sign tokens

| Property | Description                              |
|----------|------------------------------------------|
| `addr`   | Go like address, may contain IP and port |
| `keys`   | Public and private keys for TLS          |

# `keys`

Public and private keys for TLS

| Property | Description      |
|----------|------------------|
| `cert`   | Certificate file |
| `key`    | Key file         |

### `clients`

List of clients

Each entry may contain the following options

| Property     | Description                |
|--------------|----------------------------|
| `id`         | The id of the client       |
| `secret`     | SHA512 hashed secret       |
| `accessTTL`  | Access token time to live  |
| `refreshTTL` | Refresh token time to live |
| `redirects`  | List of redirects URIs     |
| `claims`     | List of claims             |

# `calims`

List of claims

Each entry may contain the following options

| Property | Description |
|----------|-------------|
| `name`   | Name        |
| `value`  | Value       |

### `users`

List of users

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
  tokenKeys:
    cert: server.crt
    key: server.key
  addr: :8080
  tls:
    addr: :8081
    keys:
      cert: server.crt
      key: server.key
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
  redirects:
    - https://oauth.pstmn.io/v1/callback
users:
- username: foo
  password: d82c4eb5261cb9c8aa9855edd67d1bd10482f41529858d925094d173fa662aa91ff39bc5b188615273484021dfb16fd8284cf684ccf0fc795be3aa2fc1e6c181
```