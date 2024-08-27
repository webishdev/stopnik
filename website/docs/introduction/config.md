---
sidebar_position: 3
---
# Configuration

**STOPnik** configuration is a simple YAML file.

By default **STOPnik** will use the `config.yml` in the same directory as the executable.

The possible configuration options are listed in the next section.

## Configuration file

The configuration file (e.g. `config.yml`) may contain different root options which are described here as followed

| Property  | Description                  |
|-----------|------------------------------|
| `server`  | Server configuration         |
| `ui`      | User interface configuration |
| `clients` | List of clients              |
| `users`   | List of users                |

### Server configuration 

Root entry named `server`

| Property         | Description                                                                       |
|------------------|-----------------------------------------------------------------------------------|
| `logLevel`       | Log level                                                                         |
| `authCookieName` | Name of the cookie which will be used                                             |
| `logoutRedirect` | Where to redirect user after logout                                               |
| `addr`           | Go like address, may contain IP and port                                          |
| `secret`         | Server secret                                                                     |
| `privateKey`     | General RSA or EC private key (can be overwritten for each client) to sign tokens |
| `tls`            | Configuration for TLS                                                             |

#### TLS

Public and private keys to sign tokens

Entry `server.tls`

| Property | Description                              |
|----------|------------------------------------------|
| `addr`   | Go like address, may contain IP and port |
| `keys`   | Public and private keys for TLS          |

##### TLS keys

Public and private keys for TLS

Entry `server.tls.keys`

| Property | Description      |
|----------|------------------|
| `cert`   | Certificate file |
| `key`    | Key file         |


### User interface configuration

Root entry named `ui`

| Property     | Description                      |
|--------------|----------------------------------|
| `hideFooter` | Will hide the **STOPnik** footer |
| `hideMascot` | Will hide the **STOPnik** mascot |
| `footerText` | The footer text                  |
| `title`      | Title                            |

### Clients

List of clients

Root entry `clients`

Each entry may contain the following options

| Property                  | Description                                             |
|---------------------------|---------------------------------------------------------|
| `id`                      | The id of the client                                    |
| `secret`                  | SHA512 hashed secret                                    |
| `salt`                    | Optional salt for secret to avoid identical hash values |
| `type`                    | TODO                                                    |
| `accessTTL`               | Access token time to live                               |
| `refreshTTL`              | Refresh token time to live                              |
| `introspect`              | Introspection scope                                     |
| `revoke`                  | Revocation scope                                        |
| `redirects`               | List of redirects URIs                                  |
| `opaqueToken`             | Use opaque token                                        |
| `passwordFallbackAllowed` | Form auth allowed                                       |
| `claims`                  | List of claims                                          |
| `issuer`                  | Issuer                                                  |
| `audience`                | Audience                                                |
| `privateKey`              | RSA or EC private key to sign tokens                    |
| `sessionTimeoutSeconds`   | Session timeout in seconds                              |

#### Claims

List of claims

Entry `clients[n].calims`

Each entry may contain the following options

| Property | Description |
|----------|-------------|
| `name`   | Name        |
| `value`  | Value       |

### Users

List of users

Root entry `users`

Each entry may contain the following options

| Property   | Description                                               |
|------------|-----------------------------------------------------------|
| `username` | Username                                                  |
| `password` | SHA512 hashed password                                    |
| `salt`     | Optional salt for password to avoid identical hash values |

## Examples

### Minimal configuration

The shown `config.yml` is the minimal version possible.

It only defines the HTTP port **STOPnik** should listen on.

After starting locally with this configuration, **STOPnik** will be accessible at

- http://localhost:8080/account
- http://localhost:8080/health

```yaml
server:
  addr: :8080
```

:::warning

This configuration only allows to start **STOPnik** but makes no sense at all, as no users and clients are defined.

Not login and not `OAuth | OpenId Connect` flow will be possible.

:::

### Development configuration

The shown `config.yml` is used during development and can be found [here](https://github.com/webishdev/stopnik/blob/main/config.yml) in the repository.

To be able to use it, the referenced `server.crt` and `server.key` must be created as self-signed certificate.

```yaml
server:
  #logLevel: error
  cookies:
    authName: stopnik_auth
    messageName: stopnik_message
  #logoutRedirect: http://localhost:8080
  secret: WRYldij9ebtDZ5VJSsxNAfCZ
  privateKey: ./test_keys/rsa256key.pem
  addr: :8080
  tls:
    addr: :8081
    keys:
      cert: ./test_keys/server.crt
      key: ./test_keys/server.key
ui:
#  hideFooter: true
#  hideMascot: true
#  footerText: Some nice line!
#  title: Test realm
clients:
  - id: testclient
    clientSecret: 43a77b3b7f74190654023e68a972b4b0dc21a90be9b85e80222d7bce31eb02ce3205a5fed49a7710afd0ba1fcb97b793d67b5b7ae69607461cdac1a235610dd8
    salt: 123
    accessTTL: 5
    refreshTTL: 15
    type: confidential
    redirects:
      - https://oauth.pstmn.io/v1/callback
    claims:
      - name: foo
        value: bar
  - id: testclient2
    clientSecret: deb920477e822d9373831d5521749d3685a3c359504139eb3ff61c7d2fe91986b1978aa1a7834bb304762699b05da2700319e5d60c1183f6f9f66f9c6e73e34e
    salt: abc
    accessTTL: 5
    refreshTTL: 15
    opaqueToken: true
    type: confidential
    redirects:
      - https://oauth.pstmn.io/v1/callback
  - id: testclient3
    clientSecret: 1efcbc37f7d7e2f9f8cf009b91c95b2b7b913b89d36a21a05da1e3cb396ed1ab0e596e2b649e9407367e40d852ac4d0abfcfc1c4227eb661385e9f2e0f3203ca
    salt: 321
    accessTTL: 5
    refreshTTL: 15
    type: confidential
    privateKey: ./test_keys/ecdsa521key.pem
    redirects:
      - https://oauth.pstmn.io/v1/callback
users:
  - username: foo
    password: 695e6f39f5ffd36ae60e0ade727c892d725531455a19c6035cb739d099e8f20e63d3fdfd3241888e38de1d8db85532dd65f817b12fe33ac7cdcc358ef6c8ea23
    salt: moo
```