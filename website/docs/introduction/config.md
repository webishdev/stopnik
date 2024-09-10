# Configuration

**STOPnik** configuration is a simple YAML file.

By default **STOPnik** will use the `config.yml` in the same directory as the executable.

The possible configuration options are listed in the next section.

## Configuration file

The configuration file (e.g. `config.yml`) may contain different root options which are described here as followed

| Property                              | Description                  | Required |
|---------------------------------------|------------------------------|----------|
| [`server`](#server-configuration)     | Server configuration         | Yes      |
| [`ui`](#user-interface-configuration) | User interface configuration | No       |
| [`clients`](#clients)                 | List of clients              | Yes      |
| [`users`](#users)                     | List of users                | Yes      |

### Server configuration

Root entry named `server`

| Property                      | Description                                                                                       | Required |
|-------------------------------|---------------------------------------------------------------------------------------------------|----------|
| `logLevel`                    | Log level                                                                                         | No       |
| [`cookies`](#cookies)         | Configuration related to cookie names                                                             | No       |
| `addr`                        | [Go like address](https://pkg.go.dev/net#Dial), may contain IP and port                           | Yes      |
| `secret`                      | Server secret                                                                                     | No       |
| `privateKey`                  | General RSA or EC private key (can be overwritten for each client) to sign tokens                 | No       |
| `issuer`                      | Issuer                                                                                            | No       |
| [`tls`](#tls)                 | Configuration for TLS                                                                             | No       |
| `logoutRedirect`              | Where to redirect user after logout                                                               | No       |
| `introspectScope`             | Scope which allows token introspection                                                            | No       |
| `revokeScopeScope`            | Scope which allows token revocation                                                               | No       |
| `sessionTimeoutSeconds`       | Seconds until session will end                                                                    | No       |
| [`forwardAuth`](#forwardauth) | [Traefik ForwardAuth](https://doc.traefik.io/traefik/middlewares/http/forwardauth/) configuration | No       |

#### TLS

Public and private keys to sign tokens

Entry `server.tls`

| Property | Description                                                             | Required |
|----------|-------------------------------------------------------------------------|----------|
| `addr`   | [Go like address](https://pkg.go.dev/net#Dial), may contain IP and port | Yes      |
| `keys`   | Public and private keys for TLS                                         | Yes      |

##### TLS keys

Public and private keys for TLS

Entry `server.tls.keys`

| Property | Description      | Required |
|----------|------------------|----------|
| `cert`   | Certificate file | Yes      |
| `key`    | Key file         | Yes      |

#### Cookies

Public and private keys to sign tokens

Entry `server.cookies`

| Property      | Description                      | Required |
|---------------|----------------------------------|----------|
| `authName`    | Name of the authorization cookie | No       |
| `messageName` | Name of internal message cookie  | No       |

#### ForwardAuth

**STOPnik** supports [Traefik ForwardAuth](https://doc.traefik.io/traefik/middlewares/http/forwardauth/) out of the box.

Entry `server.forwardAuth`

| Property        | Description                                         | Required |
|-----------------|-----------------------------------------------------|----------|
| `endpoint`      | Internal endpoint to be called by Traefik           | No       |
| `externalUrl`   | URL of **STOPnik** to redirect the user for a login | No       |
| `parameterName` | URL parameter used by **STOPnik** for ForwardAuth   | No       |
| `redirects`     | List of redirects URIs                              | No       |

### User interface configuration

Root entry named `ui`

| Property          | Description                                                                                                                                 | Required |
|-------------------|---------------------------------------------------------------------------------------------------------------------------------------------|----------|
| `logoImage`       | Path of additional logo image                                                                                                               | No       |
| `hideFooter`      | Will hide the **STOPnik** footer                                                                                                            | No       |
| `hideMascot`      | Will hide the **STOPnik** mascot                                                                                                            | No       |
| `footerText`      | The footer text                                                                                                                             | No       |
| `title`           | Title displayed above the forms                                                                                                             | No       |
| `htmlTitle`       | HTML title                                                                                                                                  | No       |

### Clients

List of clients

Root entry `clients`

Each entry may contain the following options

| Property                  | Description                                             | Required |
|---------------------------|---------------------------------------------------------|----------|
| `id`                      | The id of the client                                    | Yes      |
| `clientSecret`            | SHA512 hashed secret                                    | No       |
| `salt`                    | Optional salt for secret to avoid identical hash values | No       |
| `accessTTL`               | Access token time to live                               | No       |
| `refreshTTL`              | Refresh token time to live                              | No       |
| `idTTL`                   | OpenId Connect ID token time to live                    | No       |
| `oidc`                    | Flag to allow an client to handle OpenId Connect        | No       |
| `introspect`              | Introspection scope                                     | No       |
| `revoke`                  | Revocation scope                                        | No       |
| `redirects`               | List of redirects URIs                                  | No       |
| `opaqueToken`             | Use opaque token                                        | No       |
| `passwordFallbackAllowed` | Form auth allowed                                       | No       |
| [`claims`](#claims)       | List of claims                                          | No       |
| `audience`                | Audience                                                | No       |
| `privateKey`              | RSA or EC private key to sign tokens                    | No       |
| `rolesClaim`              | Name for the claim used to provide roles                | No       |

For `clientSecret` and `salt` see, [Command line - Password](../advanced/cmd.md#password)

If no `clientSecret` is provided, the client is handled as public client, otherwise it will become a confidential client.

#### Claims

List of client claims

Entry `clients[n].calims`

Each entry may contain the following options

| Property | Description | Required |
|----------|-------------|----------|
| `name`   | Name        | Yes      |
| `value`  | Value       | Yes      |

### Users

List of users

Root entry `users`

Each entry may contain the following options

| Property                   | Description                                                        | Required |
|----------------------------|--------------------------------------------------------------------|----------|
| `username`                 | Username                                                           | Yes      |
| `password`                 | SHA512 hashed password                                             | Yes      |
| `salt`                     | Optional salt for password to avoid identical hash values          | No       |
| [`profile`](#user-profile) | User profile which will be used for OpenId Connect UserInfo        | No       |
| `roles`                    | YAML map for roles, key of the map is the id of the related client | No       |

For `password` and `salt` see, [Command line - Password](../advanced/cmd.md#password)

#### User profile

User profile which will be used for OpenId Connect UserInfo

Entry `users[n].profile`

Each entry may contain the following options

| Property                   | Description                      | Required |
|----------------------------|----------------------------------|----------|
| `givenName`                | Given name                       | No       |
| `familyName`               | Family name                      | No       |
| `nickname`                 | Nickname                         | No       |
| `preferredUserName`        | Preferred username               | No       |
| `email`                    | E-Mail address                   | No       |
| `emailVerified`            | E-Mail address verification flag | No       |
| `gender`                   | Gender                           | No       |
| `birthDate`                | Birthdate                        | No       |
| `zoneInfo`                 | Zone information                 | No       |
| `locale`                   | locale                           | No       |
| `phoneNumber`              | Phone number                     | No       |
| `phoneVerified`            | Phone number verification flag   | No       |
| `website`                  | Website URL                      | No       |
| `profile`                  | Profile URL                      | No       |
| `profilePicture`           | Profile picture URL              | No       |
| [`address`](#user-address) | User address                     | No       |

#### User address

User address which will be used for OpenId Connect UserInfo

Entry `users[n].profile.address`

Each entry may contain the following options

| Property     | Description | Required |
|--------------|-------------|----------|
| `street`     | Street      | No       |
| `city`       | City        | No       |
| `postalCode` | Postal code | No       |
| `region`     | Region      | No       |
| `country`    | Country     | No       |

## Examples

### Minimal configuration

The shown `config.yml` is the minimal version possible.

It only defines the HTTP port **STOPnik** should listen on, one client and one user.

After starting locally with this configuration, **STOPnik** will be accessible at

- http://localhost:8080/account
- http://localhost:8080/health

```yaml
server:
  addr: :8080
clients:
  - id: testclient
    clientSecret: d82c4eb5261cb9c8aa9855edd67d1bd10482f41529858d925094d173fa662aa91ff39bc5b188615273484021dfb16fd8284cf684ccf0fc795be3aa2fc1e6c181
    redirects:
      - https://oauth.pstmn.io/v1/callback
users:
  - username: foo
    password: d82c4eb5261cb9c8aa9855edd67d1bd10482f41529858d925094d173fa662aa91ff39bc5b188615273484021dfb16fd8284cf684ccf0fc795be3aa2fc1e6c181
```

### Development configuration

The shown `config.yml` is used during development and can be
found in the repository.

https://github.com/webishdev/stopnik/blob/main/config.yml

This configuration uses self-singed TLS certificates, keys and a privates key located in the `.test_files` folder.

```yaml
server:
  # logLevel: debug
  cookies:
    authName: stopnik_auth
    messageName: stopnik_message
  #logoutRedirect: http://localhost:8080
  forwardAuth:
    externalUrl: http://localhost:9090
    redirects:
      - http://localhost:9090*
  secret: WRYldij9ebtDZ5VJSsxNAfCZ
  privateKey: ./.test_files/rsa256key.pem
  addr: :8082
  tls:
    addr: :8081
    keys:
      cert: ./.test_files/server.crt
      key: ./.test_files/server.key
ui:
#  hideFooter: true
#  hideLogo: true
#  footerText: Some nice line!
#  title: Test realm
clients:
  - id: testclient
    clientSecret: 43a77b3b7f74190654023e68a972b4b0dc21a90be9b85e80222d7bce31eb02ce3205a5fed49a7710afd0ba1fcb97b793d67b5b7ae69607461cdac1a235610dd8
    salt: 123
    accessTTL: 5
    refreshTTL: 15
    idTTL: 15
    oidc: true
    introspect: true
    redirects:
      - https://oauth.pstmn.io/v1/callback
      - http://localhost:8080/session/callback
      - http://localhost:5173/reporting/oidc-callback*
      - http://localhost:8082/health
    claims:
      - name: foo
        value: bar
  - id: testclient2
    clientSecret: deb920477e822d9373831d5521749d3685a3c359504139eb3ff61c7d2fe91986b1978aa1a7834bb304762699b05da2700319e5d60c1183f6f9f66f9c6e73e34e
    salt: abc
    accessTTL: 5
    refreshTTL: 15
    opaqueToken: true
    redirects:
      - https://oauth.pstmn.io/v1/callback
  - id: testclient3
    clientSecret: 1efcbc37f7d7e2f9f8cf009b91c95b2b7b913b89d36a21a05da1e3cb396ed1ab0e596e2b649e9407367e40d852ac4d0abfcfc1c4227eb661385e9f2e0f3203ca
    salt: 321
    accessTTL: 5
    refreshTTL: 15
    privateKey: ./.test_files/ecdsa521key.pem
    redirects:
      - https://oauth.pstmn.io/v1/callback
users:
  - username: foo
    password: 695e6f39f5ffd36ae60e0ade727c892d725531455a19c6035cb739d099e8f20e63d3fdfd3241888e38de1d8db85532dd65f817b12fe33ac7cdcc358ef6c8ea23
    salt: moo
    roles:
      testclient:
        - foo_role
        - bar_role
    profile:
      givenName: John
      familyName: Doe
      address:
        street: Mainstreet 1
        city: Sometown
        postalCode: 12345
        country: Boom
```