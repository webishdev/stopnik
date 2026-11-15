# Command line

**STOPnik** provides multiple parameters which can be used when starting from command line.

```bash
Usage of ./stopnik:
  -file string
        Static configuration file to use (default ".config/default/config.toml")
  -help
        Show help message
  -password
        Ask for password and salt to create hash
  -version
        Show version information

```

## Help

The `-help` parameter will show the usage information.

## Version

The `-version` parameter will show the version information.

## Configuration file

The `-file <location>` parameter can be used to point to a static configuration file,
otherwise **STOPnik** will try to read the `.config/default/config.toml` from the working directory.

The dynamic configuration folders `client.d`, `user.d` and `classification.d` are expected next to the static configuration file,
see [Configuration](../introduction/config.md).

## Password

The `-password` parameter will prompt for a password/secret and print its bcrypt hash.
The result can be used in the configuration file for client secret and user password.
bcrypt hashes contain their own random salt, so no `salt` is needed in the configuration.

:::warning

The password will be asked and shown using `stdin` and `stdout`,
someone standing next to you can see it in your terminal application!

:::

:::info

bcrypt hashes can also be created with other tools, e.g. with `htpasswd` from the Apache HTTP Server utilities

```bash
htpasswd -nbBC 10 "" bar | cut -d: -f2
```

:::

### SHA512 hashes

Previous versions of **STOPnik** used (salted) SHA512 hashes, which are still supported.
As SHA512 is fast to calculate, such hashes are easier to brute force and should be replaced by bcrypt hashes.

When not using an additional salt value, the SHA512 hash can be created with other tools.
To create the hash value for the password `bar` for example, the following command can be used

```bash
echo -n bar | shasum -a 512
d82c4eb5261cb9c8aa9855edd67d1bd10482f41529858d925094d173fa662aa91ff39bc5b188615273484021dfb16fd8284cf684ccf0fc795be3aa2fc1e6c181  -
```

With a salt, the hash is created for the value `<password>/!<salt>`.

## Admin web user interface

The separate `stopnik-admin` binary serves a web user interface to create, edit and delete
the dynamic configuration files of clients, users and classifications.
It reads the same static configuration file as **STOPnik** to find the `client.d`, `user.d` and `classification.d` folders
and validates every change with the same rules **STOPnik** uses when loading these files.
A running **STOPnik** applies the changes when `dynamic.watch` is enabled.

```bash
Usage of ./stopnik-admin:
  -addr string
        Address the admin web user interface listens to, e.g. 0.0.0.0:9999 (default "localhost:9999")
  -base-path string
        Path prefix the admin web user interface is served under, e.g. /admin
  -file string
        Static configuration file to use (default ".config/default/config.toml")
  -help
        Show help message
  -version
        Show version information
```

With `-base-path` all pages are served below the given path, e.g. `-base-path /admin` serves the overview at `/admin/`,
which allows to make the admin web user interface available through a reverse proxy next to **STOPnik**.

New entries are stored as files with a generated name (a UUID) in the matching folder,
existing files keep their name.
Settings which are not part of the forms, like custom keys, are kept when an entry is saved, comments are removed.
Passwords and client secrets entered in the forms are stored as bcrypt hashes.

Relative paths to client private keys are resolved against the working directory,
start `stopnik-admin` from the same directory as **STOPnik**.

### Sign in

Only users with `admin = true` can sign in to the admin web user interface.
When no such user exists, the sign-in page only reports a missing administrator, without showing configuration details.
An administrator has to be configured manually by adding the property to a user file in `user.d`,
e.g. with a password hash created by `stopnik -password`.

```toml
username = "admin"
password = "$2a$10$xchSl0M6Yk43/6Lvvqzx5..sWJcgOp1wCPYUOVPGW4XBh.duYU4I6"
admin = true
```

The admin flag of other users can be changed in the user form.
The signed-in user can not delete or rename their own user or remove their own admin flag.
Removing the admin flag or the user ends existing sessions right away.

Sessions are kept in memory and last for `server.sessionTimeoutSeconds`, restarting `stopnik-admin` signs out all users.
After 10 failed sign-in attempts within 5 minutes, further attempts for the username are blocked for the rest of the 5 minutes.

:::warning

Only start the admin web user interface when needed. It uses plain HTTP, so make it reachable from trusted networks only,
e.g. via `localhost`, a VPN or a reverse proxy with TLS.

:::
