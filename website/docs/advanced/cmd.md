# Command line

**STOPnik** provides multiple parameters which can be used when starting from command line.

```bash
Usage of ./stopnik:
  -file string
        Configuration file to use (default "config.yml")
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

The `-file <location>` parameter can be used to point to a configuration file,
otherwise **STOPnik** will try to read the `config.yml` from the working directory.

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
