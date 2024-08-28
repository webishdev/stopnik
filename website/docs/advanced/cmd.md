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

The `-password` parameter will prompt for password/secret and an optional salt.
The result can be used in the configuration file for client secret and user password.

:::warning

The password and salt will be asked and shown using `stdin` and `stdout`,
someone standing next to you can see them in your terminal application!

:::