# Build

Requires [Git](https://git-scm.com/) and [Go >=1.23](https://go.dev/) to be installed.

To build **STOPnik** the repository should be cloned and the build command executed.

```bash
git clone https://github.com/webishdev/stopnik.git
cd stopnik
go build github.com/webishdev/stopnik/cmd/stopnik
```

And then start **STOPnik** with

```bash
./stopnik
```

## Test

Execute tests inside the repository root folder with

```bash
go test ./...
```

To get access to the HTML coverage report the following script can be executed

```bash
./test.sh html
```

The coverage report will be created in the `.test_coverage` folder