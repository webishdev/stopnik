# Build

## Build STOPnik executable

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

### Execute test

Execute tests inside the repository root folder with

```bash
go test ./...
```

To get access to the HTML coverage report the following script can be executed

```bash
./test.sh html
```

The coverage report will be created in the `.test_coverage` folder

## Access documentation website locally

The current documentation is created with the help of [Docusaurus
](https://docusaurus.io/).

:::info

To be able to build and access the website on your local machine [NodeJS](https://nodejs.org/) must be installed.

:::

To access the website on your local machine change to the `website` directory and execute the following commands

### Install dependencies

```bash
npm install
```

### Start documentation website

```bash
npm start
```

### Access

The documentation website will become available on your local machine at http://localhost:3000/