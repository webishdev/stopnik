

import Tabs from '@theme/Tabs';
import TabItem from '@theme/TabItem';

# Getting started

Multiple ways exists to start **STOPnik**.

It can be started within a container and from a downloaded or [built](../advanced/build.md) binary.

Starting within a container is the recommended way so far.

## Get STOPnik

### Container

Using **STOPnik** within a container is more recommended way to start **STOPnik**.

**STOPnik** is build as Linux container for `linux/amd64` and `linux/arm64` platforms.

Currently, the container images are hosted at the GitHub container registry.

By default **STOPnik** containers will expose port `8080` and `8081`

<Tabs>
  <TabItem value="docker" label="Docker">
Pull the image
```bash
docker pull ghcr.io/webishdev/stopnik:latest
```
  </TabItem>
  <TabItem value="podman" label="Podman">
Pull the image
```bash
podman pull ghcr.io/webishdev/stopnik:latest
```
  </TabItem>
</Tabs>

### Download

To get the current version of **STOPnik** head over to GitHub [Releases](https://github.com/webishdev/stopnik/releases)
and download the most recent release for your operating system and system architecture.

The current build creates executables for Linux, MacOS and Windows.
The executables can be used on ARM and AMD/Intel 64-bit system architectures.

:::warning

The MacOS version is not notarized or signed right now, so probably an error will be shown on MacOS.

To get rid of this error, it is necessary to remove the quarantine attribute after download.

```bash
xattr -rc stopnik*
```

:::

## Starting for the first time

After download or pull of the container image, **STOPnik** can be started.

When starting **STOPnik** for the first time, it will complain about the missing configuration.

<Tabs>
  <TabItem value="shell" label="Shell" default>
Starting from Shell
```bash
> stopnik 
STOPnik development - none

open config.yml: no such file or directory
```
  </TabItem>
  <TabItem value="docker" label="Docker">
Starting with Docker
```bash
> docker run --rm ghcr.io/webishdev/stopnik:latest
STOPnik development - none

open config.yml: no such file or directory
```
  </TabItem>
  <TabItem value="podman" label="Podman">
Starting with Podman
```bash
> podman run --rm ghcr.io/webishdev/stopnik:latest
STOPnik development - none

open config.yml: no such file or directory
```
  </TabItem>
</Tabs>

:::note

To continue a configuration must be provided.

:::

For the binary variant just put a `config.yml` into the same directory as the binary.

For the container variant the `config.yml` should be mounted into the container. It may be also necessary to mount the necessery TLS certificates and private keys used for signing tokens.

The following command line show how to start the container when the Git repository was cloned and the provided `config.yml` and the test certificates (inside `.test_files` folder) are used.

<Tabs>
  <TabItem value="docker" label="Docker">
Starting with Docker
```bash
> docker run --rm -p 8080:8080 -p 8081:8081 -v ${PWD}/config.yml:/config.yml -v ${PWD}/.test_files:/.test_files ghcr.io/webishdev/stopnik:latest
time=2024-08-23T10:30:15.774Z level=INFO msg="Config loaded from config.yml"
time=2024-08-23T10:30:15.780Z level=INFO msg="Will accept TLS connections at [::]:8081"
time=2024-08-23T10:30:15.780Z level=ERROR msg="Error starting server: open server.crt: no such file or directory"
time=2024-08-23T10:30:15.780Z level=INFO msg="Will accept connections at [::]:8080"
```
  </TabItem>
  <TabItem value="podman" label="Podman">
Starting with Podman
```bash
> podman run --rm -p 8080:8080 -p 8081:8081 -v ${PWD}/config.yml:/config.yml -v ${PWD}/.test_files:/.test_files ghcr.io/webishdev/stopnik:latest
time=2024-08-23T10:30:15.774Z level=INFO msg="Config loaded from config.yml"
time=2024-08-23T10:30:15.780Z level=INFO msg="Will accept TLS connections at [::]:8081"
time=2024-08-23T10:30:15.780Z level=ERROR msg="Error starting server: open server.crt: no such file or directory"
time=2024-08-23T10:30:15.780Z level=INFO msg="Will accept connections at [::]:8080"
```
  </TabItem>
</Tabs>