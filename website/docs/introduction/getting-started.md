---
sidebar_position: 2
title: Getting started
---

import Tabs from '@theme/Tabs';
import TabItem from '@theme/TabItem';

# Getting started

## Download

To get the current version of **STOPnik** head over to GitHub [Releases](https://github.com/webishdev/stopnik/releases)
and download the most recent release for your operating system and system architecture.

The current build creates executables for Linux, MacOS and Windows.
The executables can be used on ARM and AMD/Intel 64-bit system architectures.

### MacOS

The MacOS version is not notarized or signed right now, so probably an error will be shown by MacOS.

To get rid of this error, it is necessary to remove the quarantine attribute after download.

```bash
xattr -rc stopnik*
```

## Container

Using **STOPnik** within a container is more recommended way to start **STOPnik**.

Currently, the container images are hosted at the GitHub container registry.

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

# Starting for the first time

After downloading and starting **STOPnik** for the first time, it will complain about the missing configuration.

When stared within a container, an empty `config.yml` will be used and the container will exit immediately.

<Tabs>
  <TabItem value="shell" label="Shell" default>
Starting from shell
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

time=2024-08-14T10:44:49.094Z level=INFO msg="Config loaded from config.yml"
```
  </TabItem>
  <TabItem value="podman" label="Podman">
Starting with Podman
```bash
> podman run --rm ghcr.io/webishdev/stopnik:latest

time=2024-08-14T10:44:49.094Z level=INFO msg="Config loaded from config.yml"
```
  </TabItem>
</Tabs>
