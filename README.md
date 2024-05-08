<p align="center">
    <picture>
      <img alt="STOPnik" title="STOPnik" src="docs/content/assets/stopnik_250.png">
    </picture>
</p>

# STOPnik

The simple and small `OAuth2 | OpenId Connect` server that secures your applications without hassle.

**STOPnik** does not have any persistence layer and will only work in-memory with the clients and users defined in the configuration file (`YAML`).
When restarted, all issued tokens will become invalid/forgotten by **STOPnik**.

![build](https://github.com/giftkugel/stopnik/actions/workflows/build.yml/badge.svg)
