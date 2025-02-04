# parlia-elc

[![test](https://github.com/datachainlab/parlia-elc/actions/workflows/ci.yaml/badge.svg)](https://github.com/datachainlab/parlia-elc/actions/workflows/ci.yaml)

[ELC](https://docs.lcp.network/protocol/elc) implementation for [BNB Smart Chain](https://github.com/bnb-chain/bsc).

NOTE: This project is currently under heavy development. Features may change or break.

## Supported Versions
- [lcp v0.2.9](https://github.com/datachainlab/lcp/releases/tag/v0.2.9)
- [BSC v1.4.13](https://github.com/bnb-chain/bsc/releases/tag/v1.4.13)

## Documents

- [Parlia light client spec](./SPEC.md)

## Configuration

Environment variables can be used to change settings.
Each configuration must be determined at build time, not at run time.

### Blocks per epoch
You can change the blocks per epoch for localnet.
This is available in dev feature only.

```sh
BSC_BLOCKS_PER_EPOCH=20 cargo build --features=dev
```

### Build Parameters

Parameters can be specified to check for acceptable headers at build time.

| Name | Description                                                                                                                                     | 
| --- |-------------------------------------------------------------------------------------------------------------------------------------------------| 
| `MINIMUM_TIMESTAMP_SUPPORTED` | Timestamp of the lowest header this light client will accept                                                                                    | 
| `MINIMUM_HEIGHT_SUPPORTED` | Height of the lowest header this light client will accept                                                                                       | 
| `PASCAL_TIMESTAMP` | Timestamp of the first Pascal Hardfork header, used to check the header structure after Pascal Hardfork; if 0 is specified, no check is made.   | 