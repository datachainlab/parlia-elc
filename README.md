# parlia-elc

[![test](https://github.com/datachainlab/parlia-elc/actions/workflows/ci.yaml/badge.svg)](https://github.com/datachainlab/parlia-elc/actions/workflows/ci.yaml)

[ELC](https://docs.lcp.network/protocol/elc) implementation for [BNB Smart Chain](https://github.com/bnb-chain/bsc).

NOTE: This project is currently under heavy development. Features may change or break.

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