# lcp-parlia

[![test](https://github.com/datachainlab/lcp-parlia/actions/workflows/ci.yaml/badge.svg)](https://github.com/datachainlab/lcp-parlia/actions/workflows/ci.yaml)

ELC implementation for BSC.

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

### Fork height
You can change the fork height for each net.

```sh
BSC_LUBAN_FORK=1000000 cargo build
```

