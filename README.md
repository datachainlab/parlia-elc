# parlia-elc

[![test](https://github.com/datachainlab/parlia-elc/actions/workflows/ci.yaml/badge.svg)](https://github.com/datachainlab/parlia-elc/actions/workflows/ci.yaml)

ELC implementation for BSC.

## Configuration

Environment variables can be used to change settings.  
Each configuration must be determined at build time, not at run time.

### Blocks per epoch
You can change the blocks per epoch for localnet.
This is available in dev feature only.

```sh
BSC_BLOCKS_PER_EPOCH=20 cargo build --features=dev
```