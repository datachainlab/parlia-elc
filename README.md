# parlia-elc

[![test](https://github.com/datachainlab/parlia-elc/actions/workflows/ci.yaml/badge.svg)](https://github.com/datachainlab/parlia-elc/actions/workflows/ci.yaml)

[ELC](https://docs.lcp.network/protocol/elc) implementation for [BNB Smart Chain](https://github.com/bnb-chain/bsc).

NOTE: This project is currently under heavy development. Features may change or break.

## Supported Versions
- [lcp v0.2.12](https://github.com/datachainlab/lcp/releases/tag/v0.2.12)
- [BSC v1.5.5](https://github.com/bnb-chain/bsc/releases/tag/v1.5.5)

## Documents

- [Parlia light client spec](./SPEC.md)

## Configuration

Environment variables can be used to change settings.
Each configuration must be determined at build time, not at run time.

### Build Parameters

Parameters can be specified to check for acceptable headers at build time.

| Name | Description                                                                                                                  | 
| --- |------------------------------------------------------------------------------------------------------------------------------| 
| `MINIMUM_TIMESTAMP_SUPPORTED` | Timestamp(millisecond) of the lowest header this light client will accept. All the ForkSpec must be greater than or equal to this value. |
| `MINIMUM_HEIGHT_SUPPORTED` | Height of the lowest header this light client will accept. All the ForkSpec must be greater than or equal to this value.                 | 
