## How to make testdata
```sh
git submodule update --init
cd ibc-parlia-relay/tool/testdata
export BSC_RPC_ADDR="bsc rpc node"
# generate create_mainnet.json and update_mainnet.json
go run main.go history mainnet
# generate create_testnet.json and update_testnet.json
go run main.go history testnet
```

## Run test

```sh
cd lcp-parlia/light-client
cargo test --package parlia-ibc-lc --test verify test::test_verify_mainnet
cargo test --package parlia-ibc-lc --test verify test::test_verify_testnet
```