## Execution Engine from LightHouse consensus client.

1. Enables communicating with a Eth execution engine using engineapi over http or rpc endpoints.
2. You can use raw JSON RPC calls use the engine abstraction

# compile
cargo build
cargo test
    Runs the unit test
    Also runs a integration test expects a GETH node running on the same node at port

NOTE:
for cargo test to pass you will need a single node geth/reth execution layer running on the same node as you are running the test.
See  https://github.com/bzbyte/ethlaunch repo for instruction to launch as single node geth.
