# k256 & Near Conflict

This is an example of a conflict between `k256` library and `Near` development kit.

# To reproduce

1. Uncomment `use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};` in `src/lib.rs` file.
2. Run `./scripts/build.sh`
3. Run `./scripts/random_acc.sh` and paste the generated account id to the `dev.env` file after `DEPLOYER_ACCOUNT_ID=`
4. Run `./scripts/deploy.sh`
5. Run `./scripts/get_greeting.sh`. This script will either return you a greeting string from the `get_greeting` function, or revert if `use k256::ecdsa...` line is uncommented.

# Excheption example

This is how the exception upon calling a `get_greeting` function looks like:

```
Here is your console command if you need to script it or re-run:
    near contract call-function as-read-only lucky-fish.testnet get_greeting text-args '' network-config testnet now

Error: 
   0: Failed to fetch query for view method: 'get_greeting' (contract <lucky-fish.testnet> on network <testnet>)
   1: Failed to make a view-function call
   2: handler error: [Function call returned an error: wasm execution failed with error: CompilationError(PrepareError(Instantiate))]

Location:
   src/common.rs:1923
```