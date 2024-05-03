# k256 & Near Conflict

This is an example of a conflict between `k256` library and `Near` development kit.

# To reproduce

1. Uncomment `use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};` in `src/lib.rs` file.
2. Run `./scripts/build.sh`
3. Run `./scripts/random_acc.sh` and paste the generated account id to the `dev.env` file after `DEPLOYER_ACCOUNT_ID=`
4. Run `./scripts/deploy.sh`
5. Run `./scripts/get_greeting.sh`. This script will either return you a greeting string from the `get_greeting` function, or revert if `use k256::ecdsa...` line is uncommented.
