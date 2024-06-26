#!/bin/bash
set -eox pipefail

rm -rf target

echo ">> Building contract"

rustup target add wasm32-unknown-unknown
cargo build -p hello_world --target wasm32-unknown-unknown --profile=contract

cp ./target/wasm32-unknown-unknown/contract/hello_world.wasm res/hello_world.wasm