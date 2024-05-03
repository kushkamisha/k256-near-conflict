source dev.env
near contract deploy $DEPLOYER_ACCOUNT_ID use-file ./res/hello_world.wasm without-init-call network-config testnet sign-with-keychain send