# Export the local chain spec to json
cargo build --release
./target/release/polkadex-stencil build-spec --disable-default-bootnode --chain local > customSpec.json
./target/release/polkadex-stencil build-spec --disable-default-bootnode --chain=customSpec.json --raw > customSpecRaw.json
cp customSpecRaw.json bootnode/
cp ./target/release/polkadex-thea-node bootnode/polkadex-thea-node