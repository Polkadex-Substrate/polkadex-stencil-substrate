wget https://polkadex-thea.s3.ap-south-1.amazonaws.com/customSpecRaw.json
wget https://polkadex-thea.s3.ap-south-1.amazonaws.com/polkadex-stencil
chmod +x polkadex-stencil




./polkadex-thea-node \
    --chain customSpecRaw.json \
    --rpc-cors=all \
    --validator \
    --bootnodes /ip4/65.1.128.149/tcp/30333/p2p/12D3KooWNbuHUdTusGid8HY9N4K6GYh6XrmwmfbCAHnSjNjQhYQj \
    --rpc-port=9945 \
    --in-peers=50 \
    --out-peers=50 \
    --telemetry-url 'wss://telemetry.polkadot.io/submit/ 0' \
    -laura=trace


curl http://localhost:9945 -H "Content-Type:application/json;charset=utf-8" -d "@aura.json"