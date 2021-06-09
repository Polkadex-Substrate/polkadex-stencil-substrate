wget https://polkadex-thea.s3.ap-south-1.amazonaws.com/customSpecRaw.json
wget https://polkadex-thea.s3.ap-south-1.amazonaws.com/polkadex-thea-node
chmod +x polkadex-thea-node




./polkadex-thea-node \
    --chain customSpecRaw.json \
    --rpc-cors=all \
    --validator \
    --bootnodes /ip4/3.6.116.184/tcp/30333/p2p/12D3KooWJV4JKrVfoNue5MXfuZAXi9xou7xvyBkS6MuvfwqiJbes \
    --rpc-port=9945 \
    --in-peers=50 \
    --out-peers=50 \
    --telemetry-url 'wss://telemetry.polkadot.io/submit/ 0' \
    -laura=trace


curl http://localhost:9945 -H "Content-Type:application/json;charset=utf-8" -d "@aura.json"