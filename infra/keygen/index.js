import {Keyring} from "@polkadot/keyring";
import {cryptoWaitReady} from "@polkadot/util-crypto";
import fs from "fs";

const keyring_babe = new Keyring({type: 'sr25519'});
const keyring_gran = new Keyring({type: 'ed25519'});
let mnemonic = "owner word vocal dose decline sunset battle example forget excite gentle waste";
await cryptoWaitReady();
for (let i = 1; i < 101; i++) {
    let json_file = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "author_insertKey",
        "params": [
            "<aura/gran>",
            "<mnemonic phrase>",
            "<public key>"
        ]
    };
    let stash_pair = keyring_babe.addFromMnemonic(mnemonic + "//" + i + "//stash", {type: 'sr25519'});
    let controller_pair = keyring_babe.addFromMnemonic(mnemonic + "//" + i + "//controller", {type: 'sr25519'});
    let babe_pair = keyring_babe.addFromMnemonic(mnemonic + "//" + i + "//babe", {type: 'sr25519'});
    json_file.params = ["babe", mnemonic + "//" + i + "//babe", "0x" + Buffer.from(babe_pair.publicKey).toString('hex')];
    fs.writeFile('../templates/polkadex-node-' + i + '-babe.json', JSON.stringify(json_file), {flag: 'w+'}, err => {
        if (err != null) {
            console.log(err);
        }
    });
    let gran_pair = keyring_gran.addFromMnemonic(mnemonic + "//" + i + "//grandpa", {type: 'ed25519'});
    json_file.params = ["gran", mnemonic + "//" + i + "//grandpa", "0x" + Buffer.from(gran_pair.publicKey).toString('hex')];
    fs.writeFile('../templates/polkadex-node-' + i + '-gran.json', JSON.stringify(json_file), {flag: 'w+'}, err => {
        if (err != null) {
            console.log(err);
        }
    });
    let iam_online_pair = keyring_babe.addFromMnemonic(mnemonic + "//" + i + "//im_online", {type: 'sr25519'});
    let auth_discovery = keyring_babe.addFromMnemonic(mnemonic + "//" + i + "//authority_discovery", {type: 'sr25519'});

    let rust_chain_spec_code = "(" + rust_code(stash_pair.publicKey)
        + rust_code(controller_pair.publicKey)
        + rust_code_unchecked(gran_pair.publicKey)
        + rust_code_unchecked(babe_pair.publicKey)
        + rust_code_unchecked(iam_online_pair.publicKey)
        + rust_code_unchecked(auth_discovery.publicKey) + "),";

    console.log(rust_chain_spec_code)
}

function rust_code(public_key) {
    return "hex![\"" + Buffer.from(public_key).toString('hex') + "\"].into(), \n"
}

function rust_code_unchecked(public_key) {
    return "hex![\"" + Buffer.from(public_key).toString('hex') + "\"].unchecked_into(), \n"
}