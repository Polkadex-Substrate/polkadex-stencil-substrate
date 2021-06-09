// This file is part of Substrate.

// Copyright (C) 2018-2021 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

//! Substrate chain configurations.

use grandpa_primitives::AuthorityId as GrandpaId;
use hex_literal::hex;
use pallet_im_online::sr25519::AuthorityId as ImOnlineId;
use sc_chain_spec::ChainSpecExtension;
use sc_service::ChainType;
use sc_telemetry::TelemetryEndpoints;
use serde::{Deserialize, Serialize};
use sp_authority_discovery::AuthorityId as AuthorityDiscoveryId;
use sp_consensus_babe::AuthorityId as BabeId;
use sp_core::{crypto::UncheckedInto, Pair, Public, sr25519};
use sp_runtime::{Perbill, traits::{IdentifyAccount, Verify}};

pub use node_primitives::{AccountId, Balance, Signature};
use node_primitives::Block;
use node_template_runtime::{
    AuthorityDiscoveryConfig, BabeConfig, BalancesConfig, ContractsConfig, CouncilConfig,
    DemocracyConfig, ElectionsConfig, GrandpaConfig, ImOnlineConfig, IndicesConfig, MAX_NOMINATIONS,
    SessionConfig, SessionKeys, SocietyConfig, StakerStatus, StakingConfig, SudoConfig,
    SystemConfig, TechnicalCommitteeConfig, wasm_binary_unwrap,
};
use node_template_runtime::constants::currency::*;
pub use node_template_runtime::GenesisConfig;

type AccountPublic = <Signature as Verify>::Signer;

const STAGING_TELEMETRY_URL: &str = "wss://telemetry.polkadot.io/submit/";

/// Node `ChainSpec` extensions.
///
/// Additional parameters for some Substrate core modules,
/// customizable from the chain spec.
#[derive(Default, Clone, Serialize, Deserialize, ChainSpecExtension)]
#[serde(rename_all = "camelCase")]
pub struct Extensions {
    /// Block numbers with known hashes.
    pub fork_blocks: sc_client_api::ForkBlocks<Block>,
    /// Known bad block hashes.
    pub bad_blocks: sc_client_api::BadBlocks<Block>,
}

/// Specialized `ChainSpec`.
pub type ChainSpec = sc_service::GenericChainSpec<
    GenesisConfig,
    Extensions,
>;
// /// Flaming Fir testnet generator
// pub fn flaming_fir_config() -> Result<ChainSpec, String> {
//     ChainSpec::from_json_bytes(&include_bytes!("../res/flaming-fir.json")[..])
// }

fn session_keys(
    grandpa: GrandpaId,
    babe: BabeId,
    im_online: ImOnlineId,
    authority_discovery: AuthorityDiscoveryId,
) -> SessionKeys {
    SessionKeys { grandpa, babe, im_online, authority_discovery }
}

fn staging_testnet_config_genesis() -> GenesisConfig {
    // stash, controller, session-key
    // generated with secret:
    // for i in 1 2 3 4 ; do for j in stash controller; do subkey inspect "$secret"/fir/$j/$i; done; done
    // and
    // for i in 1 2 3 4 ; do for j in session; do subkey --ed25519 inspect "$secret"//fir//$j//$i; done; done

    let initial_authorities: Vec<(AccountId, AccountId, GrandpaId, BabeId, ImOnlineId, AuthorityDiscoveryId)> = vec![(
                                                                                                                         // 5Fbsd6WXDGiLTxunqeK5BATNiocfCqu9bS1yArVjCgeBLkVy
                                                                                                                         hex!["9c7a2ee14e565db0c69f78c7b4cd839fbf52b607d867e9e9c5a79042898a0d12"].into(),
                                                                                                                         // 5EnCiV7wSHeNhjW3FSUwiJNkcc2SBkPLn5Nj93FmbLtBjQUq
                                                                                                                         hex!["781ead1e2fa9ccb74b44c19d29cb2a7a4b5be3972927ae98cd3877523976a276"].into(),
                                                                                                                         // 5Fb9ayurnxnaXj56CjmyQLBiadfRCqUbL2VWNbbe1nZU6wiC
                                                                                                                         hex!["9becad03e6dcac03cee07edebca5475314861492cdfc96a2144a67bbe9699332"].unchecked_into(),
                                                                                                                         // 5EZaeQ8djPcq9pheJUhgerXQZt9YaHnMJpiHMRhwQeinqUW8
                                                                                                                         hex!["6e7e4eb42cbd2e0ab4cae8708ce5509580b8c04d11f6758dbf686d50fe9f9106"].unchecked_into(),
                                                                                                                         // 5EZaeQ8djPcq9pheJUhgerXQZt9YaHnMJpiHMRhwQeinqUW8
                                                                                                                         hex!["6e7e4eb42cbd2e0ab4cae8708ce5509580b8c04d11f6758dbf686d50fe9f9106"].unchecked_into(),
                                                                                                                         // 5EZaeQ8djPcq9pheJUhgerXQZt9YaHnMJpiHMRhwQeinqUW8
                                                                                                                         hex!["6e7e4eb42cbd2e0ab4cae8708ce5509580b8c04d11f6758dbf686d50fe9f9106"].unchecked_into(),
                                                                                                                     ), (
                                                                                                                         // 5ERawXCzCWkjVq3xz1W5KGNtVx2VdefvZ62Bw1FEuZW4Vny2
                                                                                                                         hex!["68655684472b743e456907b398d3a44c113f189e56d1bbfd55e889e295dfde78"].into(),
                                                                                                                         // 5Gc4vr42hH1uDZc93Nayk5G7i687bAQdHHc9unLuyeawHipF
                                                                                                                         hex!["c8dc79e36b29395413399edaec3e20fcca7205fb19776ed8ddb25d6f427ec40e"].into(),
                                                                                                                         // 5EockCXN6YkiNCDjpqqnbcqd4ad35nU4RmA1ikM4YeRN4WcE
                                                                                                                         hex!["7932cff431e748892fa48e10c63c17d30f80ca42e4de3921e641249cd7fa3c2f"].unchecked_into(),
                                                                                                                         // 5DhLtiaQd1L1LU9jaNeeu9HJkP6eyg3BwXA7iNMzKm7qqruQ
                                                                                                                         hex!["482dbd7297a39fa145c570552249c2ca9dd47e281f0c500c971b59c9dcdcd82e"].unchecked_into(),
                                                                                                                         // 5DhLtiaQd1L1LU9jaNeeu9HJkP6eyg3BwXA7iNMzKm7qqruQ
                                                                                                                         hex!["482dbd7297a39fa145c570552249c2ca9dd47e281f0c500c971b59c9dcdcd82e"].unchecked_into(),
                                                                                                                         // 5DhLtiaQd1L1LU9jaNeeu9HJkP6eyg3BwXA7iNMzKm7qqruQ
                                                                                                                         hex!["482dbd7297a39fa145c570552249c2ca9dd47e281f0c500c971b59c9dcdcd82e"].unchecked_into(),
                                                                                                                     ), (
                                                                                                                         // 5DyVtKWPidondEu8iHZgi6Ffv9yrJJ1NDNLom3X9cTDi98qp
                                                                                                                         hex!["547ff0ab649283a7ae01dbc2eb73932eba2fb09075e9485ff369082a2ff38d65"].into(),
                                                                                                                         // 5FeD54vGVNpFX3PndHPXJ2MDakc462vBCD5mgtWRnWYCpZU9
                                                                                                                         hex!["9e42241d7cd91d001773b0b616d523dd80e13c6c2cab860b1234ef1b9ffc1526"].into(),
                                                                                                                         // 5E1jLYfLdUQKrFrtqoKgFrRvxM3oQPMbf6DfcsrugZZ5Bn8d
                                                                                                                         hex!["5633b70b80a6c8bb16270f82cca6d56b27ed7b76c8fd5af2986a25a4788ce440"].unchecked_into(),
                                                                                                                         // 5DhKqkHRkndJu8vq7pi2Q5S3DfftWJHGxbEUNH43b46qNspH
                                                                                                                         hex!["482a3389a6cf42d8ed83888cfd920fec738ea30f97e44699ada7323f08c3380a"].unchecked_into(),
                                                                                                                         // 5DhKqkHRkndJu8vq7pi2Q5S3DfftWJHGxbEUNH43b46qNspH
                                                                                                                         hex!["482a3389a6cf42d8ed83888cfd920fec738ea30f97e44699ada7323f08c3380a"].unchecked_into(),
                                                                                                                         // 5DhKqkHRkndJu8vq7pi2Q5S3DfftWJHGxbEUNH43b46qNspH
                                                                                                                         hex!["482a3389a6cf42d8ed83888cfd920fec738ea30f97e44699ada7323f08c3380a"].unchecked_into(),
                                                                                                                     ), (
                                                                                                                         // 5HYZnKWe5FVZQ33ZRJK1rG3WaLMztxWrrNDb1JRwaHHVWyP9
                                                                                                                         hex!["f26cdb14b5aec7b2789fd5ca80f979cef3761897ae1f37ffb3e154cbcc1c2663"].into(),
                                                                                                                         // 5EPQdAQ39WQNLCRjWsCk5jErsCitHiY5ZmjfWzzbXDoAoYbn
                                                                                                                         hex!["66bc1e5d275da50b72b15de072a2468a5ad414919ca9054d2695767cf650012f"].into(),
                                                                                                                         // 5DMa31Hd5u1dwoRKgC4uvqyrdK45RHv3CpwvpUC1EzuwDit4
                                                                                                                         hex!["3919132b851ef0fd2dae42a7e734fe547af5a6b809006100f48944d7fae8e8ef"].unchecked_into(),
                                                                                                                         // 5C4vDQxA8LTck2xJEy4Yg1hM9qjDt4LvTQaMo4Y8ne43aU6x
                                                                                                                         hex!["00299981a2b92f878baaf5dbeba5c18d4e70f2a1fcd9c61b32ea18daf38f4378"].unchecked_into(),
                                                                                                                         // 5C4vDQxA8LTck2xJEy4Yg1hM9qjDt4LvTQaMo4Y8ne43aU6x
                                                                                                                         hex!["00299981a2b92f878baaf5dbeba5c18d4e70f2a1fcd9c61b32ea18daf38f4378"].unchecked_into(),
                                                                                                                         // 5C4vDQxA8LTck2xJEy4Yg1hM9qjDt4LvTQaMo4Y8ne43aU6x
                                                                                                                         hex!["00299981a2b92f878baaf5dbeba5c18d4e70f2a1fcd9c61b32ea18daf38f4378"].unchecked_into(),
                                                                                                                     )];

    // generated with secret: subkey inspect "$secret"/fir
    let root_key: AccountId = hex![
		// 5Ff3iXP75ruzroPWRP2FYBHWnmGGBSb63857BgnzCoXNxfPo
		"9ee5e5bdc0ec239eb164f865ecc345ce4c88e76ee002e0f7e318097347471809"
	].into();

    let endowed_accounts: Vec<AccountId> = vec![root_key.clone()];

    testnet_genesis(initial_authorities, vec![], root_key, Some(endowed_accounts), false)
}

/// Staging testnet config.
pub fn staging_testnet_config() -> ChainSpec {
    let boot_nodes = vec![];
    ChainSpec::from_genesis(
        "Staging Testnet",
        "staging_testnet",
        ChainType::Live,
        staging_testnet_config_genesis,
        boot_nodes,
        Some(TelemetryEndpoints::new(vec![(STAGING_TELEMETRY_URL.to_string(), 0)])
            .expect("Staging telemetry url is valid; qed")),
        None,
        None,
        Default::default(),
    )
}

/// Helper function to generate a crypto pair from seed
pub fn get_from_seed<TPublic: Public>(seed: &str) -> <TPublic::Pair as Pair>::Public {
    TPublic::Pair::from_string(&format!("//{}", seed), None)
        .expect("static values are valid; qed")
        .public()
}

/// Helper function to generate an account ID from seed
pub fn get_account_id_from_seed<TPublic: Public>(seed: &str) -> AccountId where
    AccountPublic: From<<TPublic::Pair as Pair>::Public>
{
    AccountPublic::from(get_from_seed::<TPublic>(seed)).into_account()
}

/// Helper function to generate stash, controller and session key from seed
pub fn authority_keys_from_seed(seed: &str) -> (
    AccountId,
    AccountId,
    GrandpaId,
    BabeId,
    ImOnlineId,
    AuthorityDiscoveryId,
) {
    (
        get_account_id_from_seed::<sr25519::Public>(&format!("{}//stash", seed)),
        get_account_id_from_seed::<sr25519::Public>(seed),
        get_from_seed::<GrandpaId>(seed),
        get_from_seed::<BabeId>(seed),
        get_from_seed::<ImOnlineId>(seed),
        get_from_seed::<AuthorityDiscoveryId>(seed),
    )
}

/// Helper function to create GenesisConfig for testing
pub fn testnet_genesis(
    initial_authorities: Vec<(
        AccountId,
        AccountId,
        GrandpaId,
        BabeId,
        ImOnlineId,
        AuthorityDiscoveryId,
    )>,
    initial_nominators: Vec<AccountId>,
    root_key: AccountId,
    endowed_accounts: Option<Vec<AccountId>>,
    enable_println: bool,
) -> GenesisConfig {
    let mut endowed_accounts: Vec<AccountId> = endowed_accounts.unwrap_or_else(|| {
        vec![
            get_account_id_from_seed::<sr25519::Public>("Alice"),
            get_account_id_from_seed::<sr25519::Public>("Bob"),
            get_account_id_from_seed::<sr25519::Public>("Alice//stash"),
            get_account_id_from_seed::<sr25519::Public>("Bob//stash"),
        ]
    });
    // endow all authorities and nominators.
    initial_authorities.iter().map(|x| &x.0).chain(initial_nominators.iter()).for_each(|x| {
        if !endowed_accounts.contains(&x) {
            endowed_accounts.push(x.clone())
        }
    });

    // stakers: all validators and nominators.
    let mut rng = rand::thread_rng();
    let stakers = initial_authorities
        .iter()
        .map(|x| (x.0.clone(), x.1.clone(), STASH, StakerStatus::Validator))
        .chain(initial_nominators.iter().map(|x| {
            use rand::{seq::SliceRandom, Rng};
            let limit = (MAX_NOMINATIONS as usize).min(initial_authorities.len());
            let count = rng.gen::<usize>() % limit;
            let nominations = initial_authorities
                .as_slice()
                .choose_multiple(&mut rng, count)
                .into_iter()
                .map(|choice| choice.0.clone())
                .collect::<Vec<_>>();
            (x.clone(), x.clone(), STASH, StakerStatus::Nominator(nominations))
        }))
        .collect::<Vec<_>>();

    let num_endowed_accounts = endowed_accounts.len();

    const ENDOWMENT: Balance = 10_000_000 * DOLLARS;
    const STASH: Balance = ENDOWMENT / 1000;

    GenesisConfig {
        frame_system: SystemConfig {
            code: wasm_binary_unwrap().to_vec(),
            changes_trie_config: Default::default(),
        },
        pallet_balances: BalancesConfig {
            balances: endowed_accounts.iter().cloned()
                .map(|x| (x, ENDOWMENT))
                .collect()
        },
        pallet_indices: IndicesConfig {
            indices: vec![],
        },
        pallet_session: SessionConfig {
            keys: initial_authorities.iter().map(|x| {
                (x.0.clone(), x.0.clone(), session_keys(
                    x.2.clone(),
                    x.3.clone(),
                    x.4.clone(),
                    x.5.clone(),
                ))
            }).collect::<Vec<_>>(),
        },
        pallet_staking: StakingConfig {
            validator_count: initial_authorities.len() as u32 * 2,
            minimum_validator_count: initial_authorities.len() as u32,
            invulnerables: initial_authorities.iter().map(|x| x.0.clone()).collect(),
            slash_reward_fraction: Perbill::from_percent(10),
            stakers,
            ..Default::default()
        },
        pallet_democracy: DemocracyConfig::default(),
        pallet_elections_phragmen: ElectionsConfig {
            members: endowed_accounts.iter()
                // .take((num_endowed_accounts + 1) / 2)
                .take((13 + 1) / 2)
                .cloned()
                .map(|member| (member, STASH))
                .collect(),
        },
        pallet_collective_Instance1: CouncilConfig::default(),
        pallet_collective_Instance2: TechnicalCommitteeConfig {
            members: endowed_accounts.iter()
                .take((num_endowed_accounts + 1) / 2)
                .cloned()
                .collect(),
            phantom: Default::default(),
        },
        pallet_contracts: ContractsConfig {
            // println should only be enabled on development chains
            current_schedule: pallet_contracts::Schedule::default()
                .enable_println(enable_println),
        },
        pallet_sudo: SudoConfig {
            key: root_key,
        },
        pallet_babe: BabeConfig {
            authorities: vec![],
            epoch_config: Some(node_template_runtime::BABE_GENESIS_EPOCH_CONFIG),
        },
        pallet_im_online: ImOnlineConfig {
            keys: vec![],
        },
        pallet_authority_discovery: AuthorityDiscoveryConfig {
            keys: vec![],
        },
        pallet_grandpa: GrandpaConfig {
            authorities: vec![],
        },
        pallet_membership_Instance1: Default::default(),
        pallet_treasury: Default::default(),
        pallet_society: SocietyConfig {
            members: endowed_accounts.iter()
                .take((num_endowed_accounts + 1) / 2)
                .cloned()
                .collect(),
            pot: 0,
            max_members: 999,
        },
        pallet_vesting: Default::default(),
        pallet_gilt: Default::default(),
    }
}

fn development_config_genesis() -> GenesisConfig {
    testnet_genesis(
        vec![
            authority_keys_from_seed("Alice"),
        ],
        vec![],
        get_account_id_from_seed::<sr25519::Public>("Alice"),
        None,
        true,
    )
}

/// Development config (single validator Alice)
pub fn development_config() -> ChainSpec {
    ChainSpec::from_genesis(
        "Development",
        "dev",
        ChainType::Development,
        development_config_genesis,
        vec![],
        None,
        None,
        None,
        Default::default(),
    )
}

fn local_testnet_genesis() -> GenesisConfig {

    // for i in 1 2 3 4; do for j in stash controller; do subkey inspect "$SECRET//$i//$j"; done; done
    // for i in 1 2 3 4; do for j in babe; do subkey --sr25519 inspect "$SECRET//$i//$j"; done; done
    // for i in 1 2 3 4; do for j in grandpa; do subkey --ed25519 inspect "$SECRET//$i//$j"; done; done
    // for i in 1 2 3 4; do for j in im_online; do subkey --sr25519 inspect "$SECRET//$i//$j"; done; done
    let initial_authorities: Vec<(
        AccountId,
        AccountId,
        GrandpaId,
        BabeId,
        ImOnlineId,
        AuthorityDiscoveryId,
    )> = get_100_validators();

    testnet_genesis(
        initial_authorities,
        vec![],
        get_account_id_from_seed::<sr25519::Public>("Alice"),
        None,
        false,
    )
}

/// Local testnet config (multivalidator Alice + Bob)
pub fn local_testnet_config() -> ChainSpec {
    ChainSpec::from_genesis(
        "Local Testnet",
        "local_testnet",
        ChainType::Local,
        local_testnet_genesis,
        vec![],
        Some(TelemetryEndpoints::new(vec![(STAGING_TELEMETRY_URL.to_string(), 0)])
            .expect("Staging telemetry url is valid; qed")),
        None,
        None,
        Default::default(),
    )
}

pub fn get_100_validators() -> Vec<(
    AccountId,
    AccountId,
    GrandpaId,
    BabeId,
    ImOnlineId,
    AuthorityDiscoveryId,
)> {
    vec![
        (hex!["d41e0bf1d76de368bdb91896b0d02d758950969ea795b1e7154343ee210de649"].into(),
         hex!["382bd29103cf3af5f7c032bbedccfb3144fe672ca2c606147974bc2984ca2b14"].into(),
         hex!["01a474a93a0cf830fb40b1d17fd1fc7c6b4a95fa11f90345558574a72da0d4b1"].unchecked_into(),
         hex!["48640c12bc1b351cf4b051ac1cf7b5740765d02e34989d0a9dd935ce054ebb21"].unchecked_into(),
         hex!["50041e469c63c994374a2829b0b0829213abd53be5113e751043318a9d7c0757"].unchecked_into(),
         hex!["e082231a2317c115c80fc8d041dee85c2da42a5d06b79d1d28a698122665c72f"].unchecked_into(),
        ),
        (hex!["08050f1b6bcd4651004df427c884073652bafd54e5ca25cea69169532db2910b"].into(),
         hex!["8275157f2a1d8373106cb00078a73a92a3303f3bf6eb72c3a67413bd943b020b"].into(),
         hex!["acdfcce0e40406fac1a8198c623ec42ea13fc627e0274bbb6c21e0811482ce13"].unchecked_into(),
         hex!["0ecddcf7643a98de200b80fe7b18ebd38987fa106c5ed84fc004fa75ea4bac67"].unchecked_into(),
         hex!["6ac58683d639d3992a0090ab15f8c1dcf5a5ab7652fc9de60845441f9fc93903"].unchecked_into(),
         hex!["1a90ef85a2ba2c167f066d6d1fcdfd3bef6a902fe59f31ad0782df50be317e3f"].unchecked_into(),
        ),
        (hex!["861c6d95051f942bb022f13fc2125b2974933d8ab1441bfdee9855e9d8051556"].into(),
         hex!["8801f479e09a78515f1badee0169864dae45648109091e29b03a7b4ea97ec018"].into(),
         hex!["e493d74f9fa7568cca9dd294c9619a54c2e1b6bd3ecf3677fa7f9076b98c3fcd"].unchecked_into(),
         hex!["0c4d9de1e313572750abe19140db56433d20e4668e09de4df81a36566a8f2528"].unchecked_into(),
         hex!["c2e2a133b23995a48ff46cc704ef61929ee4a29b5fa468e41019ac63f3694e1f"].unchecked_into(),
         hex!["82933df3e14db20e191594f9caa9650b4a4232e3b7ade919ec76aa9bea460c29"].unchecked_into(),
        ),
        (hex!["ac8fdba5bbe008f65d0e85181daa5443c2eb492fea729a5981b2161467f8655c"].into(),
         hex!["ac039bef73f76755d3747d711554f7fb0f16022da51483e0d600c9c7c8cbf821"].into(),
         hex!["392c51bf0c08f89cb1e091782d81359475d780986968ba7f6fa60f41feda6bf7"].unchecked_into(),
         hex!["ca2245b6fa117fab9353a2031104d1d5d62e311957f375762324e65d71127465"].unchecked_into(),
         hex!["e68c9a2ee25e1999a4e87906aea429f3e5f3fc8dc9cd89f423d82860c6937b2e"].unchecked_into(),
         hex!["70d6914a23fbb841de016a42e9d055fabc651d6a42ce9b4939bd4c749dc43f10"].unchecked_into(),
        ),
        (hex!["ee41a70022c17745df35ef7d7ad5b520f5ccdc2a18a72b70067d6e4a0acaea1c"].into(),
         hex!["228b0fa7745e79be8fd061f4549464949ed0adefbec2fdb9c4896b59f4af9432"].into(),
         hex!["804a16cf6f9e22a6fc8de8f1e063c2f58a8794bf9cdca68e8744844f29db5d6e"].unchecked_into(),
         hex!["ec80e620f1c4e43ca49f941d69ad67fcbd79f8f9b8324718023b9b0201149528"].unchecked_into(),
         hex!["a8bc539c89c2f0e6a35959e4a5d074ab0f65f0785e29fad78ce2eaf95e48264d"].unchecked_into(),
         hex!["58a3c7dec15654a69b4b04480e3d2583874d2dbf7860132ecb99d05c5bd15577"].unchecked_into(),
        ),
        (hex!["56586fa668f5e871d045b04b6e1f5e4dbfa8455e426014c95b84e53acfc8c951"].into(),
         hex!["8a86dc0fa73ae285295073c2d67f4545a99a162485dde9b6e910235a9b797417"].into(),
         hex!["1e3472af73e0908f7935b227c9f11e65360fc1845f77a0283690c2f429356e58"].unchecked_into(),
         hex!["5a83f11465638030852cdbf1f8e76c008bd33aa87d5fe86fddd2a39a87d06157"].unchecked_into(),
         hex!["76254d99fc8fab493e9b7b337339888d732fb6ef082bfba4bf8516c0ca194336"].unchecked_into(),
         hex!["dece192c37a68154e11a4893ce13727e6859935cd8395fadf4b3e8c325e5d76d"].unchecked_into(),
        ),
        (hex!["a0e2ecdb55bbce3248f0769332124d8e619e38f1fea4c72765a0ca96072e7133"].into(),
         hex!["a8819f3b3c79adb1be1d72fcd04417f278de9d9785f74c7b948a026d9863e618"].into(),
         hex!["3945003240e33404961ee0f1c3f7682700cab8d9f8d122ea36132c21b230dc3b"].unchecked_into(),
         hex!["d66fe34387d276b2c7b45b2a6af0e3a64e96ef133f4a8137fd500d121db88a09"].unchecked_into(),
         hex!["aa667a5503938d7e4570ed86ab47fd7e9f244a9aa30a3017e769e72d226e2d55"].unchecked_into(),
         hex!["daf4fa9e263558d7068ca8eb4b339c8399cf2f7f8327ecbfa063e683e7b8235d"].unchecked_into(),
        ),
        (hex!["b60254ad4b6477bb0c22cf24d527bf03a326937f04ebbbc6dd8712de4b919170"].into(),
         hex!["bab81add79ef9f109d6f0dc8a0dffce49d32a0e8a529e9b4484027f647263005"].into(),
         hex!["17ac0168fb844e52a53ebb10a24bd4765e19efb2104617019f477332c41998fa"].unchecked_into(),
         hex!["58173bdeade9ac4ba1f0157f7656632647be27a915469410eb1b5dbbf11cda7e"].unchecked_into(),
         hex!["e875c25fd199c3483643c62b766cdbb445adc15295e6e027ed89aaa1a94d990c"].unchecked_into(),
         hex!["54d88811431fc027a1ee0a40cdcd5f2e2b70964f8e2c77d7e62532be4c5b0c50"].unchecked_into(),
        ),
        (hex!["dadedcc5428f0b3a8736512f521349b41b11b640c59cc0dffda4ced5f57e8137"].into(),
         hex!["8889fd5c6b44cbe1b868105062070732ace43652a7b59dcb3c82e7d3d3ba7048"].into(),
         hex!["a3eb02f28d073ff1ce9b62c30449b640e5fe6a60c70f8e8ca359a26be34b699a"].unchecked_into(),
         hex!["da0509e11b74433752624ce404f97932224543ff2bb256273c23cec9bdab4302"].unchecked_into(),
         hex!["18d6fc581e22d73d00de025c4b00464e60faac75aa12713c966d7cbe618d8678"].unchecked_into(),
         hex!["aae0fee2891113eb8a1a6673ea264469f304e405341b8ff7020219e637e1815b"].unchecked_into(),
        ),
        (hex!["b25ed2d7ed6738e1ffcfb66b801fecd2829b411a22b512ddeecb8ba744918c23"].into(),
         hex!["2a310dbb66712bbd55bbc74d1bec334f6c11206f1ab89cb1a89ab0f3fbe9cb7e"].into(),
         hex!["fc1dfb4bcd5ed24c5c0fc67045efffbe726e25ad2201bee184d1c13d9a14e7e3"].unchecked_into(),
         hex!["926ca02b46a60aa30c087a7715e457389bc25465064c61619dbc9971cd384d6a"].unchecked_into(),
         hex!["d2ea40e16a8e43d23f403fce01b35bd8552cfb7cd1e78901a405035ff727360f"].unchecked_into(),
         hex!["4497103761a5fa9bba312f7db0525e1c804a4e5071672eceac0fd65ad5326262"].unchecked_into(),
        ),
        (hex!["e60de0125b08f6af969ad575188e59279f317b8c0b1e137ad8c72d83c2fd6244"].into(),
         hex!["0c11763eaf342ce024fa25cba95b66f4dc7b8b1f2c8a2082773f764e246dd378"].into(),
         hex!["68bd433ead6996a5a5e9997670265165fc2c38750561cafe57ec2c85fa3e4dd9"].unchecked_into(),
         hex!["b45b97d7b7806c70ab821294376d885ed2d6ab2281b98ed09968c909ce8aa34d"].unchecked_into(),
         hex!["24209c26466b2bbfba449866a95e07060a4b37607d3596d5d75dbe173e555558"].unchecked_into(),
         hex!["10880676cb5fa577d2622dbcf54493bc8fdfd8ff68b99e5f2626aec1dbd5ce12"].unchecked_into(),
        ),
        (hex!["865fd7903ba4852af6a040fab0094460423f8751269413ea037150af4a2bc33d"].into(),
         hex!["88e56b574486dba28ee3aef91cd1455a935ebd190f06ec79064fa234294dab0e"].into(),
         hex!["cd024c7227790d1dba5d367b06d2950359a54139d863ea5235c2bf63fe6cd224"].unchecked_into(),
         hex!["a696cf233de9a0ce30e0ce16ec471eff0dc9b80d256a7af321d412c5c1d6eb6f"].unchecked_into(),
         hex!["c47417dcbfaabcbba4a0d18b66431748a35cbf3a1b60c879f8f429bffd6e4e57"].unchecked_into(),
         hex!["dea0fec4324bc45edbd9046e0584daa7040613eade8041154e98f7f939490d04"].unchecked_into(),
        ),
        (hex!["eca1901eeae4dbdc2270f51731ab0cd70a1c788fe2af8fb135a7e2f8481ee015"].into(),
         hex!["8a0531001a2caa09fc5714f5c73999278bae5681d9a9f806ceffbcdc89d6ca1c"].into(),
         hex!["e5e9f7272ab44d6070139410e3ef13a5104f96464b495ed651b98e6cd306500b"].unchecked_into(),
         hex!["f61abac7f7ed6571c2f9d74217b3e840672b56eb8bcd9346f2efb9db8962bd5c"].unchecked_into(),
         hex!["d2cff1e08941599831f686a1b74589d636caa71cd3a6fc48e902b54eb2401417"].unchecked_into(),
         hex!["32cd8b1256207651de09b8e3a37a4d8e5137ecb263060e970f230bf0f938ec4b"].unchecked_into(),
        ),
        (hex!["d468e92459f82e8a995288757a79f3c64b07a4f5a967f89227b8e9c0ed6c4077"].into(),
         hex!["8212a48b2114399aa83acc2f070673abd4822db9021751fc11c0dab1f7e67274"].into(),
         hex!["9da369f21fba17c2cfa5e6b1c4c8f096af0f7bbe0179d76ab778fcbae608fc72"].unchecked_into(),
         hex!["808a41a74dbda45230a5b3fa5930d3fda5aba3282e9dfadb83e66a0c40ebf13d"].unchecked_into(),
         hex!["bce5567d6678458f208c26a82088a1566068ee2f70e04b901a0d0245a48e067e"].unchecked_into(),
         hex!["e079845db41ef53c48ee5b877d120c216a5e53d5a1c722748d8539c915a66851"].unchecked_into(),
        ),
        (hex!["42e296b39f459312ce0206d0063714530a8d69feacff0a5e49c71cd59426924c"].into(),
         hex!["a0ec2f77696578871943f8ebec02f727107c97ad50902ed23bad3922633ec35e"].into(),
         hex!["02c3d02ddeae100cd7acaf7b80491f3eb6d02a9ef7946222df318a31d507a2d8"].unchecked_into(),
         hex!["700ec7b85535b195c1df09c21b41d77ecd1998bddca7621a45ca4ef2ac937b36"].unchecked_into(),
         hex!["9039a75569281395fc8cda9666c8c80cd9118c71b1e4724f5228c3f194248e0a"].unchecked_into(),
         hex!["ae93ffb79c263b3de6d40097d17032eaf20a1eb1f53cc34857f4847a7223ba61"].unchecked_into(),
        ),
        (hex!["bc4b33a8aaa91e2a0eb12b5b1c4f10acd0a86621f548be5a2705997b1d0e2200"].into(),
         hex!["c82db5f6dff2638a7a7b6bcdba7328616672f2ee694f386cb46e27f7c474b528"].into(),
         hex!["0298938dc11b2d2c871aa1e9b18d9794109d9015738b546eaf24004c90078c83"].unchecked_into(),
         hex!["fe0a5cb90354b23890d258d6824b5fb421bf5611a12fef44d0684b5bdbfb9e58"].unchecked_into(),
         hex!["e2c94c04909752fd00cf163eae35e43670e7509dd6da224d7bd89a843c10a203"].unchecked_into(),
         hex!["12f2b3e702d0947276642310e3d330c5d8991f4162a9749e424deea06687fa70"].unchecked_into(),
        ),
        (hex!["7ea0aeacbb7a4631163bc6e8f50584f1d61b15a2dcf42c4ff637e7d532acb479"].into(),
         hex!["86d1798bea1c4c5ee3b6106aabfe38e88ca57ea01f205772f0fd0536a5b8fe1a"].into(),
         hex!["9ba6c4f4b919fa813bedca912037adf607e87a80d41141c5abd3f269fe0a2188"].unchecked_into(),
         hex!["688af91f287bab8d70105620329167cdd945bcf5d5db7d1ac19b2df5d16e7a70"].unchecked_into(),
         hex!["8c9fc6960dcaf5be552c0211957678cc4744a560a1650434092b8157f1a9d235"].unchecked_into(),
         hex!["56d004ced7bfd1b69cc9f8a0584ebd18bfab2a0275fe4ceaa313296469c4900a"].unchecked_into(),
        ),
        (hex!["1aff6db229955640bdde344453deb0f789378c783f8cf6b3c7da1d3182a51013"].into(),
         hex!["f6ad480dacb11b44a428634fe4b21b13dba218e8318a931e8d059751bd6cf57a"].into(),
         hex!["c318460eb286f32b87e00817d62a8dd1dc730b5bdba2eabbd0945779a8ad1ae3"].unchecked_into(),
         hex!["9253c7849d110ac0057c16bde3d8d5a7efe129748bd58d931364467882b22028"].unchecked_into(),
         hex!["c6c7f6a619573de034ddecb9320edccfc829e470d20e2dfd0675d304744d6666"].unchecked_into(),
         hex!["d6054def6daf988cb52b100b2ecb33d36b26cf84e16ea5519acbdb893866d36e"].unchecked_into(),
        ),
        (hex!["bea90ba8239e68fb0488a2ad084f4a9b9365db3ed0d00ede459fe2452fd5b322"].into(),
         hex!["566fbd30cd0e1ac6de1550d19f693c1fd47b50ae5a49cf0b697cf8e3114ba827"].into(),
         hex!["9fdda49d18aec76c4bd6f82dec2f66eb2b1352a2f731f18dd92e43d629774f1d"].unchecked_into(),
         hex!["64d5e16a841711ce59c12df1e215f3e390c585585c4c5462012e47992d7ff35e"].unchecked_into(),
         hex!["f2d98ba4101137b888e0293c2bf9e4aa59041cf92fb17fa5bdd914e9b075484e"].unchecked_into(),
         hex!["7c9fb3aeff1dfcfb345585574b0565e0065798dba04c5100a38d147248788176"].unchecked_into(),
        ),
        (hex!["0835f42281dbff1e40dbb13491d0005d4aa049825cc3be0cd451facf586fcc1a"].into(),
         hex!["d23b926594ff37c7edcda4d187d35b2f487f4690cf9a7066e881dd378d9b3e6d"].into(),
         hex!["cf45472a9634e7f7a19f044f245bc36df7b9797de26018a1aa208cd420b95f4a"].unchecked_into(),
         hex!["9e04ae95c3b950c4a90b357e77c94e14290388baef2c9c16e1b400397304cf74"].unchecked_into(),
         hex!["f283ded789a79b848166462041e7ace17c1b8363f08659567e39c8dbcb8fff6f"].unchecked_into(),
         hex!["8c4f938025c0862f3eae52d8d37f6275401e197e1cd01b728ba542d3f0ead647"].unchecked_into(),
        ),
        (hex!["e2d9088b01faabc7848b006cf4274c5722d873cfb20caf4f3f3e7462c48f841c"].into(),
         hex!["aa86f180de646e8f2e0f9234b36617496dec0aa4cf8164db63117dce0d2bea2f"].into(),
         hex!["44df093e9f80b72cf0ebc050d766507547e1ce653fe7bcd41baf990948a00ebb"].unchecked_into(),
         hex!["18ecc20729ef271d69b4ed48154a57c04d79f1fb2279a3e13a77e7cef60a5e76"].unchecked_into(),
         hex!["3c2efb53bb8b696e50420855fa25ffea55b287e54146265d12cd31f541aaf772"].unchecked_into(),
         hex!["2e3b8d1a58a68ae936558b6a40bb01408d4baa0ae995c39272f1f21e05a62b7e"].unchecked_into(),
        ),
        (hex!["4aa8ef54d2fd9faff2ff490b16ec7c190c2c2a9d8a91a4ef8ebdfe8b590d2247"].into(),
         hex!["063cc37d694af0e8b0c27180c1c7a3cef5315e8fb3da1bca8199bd0a4530e478"].into(),
         hex!["78531601700285359aa2eeadca075843ab1c2a53ac71cdb73872bc1b44978b65"].unchecked_into(),
         hex!["c64660f001050bb6c63109258ba4a1b4c3ed9ab8f862a38c4d6e666fed31597b"].unchecked_into(),
         hex!["d4a852cd76679b6250c870bb4f3f97084c2415f887b0238fef258b3c3a15b84b"].unchecked_into(),
         hex!["d2e4c2ec70398ca19e4e23b37468b63a71c2821de2495cbc9f668e86d95a6335"].unchecked_into(),
        ),
        (hex!["3eb587a3c6110e4753bfbf5766ed3420567ab7463c86c6809716665871cd231a"].into(),
         hex!["ca1dd4632690a5c14780f252a9243d0f6032987ce9bfb6963b5c09c537505408"].into(),
         hex!["7051cdf8a090b7bb4d27f3de7cfc387ad4a20a5ef810f8dae6c22239a23c9c23"].unchecked_into(),
         hex!["ce74252744c04019ea8815d114b198dab3e637637e7768c154e62ed6991d390e"].unchecked_into(),
         hex!["5c6fb312df7e0f70342fea206eca24f726a0582e7e4e22c5244a5a9802c33928"].unchecked_into(),
         hex!["a8138130677d3bcc2151caceae4514547a84435f90ae67bcda8c20205e0d4050"].unchecked_into(),
        ),
        (hex!["2c864611f0beae422b1e644798275daa043e4bf765d536e28e7f40595008464b"].into(),
         hex!["cae92cdc106614b642d37d5f61d5cc80688f06e1f7d357ad6a547c14b9dfd950"].into(),
         hex!["7ae0934f15c81f21c719d40e96e3a18485b99921a675821cfaf5d4daa11a5502"].unchecked_into(),
         hex!["f84ee4dabc69b86320430b13e60208438051fdd5511433e740159859f23c8b46"].unchecked_into(),
         hex!["8c1765b21201d751f487e59ee758a7599c23ea8bd4b34d771c59bd697cdec924"].unchecked_into(),
         hex!["56e9102a89fe76a43675063a2b28f0432a3f67ce76241f5fad7c42343af32e7f"].unchecked_into(),
        ),
        (hex!["ced1bf5a261fef79f31776ba8a2f11de969e55e2a8d4451d47db45c7d5327d3f"].into(),
         hex!["92b3ffe4d02d44cff044ff574f32b0aada8a630476501aa1c0547e46f148da78"].into(),
         hex!["94d0f991c401350fce4dd7da57b66befc2ec11abed85c5f9c2d999df8f2dfa8f"].unchecked_into(),
         hex!["2862fb7756f0acf291e1a6afbe88c5c374ec9ea7d2dd7c2181ff250ec3561273"].unchecked_into(),
         hex!["9447152b2e2d61f9aa645d46e9b418c89355a5bdcc23a12f2980e1aca2b22b30"].unchecked_into(),
         hex!["f487d45a81fa3118d8875b9618e160b5d76ec163b1866f22b47c6b4319bd1f72"].unchecked_into(),
        ),
        (hex!["de86ca37660626ec969562ea07b67e2ae604c8c672ae959749a515211ab2cb06"].into(),
         hex!["a4d10874d06fceac430555a5cd3eeb0aeaae0dc42de81e480aad9f8d59f94a5f"].into(),
         hex!["faf2f0c9b1eecd294af5017ca93c0a0586314926cd76a09ffa2a9e8e2ac04aae"].unchecked_into(),
         hex!["b0487793cf3b804f75d80235852d58c1873fe78bae2c032f2cc06880278af668"].unchecked_into(),
         hex!["54d942fe2cd07b41669389263c12d5f19c0df412ac0dd9548f35d8b4dcb3eb1c"].unchecked_into(),
         hex!["de5f68726f1703a1774c5cfae67df12081c0ff7fe081b6326dd5ef66f0a85931"].unchecked_into(),
        ),
        (hex!["123d12a52cc2b66172153d942a88d82478945f8a7b008a536d697f699eeb2c74"].into(),
         hex!["fc525fa7e4239834e4316db435b9b45e6a953ffe59d2a84bcd6fa6a76499266a"].into(),
         hex!["b4eb74eedf59976982626ba84b243e5844a0e236534844a0b8ba30841b219d34"].unchecked_into(),
         hex!["2e4c669fb98a9c152dbaeca2a61ab73876c8c2afff5fac3809ab3f0e20408c34"].unchecked_into(),
         hex!["de9ee34983859d80df0ae24e5452044ccd0a39c348db1d6d77a0dc459a0f511c"].unchecked_into(),
         hex!["4e2310499b37de84af7a465b453ac658dd40344b85fa9b6c4f02e3fb68385132"].unchecked_into(),
        ),
        (hex!["3cc0b9701ec66be66afe48a90138519ae1fdab3669536410acdbd42894fc790b"].into(),
         hex!["de1a2b3ee56517b4de211d35f9f13a58ebfa91b3f7e4f0eb152d3d428fc5dc6e"].into(),
         hex!["79128d225492d3361fed573b8ddffd2fdc800037975a90b940694d6b35b77606"].unchecked_into(),
         hex!["f01df4fc1aff87c76a77760a364cc3193a1c78549a28c81a1f234d2f5e225a7e"].unchecked_into(),
         hex!["ae71aba65a2c3410296f8223179fc0b3c344a4823bceadd1bb84414333a35760"].unchecked_into(),
         hex!["0c61be547c30ced678fdc5bd9960b6894dbad15b1f6cccb42b5efe9c5cdc190a"].unchecked_into(),
        ),
        (hex!["2e999486bc3ecf355e33f7bd6be81a8faaf3aa4c9522d1d5abc2271b98664549"].into(),
         hex!["249570699579367ddc572da12aac2dcaf3298738a3b6b0e3f49f2b5780d83f17"].into(),
         hex!["e179823336d56722ecda41f07daf122cd871c71f719b8446d27b2078738cc375"].unchecked_into(),
         hex!["a63815d5ce6bf880a0ac40ce4f23c2f9a03162173919a7f50a8362cf2edcd554"].unchecked_into(),
         hex!["2ed4959539fcf05657d72b71fa214cd079a3e44d1495ffd1fa657e341d8f4f5c"].unchecked_into(),
         hex!["920bd567411fce142f14351d950c8320d9300881e0a4c70f811e77d3ff992004"].unchecked_into(),
        ),
        (hex!["34a5d9f667b39afd8dbefcecb4a462387adfcf0e121b08f2ae7a2a9d3b46700b"].into(),
         hex!["420d0c3a29575e184254729483ebbb04fe3c489be4e5ac9f59321f955f786b44"].into(),
         hex!["f6c9a66b0bc21e657faa65e30b69afa176ebd589a39b20b5d99b4c0099578530"].unchecked_into(),
         hex!["8a5feb403f98d7f5aebdb4ed52780046c500f108a6e9b86629ee619bc6e10e41"].unchecked_into(),
         hex!["fa44027a17b393bbbc6fdc9e4d9079fc5ee7da799ae383f24cb21c3e196d2f04"].unchecked_into(),
         hex!["82e768091fd5552b7f1e1e506106c54c566c6adbc1ddb9b3d5f75551a3ec2010"].unchecked_into(),
        ),
        (hex!["747ae889af02be85224f45a6957eef03b1b060a0b81dfe30d4f553d9a368053a"].into(),
         hex!["5eb2df2867ee71577bacf29463c83fd12ce019bd5fc1f1c8718eae564e7e6228"].into(),
         hex!["40107fdbee3e8f55a209f59c20f1ecfba2deb2077fac6c35cbf1589284b03f8a"].unchecked_into(),
         hex!["b0517a3f25d93893947037c5dda700aa38b5f748ca2a1543ea87a33b2472774b"].unchecked_into(),
         hex!["58bd82d6e326ea92f478b0e09cbcb198502226bbbb3ce1b1b542a40da2280008"].unchecked_into(),
         hex!["c0e6a7e513ea9df1c1cea7f4627b7381fffc3ea5f4bb11b562d89e1344a83972"].unchecked_into(),
        ),
        (hex!["7a1650bae854d215b1a6f0f2254edef52bf403e14af1c8162d22c055d4a1fb5d"].into(),
         hex!["e673d6f2812a5c8bcd992fb87d60b1d2adde1728dc175eadaa64ae16df624238"].into(),
         hex!["f782b903fa8bb4a278ee5fb5ff5c17fa03e0b1a65dea5a7e37218ef4d5078d5f"].unchecked_into(),
         hex!["d2cf73465acbfeb6c461cd318d81956a306735e78d39e2850552c0f88397c52d"].unchecked_into(),
         hex!["9675b97d349c64c4382a0e6d4b03fd9018f99ab3413aee3970569340bd5f1803"].unchecked_into(),
         hex!["54e674179353e0128db6fd94c32e8e7166ed72e736524216a2f1fd29c2a43507"].unchecked_into(),
        ),
        (hex!["6e015332ffb3e6010b0ef8e16670b1f8bd58e7f0f92f92c5d26ffebab935b87d"].into(),
         hex!["687bbf9675a43968d7459d12b60ba7380a536ed2f8366ec9b5730698b1b50a51"].into(),
         hex!["0f5742dcf439a1f5ce8b432f0dbec38d4be39a7a159b0dbc388c3dea2329f998"].unchecked_into(),
         hex!["de38df2ae03665f352b165edb6341dcc9842b55494ae04cde8ab46c752354108"].unchecked_into(),
         hex!["261d7dce4c9b079644b5dfb5886f0d208d12323d19615090a5d476e5a08a1b15"].unchecked_into(),
         hex!["a6980bf0815e469d965158650fa1dff901b08011a4996a462af2bf6b606bbe78"].unchecked_into(),
        ),
        (hex!["56a8b9b5690051deb3d0e6aba6b0348d7d5401d797f1631a0cdb6b94413fbc0e"].into(),
         hex!["6e0b20a9b23b2056f1929f5e7fa5011295f8fb004427dc81ab01328a7a90304a"].into(),
         hex!["6a54c28ac31aaac19f74b90a883a704a2a8cdc7bc480d97475c492334d0f262a"].unchecked_into(),
         hex!["725566a60632da17b44d01c3a8631a15c566c86a0fc40d59a85a55a84fd34652"].unchecked_into(),
         hex!["285adf884a178569fd52dc30b79b0a1e9229f0abff401210481b1769e942a12c"].unchecked_into(),
         hex!["d213ac80c554c18ebfddcce8bb8b227899bae98c6b31571f7283af73611fc807"].unchecked_into(),
        ),
        (hex!["26db8020ce3e3a58a1ea49adad365da9e50ef961acbe483a2b4a2612f0c3a079"].into(),
         hex!["c485b5257e84ce3d3f09eaf84de0ee32472762a59ea71861cb90615040d32455"].into(),
         hex!["fd4a551adb68b677db2f3cb5162d8cbf18e777cbea3e207355eb41cb83858500"].unchecked_into(),
         hex!["1a16a661931056f09629126d0e9ccbed5b2d4ba915cefe7eb97761866d28687c"].unchecked_into(),
         hex!["cad697a68fffd594a4fb199754458b952229008519107cc5fd78f01f9fba5206"].unchecked_into(),
         hex!["c0c386b7adff7ac1fdfe4edfba3d7467680eed43c0c56dd33a3207c8ea6ae847"].unchecked_into(),
        ),
        (hex!["ee53f24e1352df79835c84659175ddf5b936bf7c01c14048c929b4f4827f4c17"].into(),
         hex!["660255ee3441f082f11d26db6ac007a2034fb0211f9fb0496053f8c7ca075e06"].into(),
         hex!["857ef95a0d07ad262018afc2e5ff9f6758370885c3ea5a4db7789e1cca009e37"].unchecked_into(),
         hex!["60f32ef353b15887c5c2d04eee6dc80f1bcb5eaeed9320a3ccc4b29b5cf8f320"].unchecked_into(),
         hex!["7a4ac7121ff2732d11d359d375ed2f2287c66f679f145d9be9552c2424d0931d"].unchecked_into(),
         hex!["e66a2872639858c33a80a435e649e2238c7ce21876731a58fa2554517bf50968"].unchecked_into(),
        ),
        (hex!["9c17986afe1d10167e868f3f0326c61e1b41243b6a32068140f694d8788f931e"].into(),
         hex!["5a3e667c594349bf5ed6539d342d855f127cb3750c7cdab79d86cb4e38ea4455"].into(),
         hex!["80e7bd96f49a11fc2db74446dc4379f3dc85f0268bd414f32111ab2145a9ff1c"].unchecked_into(),
         hex!["c86f384cf6d3bd24d3c5c27ff9b07b5271d70b710c64832fe0381ebceed64967"].unchecked_into(),
         hex!["de7ac91a4c2b10f86acbd55d17117f55dc966023c0b314f195fb0a14e0724553"].unchecked_into(),
         hex!["0ad3bf1e594634e350e748d4e34111c31bd7b8261bcb8ebd7f466dc41aa0c461"].unchecked_into(),
        ),
        (hex!["eab2e2fa0dc35330201bc10933fbe3751e1f97607b58c38ee73505f6d70ce675"].into(),
         hex!["94da21311bcf9e72edd5aef833e30c939f224e8fafec3dd338f0371b399e7674"].into(),
         hex!["72b4a0c964f314a83ef48e849ef5dce7488af4b282940eda7627ebc190eb0186"].unchecked_into(),
         hex!["0ec54b25dbf4320c28996cf64bd72e9302cf9e8aaa334ebe588e05355fb23368"].unchecked_into(),
         hex!["2e1e31b82d1aeddc89bc85c39223f3890f10979aaa2b530db1cb1a36cae5851c"].unchecked_into(),
         hex!["9e75a1663afa46f5d5b28a5e95df90b2ac770859a75178ddc1d3518cea15f803"].unchecked_into(),
        ),
        (hex!["d490de1d7c5804b4dea8349248ef9c42fe4d6c55c57acb95e97ded5fc562de13"].into(),
         hex!["98aa436aef1eb27f1fb4ca51993b85df3510b4a0443329dcf0ad028827715512"].into(),
         hex!["a3babaefd588dbd82d4c4a5c4d158a8e7feaa13d1b177886e91fad2c576ac419"].unchecked_into(),
         hex!["9e2a480576cfcda8f17175a05c5c0e2098295964bef99a88654e00bd8bc6c574"].unchecked_into(),
         hex!["5ab0f7c4af04576bbc317a7ebced2acf224c2d41adc3e3b8832f046f87a5d153"].unchecked_into(),
         hex!["e6351c40fd0b1fa98b86c6fc1d891f2cdd62da003498c396bbb1a3e99067b631"].unchecked_into(),
        ),
        (hex!["20e21d831b29935d7f8d663b6e9fddf773b23ff23689a813d882d57c696db67e"].into(),
         hex!["d4231c9e1f6049a63e01d00702d0071bc2752284d6041f20cc98e6c5ee4d1823"].into(),
         hex!["e5928c7f3f23b57f1257d69c86ea5884f4ded8321706995058657db56d24eef7"].unchecked_into(),
         hex!["3a242a886bd1bb7a8a07ab258a8999ae91bbeff229f35b7c0cb0c1461251831b"].unchecked_into(),
         hex!["e6916f9642108acdaa849abdf4c7dcbac365aa3583960e336a7dbab4f105a264"].unchecked_into(),
         hex!["cac667c3167db57d8f665c744edac8f43f65c7dbf605e789dc55a26e0d387f3f"].unchecked_into(),
        ),
        (hex!["d485b0d82ee3d1dec70370db438c25e37323fdb789f3d47c04de6bee6d8bbd29"].into(),
         hex!["4ec9047acf6f2d4e7e3d7fd73427eb2bb97de4ef86cac0812be0ff957364c94c"].into(),
         hex!["498f051e44e33d3689baa455280799882363d85c3392038492b9ed303fd7e3a0"].unchecked_into(),
         hex!["ec4acfcff599bb4f1397e35ba210d41943b09058c7abac4ea0f635d9533f2244"].unchecked_into(),
         hex!["6ac64132b450d9dfabed5de70c894e6da739a351b43d2b322ecd26edcdc44168"].unchecked_into(),
         hex!["00cddcbe708c9fe54304c2d46b569331c169efb02eaab9b3f9a09cf8990b4b52"].unchecked_into(),
        ),
        (hex!["f2b7c24d1b0a74cae2f1a1a7cd92672b778ab537f1360543ff2652541fed2424"].into(),
         hex!["1a0ed26228a3aca19239f67dc2ee69fb0a7a742294d50c5f9226427bce1b257c"].into(),
         hex!["8f30257933fabfc989508b6278866503f766fc0c7b8372af88aa3c31574e0645"].unchecked_into(),
         hex!["ee797f8c469410062d826166d06d2f5eb8ba53fe2a8b9025829ed0b458ba176f"].unchecked_into(),
         hex!["ac6d5d287303ac5d6b02b0261a0191b8f364438c630c3c451060721f3a20d94f"].unchecked_into(),
         hex!["94361b9b49869c1a3295fac0ba1b71e65395080ab2ed850f381aff85fea8a315"].unchecked_into(),
        ),
        (hex!["b0583f78fae595f812451fbc18cb5f92cdc2b6c92957dbdc7837705536db6015"].into(),
         hex!["de07ca1b836d1576b557c229e4cb5b06539e752bcd9b4995d6259bd4d357994a"].into(),
         hex!["0264d78e9174ce14813da125a9e5e19d1584d8d30ba7d63dcf57ab33ac1791a1"].unchecked_into(),
         hex!["9e9f95078c4649801c9700082dbaa4ed149fa0d785f88d277a98d5f4387fe77b"].unchecked_into(),
         hex!["023e63cd2d3cbfe97e660457b1c588d65093d27df74b0c4f25a622b81f1d7d12"].unchecked_into(),
         hex!["d404f7d8ac660d2aa67f25c26e2efe1151ba42a2370ad073f331f86741489636"].unchecked_into(),
        ),
        (hex!["e4b2459f76b673bccdee2c8a4824ffed2544a8cc471d9008a85d2a6418a0ba58"].into(),
         hex!["3012cb699c811da16d4dc5cf9df34bf90f8dd5f867a2da5708891e8b3f27524e"].into(),
         hex!["7f7c16e512cecd2a0706f35b89acef0a0a173fa3d0906e00f6f3dbd4f87dac01"].unchecked_into(),
         hex!["d40b6677f1e21fdb97abadef72c1514c2a35c6c3fa08bb462604cfcb34baba5c"].unchecked_into(),
         hex!["04f7e1da3a6197773888927bfaa4159fb09a2b9d2b13b01079744fe9f92b5342"].unchecked_into(),
         hex!["68fbb23b8d2d6a13e8aac72b18ee86b4797ef923add77e5447cdf7484f729b0c"].unchecked_into(),
        ),
        (hex!["9ef6f09172ddcea0972cac2bc384534919a68f149ebc84f494394f4d852a9400"].into(),
         hex!["fe566336b868667810d1f530f6d5e2643f918049606aa52a639102b7770e7656"].into(),
         hex!["eab89ce1932049124949d7f7a2de7de3a3a6c8811a87c58d57e5e6d5845ac8e2"].unchecked_into(),
         hex!["107efbf1b49e8158f92ec5cbbccbdd3aad7d59c3eb088662be1a4dd8e326ab2a"].unchecked_into(),
         hex!["de5ec29d0d42824a821f35a0a041a3066706b552ec73052524846c13c4240726"].unchecked_into(),
         hex!["144ebf696c05ea36cd7a80aef58b093ca54c1faedd78b887efc56c5c868d4a2d"].unchecked_into(),
        ),
        (hex!["12735945ef1fb10d26de9836a213e832f1bd8693710963e57a5c669ea5afa058"].into(),
         hex!["8a7beef4b462a2a562229c0b2cd116a967dcdcaaf3636bb426fea42cc68d0430"].into(),
         hex!["b88b74be88cd32e452da866bf9087dbdb04f7766eb40cd69320e98025ef21ec4"].unchecked_into(),
         hex!["1e7a42d1e9166bc1bdae6590df9ef3ea62bef1b9e448da9423fc0711eaabf67a"].unchecked_into(),
         hex!["6e1e2d450a2818c6b950ce157033e5681efa5ae84a7a082d59bc7ca4c1049721"].unchecked_into(),
         hex!["447ef8c438b6a9c5f29b3a308ec7677c852345a6dbc8fbab9229394339d3706b"].unchecked_into(),
        ),
        (hex!["56d195fcf30bb85b782794b6e857b5651f7957c84a7d168c7f51a14ab303fb40"].into(),
         hex!["161709886ae1506f0401389a8b637de013c79fb72f9ce98188922a3106f1377d"].into(),
         hex!["83a11190ebdfcb28fe5e9757ecc292f9fd4a0a53c36f7deb6c3b53ed89719389"].unchecked_into(),
         hex!["d89ae7850a31b99884c0fe766bb476ed117a78df01bd0cf5f5d3f3a7f1b82c05"].unchecked_into(),
         hex!["7846b723e8b632b80d7e32b99aee6112cfd47625b4779ea4c67c1a00e9142c26"].unchecked_into(),
         hex!["fccd81636000834d85a9a433b3571c48ca53858142c9753c6821bfd69bd6ea0f"].unchecked_into(),
        ),
        (hex!["7609796a54aa1bbbfd948b8ebd5239f0e4c3d8775806754ea5489c01c256f41a"].into(),
         hex!["1e5f1d6deb9f42c9c3d74e13631db5b5711e4b3ba910faf83a9ad472db37e653"].into(),
         hex!["3e61a6d3e0bdce1818d47a1ae30005f147684790f91f68836647d2e89bc2a4de"].unchecked_into(),
         hex!["26eabe947005c23e01c681a97a390f6c7434297fa5652068e9120a05f9c6b055"].unchecked_into(),
         hex!["70d2bc15a7b5c0186cb78d461b2434ff076ed4060a5b79b8337bb5c351347744"].unchecked_into(),
         hex!["1813694e1f97f5ccbe4d2a0292f30fcee99f4ffab1332f074d1e3b9992d1722f"].unchecked_into(),
        ),
        (hex!["a8a27f73f97784cc42bedb70f93ef1b8bfef6411c846c53b38fcc5f57c029479"].into(),
         hex!["da124e6d534e0353e74618105ee3a3d6eda069cc0d41e3490c459a42bd60ae1b"].into(),
         hex!["15b9c9549c57ce431dedddd04a7326771183697e10aa8a437bc7a35419dcbc21"].unchecked_into(),
         hex!["fa27b604116985ead12c5889f4763b492f8a7f567076adb6fcfc78fb46c63360"].unchecked_into(),
         hex!["1c478926d0b8c8c1330767e0a7b77a9d7bc59d4f1b47c4b67e9a36362b3fff29"].unchecked_into(),
         hex!["76ce7c9dbf4327be1f2d159faff7ae10e70a2ca328c5bf815bd39073f7c6c216"].unchecked_into(),
        ),
        (hex!["22a0cf994c9e628705f474bbd171142c7b9598e15ccb698a3f00a522f121c367"].into(),
         hex!["f60cc0751f8968530070589bf3c247146179ef1668276685ef1d8dec13e78e24"].into(),
         hex!["f6b7da5798ba8636620dfec3578197fd0cedfd415b6c7097e2e23b8dae31eb5a"].unchecked_into(),
         hex!["24b5ad8257246929bfe36d40c83f71c6373c8feee7ef9e284c15250aeebd0a46"].unchecked_into(),
         hex!["848f5817c5160d8d2a9af9910644cb75884a0e2178006967e86350a588016c69"].unchecked_into(),
         hex!["dc633a9b5fabe1fe274bede3828443a65bce2cc5a0df2414f1a046b87dd4aa4c"].unchecked_into(),
        ),
        (hex!["dcbcd7175797ec8ec3168b993629c1787775c50f173fd7660806852b63e78d6f"].into(),
         hex!["52c804f5b4014ed5122d0423e0adfab7b59265365979503c3f22113488a0a91a"].into(),
         hex!["515c7ffe3f2f012d52124f33301dff8d6e527bea2f40ffb4cab19e00af60e263"].unchecked_into(),
         hex!["364b05cff20e8bffb1d0104c7cc0d544b845c921b820bd523f3cc316c4c64255"].unchecked_into(),
         hex!["d8aa58981c9ae84cedcff15f2ce81334362815fc41ba0883e346e0516bcdf54d"].unchecked_into(),
         hex!["c2c19b3f6be817d38098ccc5c8416f7428d506f60658c6c93612ed916c643c3e"].unchecked_into(),
        ),
        (hex!["9c72c624326faa51bcb49370fd1841be2fa026df52f444f75d22f3c894229641"].into(),
         hex!["30bcf76fe0824256b260c89151ee5fc9c740ba83f6ae426d6075c90cadcb017a"].into(),
         hex!["fb9f35fcc96556b24c970ed2817664b03f93ce1af417654d850ff72df44b38b6"].unchecked_into(),
         hex!["d22f389281dc3b1f268971647bab126d8683cb2e8b57b3c205459f906bdd9e6d"].unchecked_into(),
         hex!["7ea7055acbfc0ad1cd64ce7d5b5f329c95ccff0ff4240a82e7378818c8a99e4e"].unchecked_into(),
         hex!["ac6265cd695735f874af38dd1c9c5a4b5db500e0bd1095e9520081c85e037752"].unchecked_into(),
        ),
        (hex!["f0baf6341f568b310360f5d8282c70f3ad3b8e8e91ca6f53861191904dd9f209"].into(),
         hex!["18e94a984598d16f91e072a3c3e8da35129ae380545fbd0af4ca3180c0387d1c"].into(),
         hex!["d63cd02f70b0ce100b27b4eb5a7b43fd22268bc6e190ccc185784dab08ed0ed8"].unchecked_into(),
         hex!["6677cac43a8c0c6d55b17dd176c1bf7ad58b537230d270c83d8415e3244cff22"].unchecked_into(),
         hex!["f6316bbd038503ea9af8332d96c147fd16f46cdd7d5b430a8c8c727826fd1e79"].unchecked_into(),
         hex!["481b147884ea99dd3aebeff042f77a656acc2ed58e6ea7d3f7ff6723e591884e"].unchecked_into(),
        ),
        (hex!["62b8896d5ccab37a3b192e35f6d5de7b6431ba16d1a5585df27704d8532c754c"].into(),
         hex!["60db500c345f32c3182ca4325a0d1e43361e52887e3983257d973ab906a35a04"].into(),
         hex!["ee428bd9c419c5b4ecb6958e5559f31c2385d3302d93ed5af4e5714c6f1ffe14"].unchecked_into(),
         hex!["38592b72f9bc1d11231ddc78f792e0176b3ac080b1942c38a47e5f5d40b46a57"].unchecked_into(),
         hex!["dc0722a7ce65621b9be1ddb87b1ff6e19da0c998e92e8ca9bb77b661ae7ac319"].unchecked_into(),
         hex!["c6f858fa75dc6ef7387905621a190d258bb4f3a0fcb69ede61b43aa9c93a4d43"].unchecked_into(),
        ),
        (hex!["58c884249df00313768e419515e8fe8992157264bab81c81a78e5f537d5b3834"].into(),
         hex!["b8d5078b39ca1767cfd3432e9b572ba61dccd407d2adfe7ecaefe629731f6156"].into(),
         hex!["506ea978282a05bae0421f4b9bad88086b5fa830dfd39ad34511b01b9dcbbae7"].unchecked_into(),
         hex!["d8ab2de07bf4d1e92f2ee23a8a76706b799a11ee3b36ef15a75f58d9be4bec48"].unchecked_into(),
         hex!["a20f9a3b2614b95a0a16c9fd1f7b137a2227d188d999d10eea3db5956a35a855"].unchecked_into(),
         hex!["c2ab4f472d6c14522606a52cf2d65b20996dee9bbfe78b76e4896437fa62844b"].unchecked_into(),
        ),
        (hex!["8e7638e6e8e140049b33542c3d0a6b1ec51a127f7a09f14ccf401b0d5b96942c"].into(),
         hex!["10a9f8e1cf4c5e6f1194ee8b0ed428fee7e3175be21b66483010057c72de0912"].into(),
         hex!["d2fe8643538dd071341f143b34927fe36aa9c8715a83b98e819d9925d3a84277"].unchecked_into(),
         hex!["10784c414cfca2cf0b00b6aa6625d4d0f1b85b90d49a1d56c7586c997b858c54"].unchecked_into(),
         hex!["5e5550562760a285c6470c4a4c86f3f1251dec69f92e890aff14ea6722aa0f1c"].unchecked_into(),
         hex!["c250075b8aad4c7d6313bffd182a584383a99183967bfd51108c454645f79d33"].unchecked_into(),
        ),
        (hex!["6642d4536e62308e50a6df17c649e792e43c183899a585e9c8b4e678b9990c6a"].into(),
         hex!["3cfca4903282569a9cefc772c96358b6816369c694ec693251df4fee751fbe44"].into(),
         hex!["a7a1cfd63f67ef87d9a010ea08544c8fe4520bfa14d071bebcbb960047cda21c"].unchecked_into(),
         hex!["12b9db48e8ea8ac2673f53eac5b77bf29ab42131b7dabf69793b7bbaa248a50b"].unchecked_into(),
         hex!["6a08e88bea0a4f2d36c0f4232d197e32dfb103c13ac09dabf842311ba278620d"].unchecked_into(),
         hex!["94bcf646a1cfa00941320e8fdb379618f2bfd7f15ab1fd77ed2a8b65bc05bd24"].unchecked_into(),
        ),
        (hex!["4c616836ce2f0f86e434eb29a999217dda125a85475488e1f9cb0bed63e8ec09"].into(),
         hex!["f85889b28ba951b2d9e91348884c00ca868b0546c91c63ae5dc6e4d649a7cf23"].into(),
         hex!["6cf92283a6ea67843984a550f117e6743c4c248728eecac81b12b9b67a5bef99"].unchecked_into(),
         hex!["92030105be89122ce4b229a46b3ad14f2d78d0282e4ea618e69137450b10f35f"].unchecked_into(),
         hex!["3429f9752fc0a90b76f584a3555bf5e5aac441d5b57e0af8fc44d68186267138"].unchecked_into(),
         hex!["d84553b9d3834921ae2b5ddb39973dc92e9a8203aa1649a92c8e2f68ac993e07"].unchecked_into(),
        ),
        (hex!["5e7dbc2598215fc45e94569045acea2fe2d6e44a2033085207aff8f405327e33"].into(),
         hex!["62f2d199cd840cea75e654b434ccb025ddf1b258182f6e128e37fb87dfd1a729"].into(),
         hex!["b7405b5b7171bee7e0b50072a3f40da4792913e32070f33ce406121a3f6241da"].unchecked_into(),
         hex!["4a0c04c1a34034c5069ebe26f6d9f52ca0176c5766346b973d1df7d4bd295873"].unchecked_into(),
         hex!["26a4f4d6ff4b8ee512c5a46d34f283058c66254fac8c6d481a9f8af4a4fad87e"].unchecked_into(),
         hex!["1eead0c0acd93f19807b504c56c7bbe407a30343b9bba244062d78676c266a62"].unchecked_into(),
        ),
        (hex!["cce8d68b43a1b3064682f10aab037278d41422500777d531f70693ee025a1705"].into(),
         hex!["aed9fc0124a9216edaeb204cc94525087d32a17764c908e2a543e683ff00f515"].into(),
         hex!["19d865ea541f611c21ead320143d29e276427009dc3e4b37c64ba4c97215a77e"].unchecked_into(),
         hex!["843e559228652d9c90130d466e06f06a43ea1de5d9ae784f0e1952def8ba8551"].unchecked_into(),
         hex!["0c62dc1e074c5ed4788703f68d33e7c408dda637c620d87939ee06c6005d5a1d"].unchecked_into(),
         hex!["5cfcd0fd0cf372266eb5b714328f5ab5d3e0ddc5341c40d7c0b8c1d9eb8d1618"].unchecked_into(),
        ),
        (hex!["d0acac98b07a51f0e295e3400194ed49d88252640a7c71e07cbd7d13360a9762"].into(),
         hex!["340b42e6d124ee9363116cc881984272bab065d6e01a3c115eefaa116c0dd100"].into(),
         hex!["48914d1c4c66c4d4084ab41e737110e5e38edfd7c915fcfa283ac88a5af94caa"].unchecked_into(),
         hex!["c4d9290ea21b618aae67a5e54ad4e801746b8865471860d765a61c5e13089c1c"].unchecked_into(),
         hex!["5c1ac4f52ba59571314ae1f2a10164e113736eac1a61039a75835d792e0ebd49"].unchecked_into(),
         hex!["04695e262b9a602417657f8c4a4c98e04dff0c797d005272235a9c3a04080645"].unchecked_into(),
        ),
        (hex!["b05b4f008b8240353342c592ec8d395fe123df47e47efe777a9811c5a7fb9377"].into(),
         hex!["683b2a53c0c1c9b35e1657511ae34eb8c669573a46c0d84cf23185f553e2752b"].into(),
         hex!["84d5c7fe03a3d6a50f98d0c08ffc6606fbffbeed7223c226737cb4223f509b94"].unchecked_into(),
         hex!["844c37c31a937ca462c4235d6768e4805a6cf77d795b6b71c8f55132eb371402"].unchecked_into(),
         hex!["14ffec7e0cf2f63bd169874231bccbf955eaaa8fb7fd5f21ec9dcfd786f25206"].unchecked_into(),
         hex!["6a3e84f05345b26f732fdeb33f0cb9111076c0d91dcb1817f8bd86a8e59de14f"].unchecked_into(),
        ),
        (hex!["b6f16f3320b1daa75807eb90b8f9e00c01dfdbbcbf09bd8d44f6622fa406ae30"].into(),
         hex!["b05c5856f6d40cab0f46cbe49ecfa655ec9e0698bb3373220953c612688f211d"].into(),
         hex!["c001ae70a78287d0ef8c7563a71f320495b5d3e77d2640379a9158b445870397"].unchecked_into(),
         hex!["9e81bc077d9d49e4b1a8ea25e383555ecd0c1fac98d478d426a1c67f3b81981e"].unchecked_into(),
         hex!["befb120e32d0685d88d605468fe15e59d2ccf05fdd930c907626b36e5c60873d"].unchecked_into(),
         hex!["5008ee41d4986481319121b0871a0dab88ca562da194d452bc00e7193d86b622"].unchecked_into(),
        ),
        (hex!["84176c49276dcf3bd7a9826691743474ae6e79f8814c0dfa648f2b4aee87927a"].into(),
         hex!["a657c2e8876978b6f24c9581b1d7300180afe2f46ecdadea68fa4eecabc83f39"].into(),
         hex!["cfc9c2c6d82268d13d87191444a41c2097fd9277ef035c4242eda118d5d8587e"].unchecked_into(),
         hex!["309ca296a243a43c89d9a407b47634ac1ecb82b5692c72f51ad16b322863fd24"].unchecked_into(),
         hex!["ecbc81df526ec7ef6fd7391b84416f173e1c6fbed7d3e56177b3107739e71c0c"].unchecked_into(),
         hex!["466517c06af700373ea705b1ead242be2b85fdec0eb84f7be03ab6c7fd933c0e"].unchecked_into(),
        ),
        (hex!["8c4dd47df34bf1f4874bb69088f7b659e38832d58bfb959f02139711a3462e5d"].into(),
         hex!["e2bdc33beabd530a84d0d66f0ec457ddaa5c6099479b52b9299d3cc1ad687a46"].into(),
         hex!["1a78c4c2a0ab746a71c0fa01a2929cefc682ee22fc194b287cd575495a542b77"].unchecked_into(),
         hex!["aea96f70379cbcdd2e8acc26fbcda641ef8453b27f6629c529934d555d8a3269"].unchecked_into(),
         hex!["96fecca56b89d49c4cf85ab61f8d0ae3b9946a9a42cc45f29a5e1af1b8015b04"].unchecked_into(),
         hex!["64646b106858fb57960b38ce271b4038c51b7d7127887d1323475adf994cf942"].unchecked_into(),
        ),
        (hex!["10ae5d86e7a9ceeef33895a1a922fd91e8dbcdac5d3617348691f95e0b537b0f"].into(),
         hex!["30534c323b6f8f5dd01e521a2ee6664acf16610d95ea3bf106ddbf34ce753d39"].into(),
         hex!["fd34fd07987c7e5f7e9f3e1cddec3818d393867bc82009a771495660ca3759f6"].unchecked_into(),
         hex!["8cae3ea22b5d72144b654c311c004ab551c9c17350b97e6d48e35dff8b66e34f"].unchecked_into(),
         hex!["5a135d07b971f75192263c411656062a201ceb344d06b072e02a11443d2a1419"].unchecked_into(),
         hex!["3019fd4e7aa84a4419ff7f1c2afc864c0bc570f69535ca6549c3815873861c52"].unchecked_into(),
        ),
        (hex!["429106139a75792399444390fc056eba424f45dca68eb55ea039eb62c6d1770f"].into(),
         hex!["9052a169b1847bd98efb8e7fcb354b252ff052ceb6d83e7512d8f0cfb357766e"].into(),
         hex!["9c4aaa263d38b653b38262b79c25cfcecbe4e05e8131cf0a6a61eda712306dd8"].unchecked_into(),
         hex!["6cc60a33f00d31dd63117d2ebb411e301f945d6eac87974945333ce7b242df58"].unchecked_into(),
         hex!["5e24d6d2973bf76cfb6f37a044330d32242b942df61da401c5badef9bb1a021c"].unchecked_into(),
         hex!["080614ee0d33cb5403d408defa238aa42760d48ffbd354af13cec0d531b17473"].unchecked_into(),
        ),
        (hex!["6ccbaddcc94fa0cef0df6dd3a12d10c0d65ff0073347112ea9fce2737e0dbc68"].into(),
         hex!["6839d86f228df81e179bfc686d12dfaa1734abbbdefcb1f7253e40458bb6e103"].into(),
         hex!["4377da5796b220510aa11fdf0f58599fdf01b3626a3205ab249dea0c02f5de94"].unchecked_into(),
         hex!["a8a4db006b1e577959a75bf790e628a4637f6c81c367b445215134057a41a450"].unchecked_into(),
         hex!["ba26277670cfc8a5cde3a4d799cd81a0c8dce06b199e0adae4693f1394726010"].unchecked_into(),
         hex!["1ca3392eb877d20742e77371a366e945400ce601ccf30636a944f9a38405d74e"].unchecked_into(),
        ),
        (hex!["04c14a1ba61ef9d3a69b62d540df11f882b47d6f8a7ec60b989af17a016abf4d"].into(),
         hex!["2a63113bfb4d645b492b66238af456169f2da88abc260fc6ffb95772d76abc0d"].into(),
         hex!["655c5ccc96d6cb5e1563186997d69110e1a35f17300a086aba10471688bf8721"].unchecked_into(),
         hex!["dc189b1184e956eb663d1e7e0011b193e603791e4b9d47e50d5f2ff4b78ffa5a"].unchecked_into(),
         hex!["20523f5d8c8386f87e39da8aadcfbf71697f4c643a7bac2605b7bf5dde82803c"].unchecked_into(),
         hex!["9aa1bd2cd7aa023eb8dba75df22d20e9fecfecc087aafe3a277274cdb2f89e26"].unchecked_into(),
        ),
        (hex!["8659e50693884bad71d07c8aaa4e4cf04a523e3c12df27aca8b9a3a632c23b3b"].into(),
         hex!["c289933f7c357323d6f0e48bc8f85db594d48a89760c60785d076759cef6011a"].into(),
         hex!["816b5a4e23d6db4c2f96af5924ed631c176d1b297d28b713e0e586e0c6e7a8a4"].unchecked_into(),
         hex!["f2a75523b3f14fc3443fdb447eff8cd10b7370b3f5236a60b8dcaa9d2c130c42"].unchecked_into(),
         hex!["9c3ee640cf2c8d06f5ce7dd4a5ec57057df28139d6a3e8d6ba1c4624c080c040"].unchecked_into(),
         hex!["3a76a45c4e0bb6a9084a167e11d1ab3cd927b14f40d76a26750eef776f625235"].unchecked_into(),
        ),
        (hex!["caaad6fc54606a3f2a7adfe18622fa60a29f03b992f79152b847d95a16416b16"].into(),
         hex!["746cd8e97bc80c501160fd3adbb4a11bddef59bb1ab67de8f719466ebd6a4844"].into(),
         hex!["212aa95db03aaaa5472eb7bfe7fbacea867d051b7b92f7b92d55a82c37377e2b"].unchecked_into(),
         hex!["9841ee261b30bdd6f7b8e75fd2de6f5c1f920e57bca98f2bc2919a0281436e55"].unchecked_into(),
         hex!["4aafeb573658addd6875e3f0760e958d6e0cd119ad603c3c145d0146bf701474"].unchecked_into(),
         hex!["02cc68e1e2753b3957030b34d86e87c9cab8bd5ec7ecdd607dde2fb0f7855e73"].unchecked_into(),
        ),
        (hex!["baf4b5c7b0514563c147624fd71cdbb5a5de1900855c0e73821d0ad366f5ee06"].into(),
         hex!["d885d4bb00915150b61c952112124fee76349ccdaffe99134ee28c16a6c85428"].into(),
         hex!["bb92aec78e6301145b21e74ab2db504afd5cbc4b06b21b3eb28182e4137c195a"].unchecked_into(),
         hex!["8c9038a9ec0a1cdbe37ad17cc2e74f7b216ae18e7d6683482eda55181dc7a652"].unchecked_into(),
         hex!["2c8c5112db0d661443b3f8d0588b6ee23c64722025250e8a9b94ab415ef2a023"].unchecked_into(),
         hex!["ae91724b871a4c13105d06825c183acfaaec23ed71130d03b05a4fcf39a57e08"].unchecked_into(),
        ),
        (hex!["c492edb6bf4db892d750c922f3eba5e5ae76156151b760d8fd575e1049279253"].into(),
         hex!["ba1712212ad4c10d8d0e3b0afdc3e51db9e51b4a54c97c3569727c35e1d02d4f"].into(),
         hex!["cca1ed4fc82e910d7efc757bec9766bb5d867a277bb74dfd4663d5d1a35f3cc4"].unchecked_into(),
         hex!["74594cd54cc6e9bd6ab39a78c9fae371e6e5e305ecb90df66519f0240adc534b"].unchecked_into(),
         hex!["da9e298133f9b555029748938bfa1f3ad4912569d8c3cc0e4175b2df5883fa32"].unchecked_into(),
         hex!["8adaf174196002e624aec81048f2843bf2bc80a960ffe0b0e20f24fe094edd08"].unchecked_into(),
        ),
        (hex!["3428cba814c648ba845262993ff92193bff584eb5f165c3648c72bcdcebfb977"].into(),
         hex!["80bce8919887c49e4e322ba0e6c677e2ab3314d09af0682795acab028ac61e7a"].into(),
         hex!["95ccd1435766d0404b6ee83bb695f6126a1aa2cba9789321f6c536186a988a90"].unchecked_into(),
         hex!["401829c119d6f6c1d4f9a9995dbdbaf4457cca3a7c4df29564ddf3cbd6961b12"].unchecked_into(),
         hex!["aaedcffa818e398b0eecc506ccad9d79e1e728bf801b2b1d7600975a57e7c246"].unchecked_into(),
         hex!["08eea1455db68f592ef8a0c561571037fdde3d6965d6bd5a15da701f7cbb9a6f"].unchecked_into(),
        ),
        (hex!["d07c7efd7d399fe46f55d3ce44c7a2996132abb06072ea8a56fe6ece6ecfcd48"].into(),
         hex!["2c1c61e0f1fb51591a152f5edcb50bdc4077fbe0bf4a7da7a397fdfa32d97322"].into(),
         hex!["6056284b7d3c9ecacccff48e64a043ffbf73e622de4136a57872f5af8da27956"].unchecked_into(),
         hex!["b4d3feebecae89232e6838aa3660296a5ea625e263fbddcac85664b0533fc72f"].unchecked_into(),
         hex!["049ef7cef5ea0bd101dc4e49b48ceceec30643969d0db82b90f2ad191cb5441d"].unchecked_into(),
         hex!["5487597aa25d8b24752c4439f52c22504822300c1957ad7b7e47359992ac3e4a"].unchecked_into(),
        ),
        (hex!["749c6861c98e5771a8620a1b78aff9e6049fa5695118b41f10d2c87a4957064c"].into(),
         hex!["865dd3c5c954d9de08858b421bd845418db0d320104d1ba126386f2dddd36812"].into(),
         hex!["2c206386f206693f9cf24daafe0481c4b66a5df6670dcfcd2a8a442cc4beee35"].unchecked_into(),
         hex!["38e8ef4db6cd3cad9e2f46e917c4722f33356a1bc84dbdedbd38e9bb0dd50866"].unchecked_into(),
         hex!["8c1471557b6ec35494393b095d3ca66d51c0e15b46d13d666849cdd9b4c59d05"].unchecked_into(),
         hex!["281f8579a379c1221e3198e2bd0209c2fb45ff8f95f4cd6ff37da35566020f1c"].unchecked_into(),
        ),
        (hex!["1caba550a06c376b97bcf7153dae296c5ec75a39297d5585ba20dbce30f6645b"].into(),
         hex!["5aabb54e76173e49581834efca879a8d3d964c6d8786a1215220330c9835e32e"].into(),
         hex!["f7c3a942384c65a62d712c386e278907d002e6d713d41dc625ca10005a2cf8fb"].unchecked_into(),
         hex!["5e99158c034d657d427cd83c25122a5a92c1400ad282b417bbfddb4e28b6440a"].unchecked_into(),
         hex!["a4be35e9c6e3ea2476a9a2a86b067eca1300a6b85093c66c72dcd75da1504b32"].unchecked_into(),
         hex!["ce806065f3e9ccc5a9572a9199b34e0a7980ada08c93b6dff1b7d8e454df442e"].unchecked_into(),
        ),
        (hex!["2c18fa4d5ee5994917a27e2a11686c57bd7e93bd9d1176f75447cb5e5cdb1c79"].into(),
         hex!["cc72f6cbd5a2f33cc35d7130b1fbc30befdc56fd7ba31ce2ca5223fe2f979e01"].into(),
         hex!["e31012d446618988cd09e06b9c9cd420fb22689c785c9cde2b602fb6e91ee0bc"].unchecked_into(),
         hex!["62026afbf1f33bbccbea027ddbc0cf2ccd8a8f8a8b39638d9ce7152d57fa827f"].unchecked_into(),
         hex!["2eab4f2aad4b54df16e85af4949e9c15f754ae267741e9d718b5f74330a97c0a"].unchecked_into(),
         hex!["ae453e03c64acd44e27a40d6a966ba4266bdcb5dd96162fa2d844a20b7de8a7a"].unchecked_into(),
        ),
        (hex!["3aa5ce7383485fc92b56013223174a475cb2b5d4683973cd2c1e5c7c6c80e553"].into(),
         hex!["b8d03981290286236051236bc6ba792d8e025a110db453e6c564a1e80c2fd866"].into(),
         hex!["d2ef7db13b14ce5b107d12932194903ce7aa580f267088ab81dab1234014e501"].unchecked_into(),
         hex!["2459237b158a79326479bab561c00542e8821a463eaf31cb367b0f802fa47937"].unchecked_into(),
         hex!["a636549f5c014e9a1d265e0fe3389e80542c53bd1ce5997ec47d9d7bc048d858"].unchecked_into(),
         hex!["a0a8c2aac35f57c9f4b2e87b018c3a58c5c2825edfe3a3122d16ce992872d568"].unchecked_into(),
        ),
        (hex!["608c07ec39d5e5bc1bde66f6b2ceac77b17da15d684b96fe5e77fd2974234f29"].into(),
         hex!["d4e13263015ba81e37e0ab9d54a8b684d23b033a78db1f69d50ae29895b1b76f"].into(),
         hex!["6ed56081b02a2f7c4c9303e4b94de213063d9f362aca858ed8748185737e5ab9"].unchecked_into(),
         hex!["4c14d78a970b8055b35cfcee8fdfebf3d5ea841800dcd53cf4e4a9aa13cdf517"].unchecked_into(),
         hex!["768c0574722710456b9ff8b521b19d22b1f0ab4532177db02de6aa5e0c605468"].unchecked_into(),
         hex!["acd124f9c96b26ad4fb1430d97c14ab2ca6b86feb16bd24d1c3fdcd510e66c3b"].unchecked_into(),
        ),
        (hex!["eeea1677d0e621cca6ebc4dff7d5f45fc1e8a5b51b068091ab50594653692b23"].into(),
         hex!["74eb310b838f19e9c12034fff350168e4b9330baea0d785aabf634a6c42e6508"].into(),
         hex!["a2ebe15b0e70668952a36abb9eca461b365c059b28c7386433bd8c33c5219d6b"].unchecked_into(),
         hex!["42b8b40323f9128febc5888dcb05462ecaa1b5fbe3e5699354238b10d35d7f13"].unchecked_into(),
         hex!["0439d7afa0c3aeeeb6cf3fec023fba09f0c4edbd913c90ad06484cfd93495e3e"].unchecked_into(),
         hex!["c0983864973c9f5badd851df583c9a506a366011b3e46fe62546c9082e0e9d11"].unchecked_into(),
        ),
        (hex!["208f6d33ac5ce4e9e96230b9ac927836c4f6cba19f8b04c023dddc71facdfa70"].into(),
         hex!["bc57ed530ee8879164ec54cb4ea161d674227d44020b664721dd0181ef9db941"].into(),
         hex!["aec937f6d3580d486c51f348a91c065a4325e7f105e9c645654ad7a4393d61f9"].unchecked_into(),
         hex!["fa2b2a9f8d31442165026c726ba841bb30443a98612ee1c1b3f1f85029a03a64"].unchecked_into(),
         hex!["bcecee2307ab0ab3ea00c5ee4f852cdf0502c5b50922c6c364aacc19b183b43f"].unchecked_into(),
         hex!["ee9b843419d7a8451cd8d2c1ed54c3bab9b78ae6e3cee3da1d603b31dde8ca3e"].unchecked_into(),
        ),
        (hex!["a2c13f29001690a7a88880629df98cea76d014dc02e30f73a8921aaba3212b21"].into(),
         hex!["ec68838979cf34cd9f1aa0b9a044d30c1dfbc1de602204fa184af09ba9a4e04d"].into(),
         hex!["4846bfe61f21f8e21ccc5a0ea3bdc974e7c50f779436e03cdfb8193a13723d82"].unchecked_into(),
         hex!["d033abf8b7ce817c636a47123417744fb7085ca023d39c69e78123612b71f947"].unchecked_into(),
         hex!["78c84bde8b26661abece73c171cc299b7709e8c71b463c96ced4a2d3ecb9c442"].unchecked_into(),
         hex!["c47da8a79963bae808b03e345ae0a69db0ed2cbf290883c223033f794367d157"].unchecked_into(),
        ),
        (hex!["c00f3be7c7f54e0a5fb1adc3824b6fb8511f74c9dcbc9816a9663aa25e3c6b2b"].into(),
         hex!["6ab3b90df455e18e3dbe09f116a9b9b0049fa91c726c85c51253a51fbc969413"].into(),
         hex!["d3ebfce8118f81683ac77893bd843591521b45fe4f28334b87a7b98f92d4c40e"].unchecked_into(),
         hex!["6c1f201f968b26c3a5a55e3c9aa2a24930aea5cfada20e708a64018879cc6257"].unchecked_into(),
         hex!["5620ccc83d67a3375d1150ffe44a0e8f34bc1c7f66b7b39ee8b3c8614a62a914"].unchecked_into(),
         hex!["7ca66b6ff992af9837b4ff987e66912e6254ae05e3ee275e090c28b8d0301d16"].unchecked_into(),
        ),
        (hex!["5499c704613e531e1b317d85aee9baa0bc58e17c0eb19dee99b509b01bf9932c"].into(),
         hex!["62f138793adf31f7f078e61d7c822d165a948bf954674c10d92e73de92ecfb0e"].into(),
         hex!["b51523a89d9c743a50ffe46d74386d7ae8facba75f7a991620314d3a9256a080"].unchecked_into(),
         hex!["083853b9016986e8813e4d843e441031e5468b53e2722b011da36d4d7f867520"].unchecked_into(),
         hex!["a47f7de3b73e28fad1c4aa9788819763a1d309bb880b7af0bb44efad79633435"].unchecked_into(),
         hex!["48b61bf8200f696709144b8e87e784acf87c9d98b9a6abc78115a88aa5bbbc02"].unchecked_into(),
        ),
        (hex!["be0e88ba6f8ff01de0161899a3f4779b96d7222a95f23aa397f418146a3d1d01"].into(),
         hex!["46f59788dc85d077053900e54edf6609806b9b77ab8fc8bd02b43c9103c9bb65"].into(),
         hex!["69d831db8ae046406a9d901e09d38bd429123d8ac7ab75cfb3721bd40f47b757"].unchecked_into(),
         hex!["fa347ad13f03aa4e0ab3e356d930c469b97506c58d4afe5eaf2901b970276314"].unchecked_into(),
         hex!["28ea1e8fc8eaba7c55c9627881114a53d1aff0057779ee5863b0bcab60521877"].unchecked_into(),
         hex!["8a3b7986da1d41d392724705bb2c61d61415e7b445ae644e81aab6c5ae5cd352"].unchecked_into(),
        ),
        (hex!["546963fe3097a05d0d41f1d4aacb0d73ec38cbb1524fd2113eff529be877680b"].into(),
         hex!["08c54001b6a02089806e622fbdeb2ba8c1d7926d5ca8cf067d326840da94ea27"].into(),
         hex!["7707a47071f840f1412eab1048dbe2d4d928f26b871e7bb8ece6ded6e1bc0180"].unchecked_into(),
         hex!["00359e65779e8f8963b817fe05c44093448a44840c4bbd497d33d96e31b4ee5d"].unchecked_into(),
         hex!["9c6365abafa0468254dec5c838ae1b28e30583f0087929dc5f7ef71888357072"].unchecked_into(),
         hex!["a60d4cd6663c0d1c005c61d5d780092e1228a34ee0ba4707b498b1bc2338e00d"].unchecked_into(),
        ),
        (hex!["30a03bfc3aa10e498d3c188af1a625aa5b23d45d609a1619ed91d7264002f205"].into(),
         hex!["1ec899a189e6cf7ee06090968292b2e01812d2b915e44c40d90cbbb31d217f3b"].into(),
         hex!["9552ff04b883e772679235e3532f336b415218b2e39a485af04e35aa1ae4e58e"].unchecked_into(),
         hex!["04f451e9d61b0ef9c5b86f03e95d94de0e387218f464cf71743a6d96c604ce21"].unchecked_into(),
         hex!["6456ee95eadea963adc8b21adbc78e3c9b7a9640569f802fc27a62db75302353"].unchecked_into(),
         hex!["40cb74b273337e966c7b6b88b5bfa553253ab2c3e0fe6b9088369bcd142e6457"].unchecked_into(),
        ),
        (hex!["da28a7dfa02801130c420256b77352a35dbc2d98e7bfbb84adeb0a574c080619"].into(),
         hex!["f21e23cd6d59a0193aa542054b29291f51a50280c4759d8f1277adf324772919"].into(),
         hex!["af476bd6ebefc8ec8adee8189cb2b60e076131a37fbd06a95993610e41877a9d"].unchecked_into(),
         hex!["aac30b7f7a99660272c9c64614ae42a5527a120c48bb0aedad912f4b53c38b65"].unchecked_into(),
         hex!["683d4a423bf387162ba7f8f135c137c335e3ed1983e3ee8a8a3d9fdf537a8140"].unchecked_into(),
         hex!["c2b0f7def8d0dcf0de3783322f9d295a86d3d396bc257574da704d6b8b466e0b"].unchecked_into(),
        ),
        (hex!["3402a1a7e0cf019d4d24a81bb959a7249656af672d2d0b96b15f770f48d1e211"].into(),
         hex!["6af6a5c0f26bea06dea21f5fca482c65b4ee5fb2e2276e2fa5771725d89f3f48"].into(),
         hex!["fa61c1e39fe750065739516cdf46c1f475a870009413257b324c46dc5e1637eb"].unchecked_into(),
         hex!["ca24deb18487f51127d1305a5c3fe47b0366d8bb1d5a27c2811e395c8be60f5f"].unchecked_into(),
         hex!["1c10fe743027bac7c2e532bf4b629cdf96d726e0a47e8d21b770c9bfe7fdf44d"].unchecked_into(),
         hex!["b0f12678d1da5888d65719fa66d3d2266176b22adbec04b3b94a7f6104c87d7c"].unchecked_into(),
        ),
        (hex!["72b32e9e449b8d63d5c815555696b3f7f5b47d3b775543eff82f4992f485d16b"].into(),
         hex!["a2cabfb5e3bfd0ac8c6fe3a6853fad8a29b47a6f0bd35c4ea96f6b6a5c126875"].into(),
         hex!["5b6f759b1a8d3547aa5d6d238170c8bce3e5920dacea7fcc6bd66e28f2acf3e5"].unchecked_into(),
         hex!["048dd70469517d276ba625fb446c809d0e9f85be433781d1d2cc08ef4609fd26"].unchecked_into(),
         hex!["da6125e0427f83ade5091c83a11d83e8b13815db09d0eb3d99a9733c51222701"].unchecked_into(),
         hex!["34e6762e8315aa13fd8669a786d76e31b81664315a3187b5693e9e3954a61b10"].unchecked_into(),
        ),
        (hex!["6080d21f2136d306dcb2029d9322206802bcecc0c12367a8d550382af54dd700"].into(),
         hex!["e466225b73312f876fe8f26711e7f238d0c1f01815454aa625e9d9bbe0836002"].into(),
         hex!["d8d65bb9d3f2561d6b0123506e289f14b0ea3f8d107b80581d3dc55b5d4cf290"].unchecked_into(),
         hex!["ce4723b527697fc8faa2aead8657b816826c0e236d5af308a4a361cf6cbf8c44"].unchecked_into(),
         hex!["90708d9649f161f7192927487edb2b3e4435da97a114a49da0c80dd389e29e2e"].unchecked_into(),
         hex!["ae937888fb04ed8a44c6a7a814d03f852cc8d5281aa18cda812860c7f7757336"].unchecked_into(),
        ),
        (hex!["3e605eec59bbc981e225f588d30c743ad82e79444af95d3148454dc802c26353"].into(),
         hex!["2671ac3cbef6e62bc5427e7796930739f4bb9830486d6ad3b9550cc02d9e422c"].into(),
         hex!["a1806cc0f3c937290898dd1fc01b27e05b34cf538822c44cd5c72d1f89ad1ad5"].unchecked_into(),
         hex!["76e9616468182c518c2efd0bb6c82c6aa4f0f27de7738fe9b7235cebc8cbb718"].unchecked_into(),
         hex!["c6196cb23bc54bdf6cfa1d5ee08972cb390f7a9518ef1ab1a49fc24aa6ec6b57"].unchecked_into(),
         hex!["b0f4ceaca86c2677d6fdda2f321e42d2c442e8fe54dc9c3ca71aae6ca226274f"].unchecked_into(),
        ),
        (hex!["c8080c1cd99e6bbd447d0f09a0ce79807773c1f8423977e5a1bf86ae6060da03"].into(),
         hex!["c4b09473cd4b4d215e99914c3020199d5b59884e134273e16a45e324c391cd60"].into(),
         hex!["244981508dea17179841016150dc4ff58747b57c0d58eee1b253edc6952777d6"].unchecked_into(),
         hex!["8039ee0700054f2337680068494cf5b2ecdb1833cd983b7af611c2b1e192951e"].unchecked_into(),
         hex!["5c6b68341e6ecd512462ee32a75d3cbbadd999e644f99b4551a6002ff7c22054"].unchecked_into(),
         hex!["721d0c5d36bbca27b005fb298652417c6357cd0024a102b7cb2517d8f65eee2f"].unchecked_into(),
        ),
        (hex!["96d9b0e8df9e3aa42db284d3a40bccf71fac1ac8e629e6ef409597b4cb24692f"].into(),
         hex!["14def7c329ec81e13b8292e9e916e3f5e10f2aea1a82aa364eda0e8b7e0ccd6a"].into(),
         hex!["61b87fa5562c709183db4bb0ccfb7a8596acc974b4178a30a40e5015faf0e3ab"].unchecked_into(),
         hex!["961ec14b989c76b3c327df7c41cabaa89c7de76db0990984816d981c68818e26"].unchecked_into(),
         hex!["84a476f0440bb429b377363a01cdd6cacba97699ec9e3fbcf9c6d6bc599d6b13"].unchecked_into(),
         hex!["825fd7b1a1ef6e731d4e7b86c5ae48cea4782e908247efbc3f3e50e6aa51d112"].unchecked_into(),
        ),
        (hex!["02cbf9ce99f64379ba06782340f986938e03daae557631e6dd1706a80d1c985c"].into(),
         hex!["baebee2d01e51606e476543615a72ff1effb366f8c1711b37323788a526ba67b"].into(),
         hex!["5c66ae77ce7ddaa50b457bde437cd461d92370facc88367a91e5c70c803887ab"].unchecked_into(),
         hex!["a02d30ba0e156d23a1ac6fc2a49b4528ee850e59a487e4e00a6ee65241428d47"].unchecked_into(),
         hex!["825be7d2e4c4626cd83d3d20a9f944b986dd722d921ca978ea4c12e26bdad422"].unchecked_into(),
         hex!["be2410403842a9906234f9bf1167e9d7ca664282cffc8c6c95233c42eec0165e"].unchecked_into(),
        ),
        (hex!["bec924f54eb8a1990e28fc832cd41d8cbbb5a35e533faa13a4f0daeff93e3531"].into(),
         hex!["f0650bb478969829962cf775b0148526228939a4ee6dbe09339ac88cb3e2fc54"].into(),
         hex!["bc523f2a5055772fd960f6e1d5fe9651a0be59d68c185de2f35630189b19fc03"].unchecked_into(),
         hex!["486efe1e58a3c9dcd45cfeb724d1a5aa1d1e261e05f5b99145178cdbc0388337"].unchecked_into(),
         hex!["5e2d512f9c07b86d18ccc91f9a39b995ff7d2d6f11e249e03a585b137c2d7f75"].unchecked_into(),
         hex!["8011a73813dc2672bc7a55e584c1dd905ca3242b2abb58a307e917271d277d47"].unchecked_into(),
        ),
        (hex!["74eccd21d347f5578ed546fd50bf37bc4a359272fe2eb39f27db7658555de825"].into(),
         hex!["e2af8b5fa7f6ea14a903c4c8dcd5c4698644b7930e41b753b5fd059aa930400e"].into(),
         hex!["c389ea82a0b41e37835288687297a36cae41b376540af3e4faf4b79e173c213a"].unchecked_into(),
         hex!["0af22720144cbbefdb838e901a22bdd8b127cb856b1b2b354dd7853c5ce4f666"].unchecked_into(),
         hex!["f6036a74f284665cc039ce753fbbbcb7704d4d3b9157e7eb0bcc3411877c3648"].unchecked_into(),
         hex!["ec2126a5d395068d0296f58dea24d624eff9fb3ee11e97e1ead10a07fd28fb6b"].unchecked_into(),
        ),
        (hex!["3c54f5c44238f2ec2ecc2f6dcd1a08928346cdf6f301e8c5e951f9b60312e255"].into(),
         hex!["60914a51e78c5d1fb7b4accf50daab3bdc93a8226be8d6e0e3d53e45a2fadf1c"].into(),
         hex!["796e62e6d374e983ddf51b9b9575b23c70f0aff9e73c878d706562593741f05e"].unchecked_into(),
         hex!["c07703cade506d2e638d169226ab05d98bdf19ca42c22cff2398b3dbaa35470c"].unchecked_into(),
         hex!["ce35798d213b4da4c0ade23508afd41a09e7b13130d25175691f96b185283138"].unchecked_into(),
         hex!["e8616f8f87367a60a8137e4c2f168e90ce0a5fa27e5ff6c1c4c63a7f0d2cab2d"].unchecked_into(),
        ),
        (hex!["364bd8fcba5a3aa9fff312a1c2dd653864c8417df136d5832f55a52dccb95c65"].into(),
         hex!["4cacb8801a117dc263a81bd17d9b82ce5c71d2efc6d0a14f5ded05035b205d18"].into(),
         hex!["2874c3d32573d8fdac8a81a7fe6ceb6ef4a549694a5511a5c70c553f2c233c13"].unchecked_into(),
         hex!["fa71e5a53adcb7550594926681e3f28ea2314735e83d30873d54a806b016c83e"].unchecked_into(),
         hex!["c8789c4a8018e976585a4acbfd8f1546531275c2d7d75dac68e49e474100fd23"].unchecked_into(),
         hex!["107e4b4d1255f2c1157be1d42c925ee2da48d9a76ec05011933ce218beb1844a"].unchecked_into(),
        )
    ]
}

#[cfg(test)]
pub(crate) mod tests {
    use sp_runtime::BuildStorage;

    use sc_service_test;

    use crate::service::{new_full_base, new_light_base, NewFullBase};

    use super::*;

    fn local_testnet_genesis_instant_single() -> GenesisConfig {
        testnet_genesis(
            vec![
                authority_keys_from_seed("Alice"),
            ],
            vec![],
            get_account_id_from_seed::<sr25519::Public>("Alice"),
            None,
            false,
        )
    }

    /// Local testnet config (single validator - Alice)
    pub fn integration_test_config_with_single_authority() -> ChainSpec {
        ChainSpec::from_genesis(
            "Integration Test",
            "test",
            ChainType::Development,
            local_testnet_genesis_instant_single,
            vec![],
            None,
            None,
            None,
            Default::default(),
        )
    }

    /// Local testnet config (multivalidator Alice + Bob)
    pub fn integration_test_config_with_two_authorities() -> ChainSpec {
        ChainSpec::from_genesis(
            "Integration Test",
            "test",
            ChainType::Development,
            local_testnet_genesis,
            vec![],
            None,
            None,
            None,
            Default::default(),
        )
    }

    #[test]
    #[ignore]
    fn test_connectivity() {
        sc_service_test::connectivity(
            integration_test_config_with_two_authorities(),
            |config| {
                let NewFullBase { task_manager, client, network, transaction_pool, .. }
                    = new_full_base(config, |_, _| ())?;
                Ok(sc_service_test::TestNetComponents::new(task_manager, client, network, transaction_pool))
            },
            |config| {
                let (keep_alive, _, client, network, transaction_pool) = new_light_base(config)?;
                Ok(sc_service_test::TestNetComponents::new(keep_alive, client, network, transaction_pool))
            },
        );
    }

    #[test]
    fn test_create_development_chain_spec() {
        development_config().build_storage().unwrap();
    }

    #[test]
    fn test_create_local_testnet_chain_spec() {
        local_testnet_config().build_storage().unwrap();
    }

    #[test]
    fn test_staging_test_net_chain_spec() {
        staging_testnet_config().build_storage().unwrap();
    }
}
