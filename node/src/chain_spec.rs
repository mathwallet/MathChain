use sp_core::{Pair, Public, sr25519, U256, H160};
use mathchain_runtime::{
	AccountId, BalancesConfig, EVMConfig, EthereumConfig, GenesisConfig,
	SudoConfig, SystemConfig, WASM_BINARY, Signature
};
use mathchain_runtime::constants::currency::MATHS as MATH;

// use sp_consensus_aura::sr25519::AuthorityId as AuraId;
// use sp_finality_grandpa::AuthorityId as GrandpaId;
use sp_runtime::traits::{Verify, IdentifyAccount};
use sc_service::{ChainType, Properties};
use std::collections::BTreeMap;
use std::str::FromStr;

use cumulus_primitives::ParaId;
use hex_literal::hex;
use rococo_parachain_primitives::{AccountId, Signature};
use sc_chain_spec::{ChainSpecExtension, ChainSpecGroup};
use serde::{Deserialize, Serialize};

const DEFAULT_PROTOCOL_ID: &str = "math";


// The URL for the telemetry server.
// const STAGING_TELEMETRY_URL: &str = "wss://telemetry.polkadot.io/submit/";

/// Specialized `ChainSpec`. This is a specialization of the general Substrate ChainSpec type.
pub type ChainSpec = sc_service::GenericChainSpec<mathchain_runtime::GenesisConfig, Extensions>;

pub fn galois_config() -> Result<ChainSpec, String> {
	ChainSpec::from_json_bytes(&include_bytes!("../res/galois.json")[..])
}

pub fn math_testnet_properties() -> Properties {
	let mut properties = Properties::new();

	properties.insert("ss58Format".into(), 40.into());
	properties.insert("tokenDecimals".into(), 18.into());
	properties.insert("tokenSymbol".into(), "MATH".into());

	properties
}

/// Generate a crypto pair from seed.
pub fn get_from_seed<TPublic: Public>(seed: &str) -> <TPublic::Pair as Pair>::Public {
	TPublic::Pair::from_string(&format!("//{}", seed), None)
		.expect("static values are valid; qed")
		.public()
}

/// The extensions for the [`ChainSpec`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ChainSpecGroup, ChainSpecExtension)]
#[serde(deny_unknown_fields)]
pub struct Extensions {
	/// The relay chain of the Parachain.
	pub relay_chain: String,
	/// The id of the Parachain.
	pub para_id: u32,
}

impl Extensions {
	/// Try to get the extension from the given `ChainSpec`.
	pub fn try_get(chain_spec: &dyn sc_service::ChainSpec) -> Option<&Self> {
		sc_chain_spec::get_extension(chain_spec.extensions())
	}
}

type AccountPublic = <Signature as Verify>::Signer;

/// Generate an account ID from seed.
pub fn get_account_id_from_seed<TPublic: Public>(seed: &str) -> AccountId where
	AccountPublic: From<<TPublic::Pair as Pair>::Public>
{
	AccountPublic::from(get_from_seed::<TPublic>(seed)).into_account()
}

pub fn development_config() -> Result<ChainSpec, String> {
	let wasm_binary = WASM_BINARY.ok_or_else(|| "Development wasm not available".to_string())?;

	Ok(ChainSpec::from_genesis(
		// Name
		"Development",
		// ID
		"mathchain-dev",
		ChainType::Development,
		move || testnet_genesis(
			wasm_binary,
			// Initial PoA authorities
			vec![
				authority_keys_from_seed("Alice"),
			],
			// Sudo account
			get_account_id_from_seed::<sr25519::Public>("Alice"),
			// Pre-funded accounts
			vec![
				get_account_id_from_seed::<sr25519::Public>("Alice"),
				get_account_id_from_seed::<sr25519::Public>("Bob"),
				get_account_id_from_seed::<sr25519::Public>("Alice//stash"),
				get_account_id_from_seed::<sr25519::Public>("Bob//stash"),
			],
			true,
		),
		// Bootnodes
		vec![],
		None,
		None,
		None,
		Extensions {
			relay_chain: "mathchain-dev".into(),
			para_id: id.into(),
		},
	))
}

pub fn local_testnet_config() -> Result<ChainSpec, String> {
	let wasm_binary = WASM_BINARY.ok_or_else(|| "Development wasm not available".to_string())?;

	Ok(ChainSpec::from_genesis(
		// Name
		"Local Testnet",
		// ID
		"mathchain_local_testnet",
		ChainType::Local,
		move || testnet_genesis(
			wasm_binary,
			// Initial PoA authorities
			vec![
				authority_keys_from_seed("Alice"),
				authority_keys_from_seed("Bob"),
			],
			// Sudo account
			get_account_id_from_seed::<sr25519::Public>("Alice"),
			// Pre-funded accounts
			vec![
				get_account_id_from_seed::<sr25519::Public>("Alice"),
				get_account_id_from_seed::<sr25519::Public>("Bob"),
				get_account_id_from_seed::<sr25519::Public>("Charlie"),
				get_account_id_from_seed::<sr25519::Public>("Dave"),
				get_account_id_from_seed::<sr25519::Public>("Eve"),
				get_account_id_from_seed::<sr25519::Public>("Ferdie"),
				get_account_id_from_seed::<sr25519::Public>("Alice//stash"),
				get_account_id_from_seed::<sr25519::Public>("Bob//stash"),
				get_account_id_from_seed::<sr25519::Public>("Charlie//stash"),
				get_account_id_from_seed::<sr25519::Public>("Dave//stash"),
				get_account_id_from_seed::<sr25519::Public>("Eve//stash"),
				get_account_id_from_seed::<sr25519::Public>("Ferdie//stash"),
			],
			true,
		),
		// Bootnodes
		vec![],
		None,
		None,
		None,
		Extensions {
			relay_chain: "mathchain-dev".into(),
			para_id: id.into(),
		},
	))
}

/// Configure initial storage state for FRAME modules.
fn testnet_genesis(
	wasm_binary: &[u8],
	root_key: AccountId,
	endowed_accounts: Vec<AccountId>,
	id: ParaId,
) -> GenesisConfig {
	// Alice evm address. private_key: 0xe5be9a5092b81bca64be81d212e7f2f9eba183bb7a90954f7b76361f6edb5c0a
	let alice_evm_account_id = H160::from_str("8097c3C354652CB1EEed3E5B65fBa2576470678A").unwrap();
	let mut evm_accounts = BTreeMap::new();
	evm_accounts.insert(
		alice_evm_account_id,
		pallet_evm::GenesisAccount {
			nonce: 0.into(),
			balance: U256::from(123456_123_000_000_000_000_000u128),
			storage: BTreeMap::new(),
			code: vec![],
		},
	);
	GenesisConfig {
		frame_system: Some(SystemConfig {
			// Add Wasm runtime to storage.
			code: wasm_binary.to_vec(),
			changes_trie_config: Default::default(),
		}),
		pallet_balances: Some(BalancesConfig {
			// Configure endowed accounts with initial balance of 10000 Math.
			balances: endowed_accounts.iter().cloned().map(|k|(k, 10000 * MATH)).collect(),
		}),
		pallet_sudo: Some(SudoConfig {
			// Assign network admin rights.
			key: root_key,
		}),
		pallet_evm: Some(EVMConfig {
			accounts: evm_accounts,
		}),
		pallet_ethereum: Some(EthereumConfig {}),
		parachain_info: Some(mathchain_runtime::ParachainInfoConfig { parachain_id: id }),
	}
}
