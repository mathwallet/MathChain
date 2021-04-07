use sp_core::{Pair, Public, sr25519, U256, H160, crypto::UncheckedInto,};
use mathchain_runtime::{
	AccountId, AuraConfig, BalancesConfig, EVMConfig, EthereumConfig, GenesisConfig, GrandpaConfig,
	SudoConfig, SystemConfig, WASM_BINARY, Signature, ValidatorSetConfig, opaque::SessionKeys, SessionConfig
};
use mathchain_runtime::constants::currency::MATHS as MATH;

use sp_consensus_aura::sr25519::AuthorityId as AuraId;
use sp_finality_grandpa::AuthorityId as GrandpaId;
use sp_runtime::traits::{Verify, IdentifyAccount};
use sc_service::{ChainType, Properties};
use std::collections::BTreeMap;
use std::str::FromStr;
use sc_telemetry::TelemetryEndpoints;

const DEFAULT_PROTOCOL_ID: &str = "math";


// The URL for the telemetry server.
// const STAGING_TELEMETRY_URL: &str = "wss://telemetry.polkadot.io/submit/";

/// Specialized `ChainSpec`. This is a specialization of the general Substrate ChainSpec type.
pub type ChainSpec = sc_service::GenericChainSpec<GenesisConfig>;

pub fn galois_config() -> Result<ChainSpec, String> {
	ChainSpec::from_json_bytes(&include_bytes!("../res/galois.json")[..])
}

// fn galois_build_spec_genesis() -> mathchain_runtime::GenesisConfig {
// 	const ROOT: &'static str = "0x24a80b84d2d5130beafcb2b1a3b1a0e0e1cee122ef0e508d6b1eb862b802fe1d";

// 	let root = AccountId::from(array_bytes::hex_str_array_unchecked!(ROOT, 32));
// 	let endowed_accounts = vec![(root.clone(), 10000 * MATH)];

// 	mathchain_runtime::GenesisConfig {
// 		frame_system: mathchain_runtime::SystemConfig {
// 			code: mathchain_runtime::WASM_BINARY
// 			.expect("WASM binary was not build, please build it!")
// 			.to_vec(),
// 			changes_trie_config: Default::default(),
// 		},
// 		pallet_balances: mathchain_runtime::BalancesConfig {
// 			balances: endowed_accounts,
// 		},
// 		pallet_sudo: mathchain_runtime::SudoConfig { key: root },
// 	}
// }

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

type AccountPublic = <Signature as Verify>::Signer;

/// Generate an account ID from seed.
pub fn get_account_id_from_seed<TPublic: Public>(seed: &str) -> AccountId where
	AccountPublic: From<<TPublic::Pair as Pair>::Public>
{
	AccountPublic::from(get_from_seed::<TPublic>(seed)).into_account()
}

/// Generate an Aura authority key.
// pub fn authority_keys_from_seed(s: &str) -> (AuraId, GrandpaId) {
// 	(
// 		get_from_seed::<AuraId>(s),
// 		get_from_seed::<GrandpaId>(s),
// 	)
// }

fn session_keys(
	aura: AuraId,
	grandpa: GrandpaId,
) -> SessionKeys {
	SessionKeys { aura, grandpa }
}

pub fn get_authority_keys_from_seed(seed: &str) -> (
	AccountId,
	AuraId,
	GrandpaId
) {
	(
		get_account_id_from_seed::<sr25519::Public>(seed),
		get_from_seed::<AuraId>(seed),
		get_from_seed::<GrandpaId>(seed)
	)
}

pub fn galois_for_genesis() -> Result<ChainSpec, String> {
	let wasm_binary = WASM_BINARY.ok_or_else(|| "Galois wasm not available".to_string())?;

	const ROOT: &'static str = "0x24a80b84d2d5130beafcb2b1a3b1a0e0e1cee122ef0e508d6b1eb862b802fe1d";
	let root: AccountId = array_bytes::hex_str_array_unchecked!(ROOT, 32).into();

	const GENESIS_VALIDATOR_SR1: &'static str =
		"0xf88768150c3a86509384e744132b5323390c6c24ddccbe39468865db7c07d842";
	const GENESIS_VALIDATOR_ED1: &'static str =
		"0x490c6732f48ae1ce0e0208d53776e7b0153713fce99e5a0c36731fd4da761450";

	const GENESIS_VALIDATOR_SR2: &'static str =
		"0xa2e1437ba4d59fc44ee774fab33a06d952527e909e35ef64dc91859bbb60fe65";
	const GENESIS_VALIDATOR_ED2: &'static str =
		"0xa2e1437ba4d59fc44ee774fab33a06d952527e909e35ef64dc91859bbb60fe65";

	const GENESIS_VALIDATOR_SR3: &'static str =
		"0xbca164498a1bc44c91e20a64c83431592a9caa7aa509e0ba5d1fc5710b524557";
	const GENESIS_VALIDATOR_ED3: &'static str =
		"0xf350c893e43dafe5d0e1c572673666b3d414057c0d117b476fcac5f777e627f2";

	let genesis_validator1: (
		AccountId,
		AuraId,
		GrandpaId,
	) = {
		let stash = array_bytes::hex_str_array_unchecked!(GENESIS_VALIDATOR_SR1, 32);
		let session = array_bytes::hex_str_array_unchecked!(GENESIS_VALIDATOR_SR1, 32);
		let grandpa = array_bytes::hex_str_array_unchecked!(GENESIS_VALIDATOR_ED1, 32);

		(
			stash.into(),
			session.unchecked_into(),
			grandpa.unchecked_into(),
		)
	};

	let genesis_validator2: (
		AccountId,
		AuraId,
		GrandpaId,
	) = {
		let stash = array_bytes::hex_str_array_unchecked!(GENESIS_VALIDATOR_SR2, 32);
		let session = array_bytes::hex_str_array_unchecked!(GENESIS_VALIDATOR_SR2, 32);
		let grandpa = array_bytes::hex_str_array_unchecked!(GENESIS_VALIDATOR_ED2, 32);

		(
			stash.into(),
			session.unchecked_into(),
			grandpa.unchecked_into(),
		)
	};

	let genesis_validator3: (
		AccountId,
		AuraId,
		GrandpaId,
	) = {
		let stash = array_bytes::hex_str_array_unchecked!(GENESIS_VALIDATOR_SR3, 32);
		let session = array_bytes::hex_str_array_unchecked!(GENESIS_VALIDATOR_SR3, 32);
		let grandpa = array_bytes::hex_str_array_unchecked!(GENESIS_VALIDATOR_ED3, 32);

		(
			stash.into(),
			session.unchecked_into(),
			grandpa.unchecked_into(),
		)
	};

	let endowed_accounts = [
		// Sudo 
		"0x24a80b84d2d5130beafcb2b1a3b1a0e0e1cee122ef0e508d6b1eb862b802fe1d",
		// node1
		"0xf88768150c3a86509384e744132b5323390c6c24ddccbe39468865db7c07d842",
		// node2
		"0xa2e1437ba4d59fc44ee774fab33a06d952527e909e35ef64dc91859bbb60fe65",
		// node3
		"0xbca164498a1bc44c91e20a64c83431592a9caa7aa509e0ba5d1fc5710b524557"
	]
	.iter()
	.map(|s| array_bytes::hex_str_array_unchecked!(s, 32).into())
	.collect::<Vec<_>>();

	Ok(ChainSpec::from_genesis(
		// Name
		"Galois",
		"galois",
		ChainType::Live,
		move || testnet_genesis(
			wasm_binary,
			// Initial Poa authorities
			vec![
				genesis_validator1.clone(),
				genesis_validator2.clone(),
				genesis_validator3.clone(),
			],
			root.clone(),
			endowed_accounts.clone(),
			true
		),
		vec![
			"/ip4/47.111.168.132/tcp/3031/p2p/12D3KooWQx4qMhpTAdYQNck1RhT8MvRQhCsTBWWSQTnicy8XQpYN".parse().unwrap(),
			"/ip4/8.209.214.249/tcp/3033/p2p/12D3KooWSf1rbwLWcSqeR99ZJ2rkt17oVm57xXDJcfhksSbjuDdh".parse().unwrap(),
			"/ip4/47.243.44.7/tcp/3032/p2p/12D3KooWGqzt3fBDpa1tYGBaaYqzHWAtfaUDyiSWkHHpjbs7cBCn".parse().unwrap(),
		],
		Some(
			TelemetryEndpoints::new(vec![
				("/dns4/telemetry.polkadot.io/tcp/443/x-parity-wss/%2Fsubmit%2F".parse().unwrap(), 0),
				("/dns4/telemetry.maiziqianbao.net/tcp/443/x-parity-wss/%2Fsubmit%2F".parse().unwrap(), 0),
				("/dns4/telemetry.maiziqianbao.vip/tcp/443/x-parity-wss/%2Fsubmit%2F".parse().unwrap(), 0),
			]).expect("Galois telemetry url is valid; qed")
		),
		// Protocol ID
		Some(DEFAULT_PROTOCOL_ID),
		// Properties
		Some(math_testnet_properties()),
		// Extensions
		None
	))
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
				get_authority_keys_from_seed("Alice"),
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
		// Telemetry
		None,
		// Protocol ID
		Some(DEFAULT_PROTOCOL_ID),
		// Properties
		Some(math_testnet_properties()),
		// Extensions
		None,
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
				get_authority_keys_from_seed("Alice"),
				get_authority_keys_from_seed("Bob"),
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
		// Telemetry
		None,
		// Protocol ID
		Some(DEFAULT_PROTOCOL_ID),
		// Properties
		Some(math_testnet_properties()),
		// Extensions
		None,
	))
}

/// Configure initial storage state for FRAME modules.
fn testnet_genesis(
	wasm_binary: &[u8],
	initial_authorities: Vec<(AccountId, AuraId, GrandpaId)>,
	root_key: AccountId,
	endowed_accounts: Vec<AccountId>,
	_enable_println: bool,
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
		frame_system: SystemConfig {
			// Add Wasm runtime to storage.
			code: wasm_binary.to_vec(),
			changes_trie_config: Default::default(),
		},
		pallet_balances: BalancesConfig {
			// Configure endowed accounts with initial balance of 10000 Math.
			balances: endowed_accounts.iter().cloned().map(|k|(k, 10000 * MATH)).collect(),
		},
		pallet_aura: AuraConfig {
			authorities: vec![],
		},
		pallet_grandpa: GrandpaConfig {
			authorities: vec![],
		},
		pallet_sudo: SudoConfig {
			// Assign network admin rights.
			key: root_key,
		},
		pallet_evm: EVMConfig {
			accounts: evm_accounts,
		},
		pallet_ethereum: EthereumConfig {},
		pallet_validator_set: ValidatorSetConfig {
			validators: initial_authorities.iter().map(|x| x.0.clone()).collect::<Vec<_>>(),
		},
		pallet_session: SessionConfig {
			keys: initial_authorities.iter().map(|x| {
				(x.0.clone(), x.0.clone(), session_keys(x.1.clone(), x.2.clone()))
			}).collect::<Vec<_>>(),
		},
	}
}
