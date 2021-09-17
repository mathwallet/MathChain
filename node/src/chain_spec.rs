use sp_core::{sr25519, Pair, Public, U256, H160, crypto::UncheckedInto,};
use mathchain_runtime::{
	AccountId, AuraConfig, BalancesConfig, EVMConfig, EthereumConfig, GenesisConfig, GrandpaConfig,
	SudoConfig, SystemConfig, WASM_BINARY, Signature, ValidatorSetConfig, opaque::SessionKeys, SessionConfig,
	SecretStoreConfig
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
		"0xe8fa4b0f758ba8c1e2911fd238bb6fd635f721f5025985ed100d5c7e730a3097";

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
		"0xbca164498a1bc44c91e20a64c83431592a9caa7aa509e0ba5d1fc5710b524557",
		// SS1
		"0xb4b105e7526ce5ae94a9be24a6bf6ab6b168255b5ed0cd65d77b905e3c3da52c",
		// SS2
		"0x18d3fdd65fb3ed9a1d89727fe230af4683303140a77aa569de387c72d64c9300",
		// SS3
		"0xa6a7302b264499959f33d3eb069f5016399ba6b5c13809398a7ea8890aa19138",
	]
	.iter()
	.map(|s| array_bytes::hex_str_array_unchecked!(s, 32).into())
	.collect::<Vec<_>>();

	Ok(ChainSpec::from_genesis(
		// Name
		"Galois-PoC-1",
		"galois",
		ChainType::Live,
		move || {
			testnet_genesis(
				wasm_binary,
				// Initial Poa authorities
				vec![
					genesis_validator1.clone(),
					genesis_validator2.clone(),
					genesis_validator3.clone(),
				],
				root.clone(),
				endowed_accounts.clone(),
				vec![
					(
						"641f76320a8956f5cf2fe231bf1e3640ea3822dc".parse().unwrap(),
						array_bytes::hex_str_array_unchecked!("0xb4b105e7526ce5ae94a9be24a6bf6ab6b168255b5ed0cd65d77b905e3c3da52c", 32).into(),
						&"47.111.168.132:10001".to_owned().into_bytes(), // node-validator
					),
					(
						"c6c4c6cf871ca4a17d25fcafc67faf6ac559bb0a".parse().unwrap(),
						array_bytes::hex_str_array_unchecked!("0x18d3fdd65fb3ed9a1d89727fe230af4683303140a77aa569de387c72d64c9300", 32).into(),
						&"8.209.214.249:10001".to_owned().into_bytes(), // node-jp
					),
					(
						"dCcf5258EBF7e34D494Cac9A01346575d040a1c3".parse().unwrap(),
						array_bytes::hex_str_array_unchecked!("0xa6a7302b264499959f33d3eb069f5016399ba6b5c13809398a7ea8890aa19138", 32).into(),
						&"47.243.44.7:10001".to_owned().into_bytes(), // node-hk
					)
				],
				true
			)
		},
		vec![],
		Some(
			TelemetryEndpoints::new(vec![
				("/dns4/telemetry.polkadot.io/tcp/443/x-parity-wss/%2Fsubmit%2F".parse().unwrap(), 0),
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
				get_account_id_from_seed::<sr25519::Public>("Charlie"),
				get_account_id_from_seed::<sr25519::Public>("Dave"),
				get_account_id_from_seed::<sr25519::Public>("Alice//stash"),
				get_account_id_from_seed::<sr25519::Public>("Bob//stash"),
				get_account_id_from_seed::<sr25519::Public>("Charlie//stash"),
				get_account_id_from_seed::<sr25519::Public>("Dave//stash"),
			],
			vec![
				(
					"1a642f0e3c3af545e7acbd38b07251b3990914f1".parse().unwrap(),
					get_account_id_from_seed::<sr25519::Public>("Alice"),
					&"127.0.0.1:10000".to_owned().into_bytes(),
				),
				(
					"5050a4f4b3f9338c3472dcc01a87c76a144b3c9c".parse().unwrap(),
					get_account_id_from_seed::<sr25519::Public>("Bob"),
					&"127.0.0.1:10001".to_owned().into_bytes(),
				),
				(
					"3325a78425f17a7e487eb5666b2bfd93abb06c70".parse().unwrap(),
					get_account_id_from_seed::<sr25519::Public>("Charlie"),
					&"127.0.0.1:10002".to_owned().into_bytes(),
				),
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
		move || {
				testnet_genesis(
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
				vec![],
				true,
			)
		},
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
	key_servers: Vec<(H160, AccountId, &[u8])>,
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
		system: SystemConfig {
			// Add Wasm runtime to storage.
			code: wasm_binary.to_vec(),
			changes_trie_config: Default::default(),
		},
		balances: BalancesConfig {
			// Configure endowed accounts with initial balance of 10000 Math.
			balances: endowed_accounts.iter().cloned().map(|k|(k, 10000 * MATH)).collect(),
		},
		aura: AuraConfig {
			authorities: vec![],
		},
		grandpa: GrandpaConfig {
			authorities: vec![],
		},
		sudo: SudoConfig {
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
		secretstore_runtime_module: SecretStoreConfig {
			owner: get_account_id_from_seed::<sr25519::Public>("Alice"),
			is_initialization_completed: true,
			key_servers: key_servers.iter().cloned().map(|k| (
				k.0, k.2.iter().cloned().collect()
			)).collect(),
			claims: key_servers.iter().cloned().map(|k| (
				k.1, k.0
			)).collect(),
			server_key_generation_fee: 0,
			server_key_retrieval_fee: 0,
			document_key_store_fee: 0,
			document_key_shadow_retrieval_fee: 0,
		}
	}
}
