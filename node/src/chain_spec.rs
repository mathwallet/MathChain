use sp_core::{sr25519, Pair, Public, U256, H160, crypto::UncheckedInto,};
use galois_runtime::{
	AccountId, AuraConfig, BalancesConfig, EVMConfig, EthereumConfig, GenesisConfig, GrandpaConfig,
	SudoConfig, SystemConfig, WASM_BINARY, Signature, ValidatorSetConfig, opaque::SessionKeys, SessionConfig,
	SecretStoreConfig
};
use mathchain_runtime::{
	WASM_BINARY as MATHCHAIN_WASM_BINARY, GenesisConfig as MathChainGenesisConfig,
	GrandpaConfig as MathChainGrandpaConfig, SystemConfig as MathChainSystemConfig,
	EthereumConfig as MathChainEthereumConfig, EVMConfig as MathChainEVMConfig,
	BalancesConfig as MathChainBalancesConfig, SessionConfig as MathChainSessionConfig,
	Signature as MathChainSignature, ValidatorSetConfig as MathChainValidatorSetConfig,
	SudoConfig as MathChainSudoConfig, AuraConfig as MathChainAuraConfig,
	AccountId as MathChainAccountId, opaque::SessionKeys as MathChainSessionKeys,
};

use galois_runtime::{
	WASM_BINARY as GALOIS_WASM_BINARY, GenesisConfig as GaloisGenesisConfig,
	GrandpaConfig as GaloisGrandpaConfig, SystemConfig as GaloisSystemConfig,
	EthereumConfig as GaloisEthereumConfig, EVMConfig as GaloisEVMConfig,
	BalancesConfig as GaloisBalancesConfig, SessionConfig as GaloisSessionConfig,
	Signature as GaloisSignature, ValidatorSetConfig as GaloisValidatorSetConfig,
	SudoConfig as GaloisSudoConfig, AuraConfig as GaloisAuraConfig,
	AccountId as GaloisAccountId, opaque::SessionKeys as GaloisSessionKeys,
	SecretStoreConfig as GaloisSecretStoreConfig,
};

use mathchain_runtime::constants::currency::MATHS as MATH;
use galois_runtime::constants::currency::MATHS as GALOIS_MATH;

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
pub type MathChainChainSpec = sc_service::GenericChainSpec<MathChainGenesisConfig>;

pub fn galois_config() -> Result<ChainSpec, String> {
	ChainSpec::from_json_bytes(&include_bytes!("../res/galois.json")[..])
}

// pub fn mathchain_config() -> Result<ChainSpec, String> {
// 	ChainSpec::from_json_bytes(&include_bytes!("../res/mathchain.json")[..])
// }

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

pub fn math_mainnet_properties() -> Properties {
	let mut properties = Properties::new();

	properties.insert("ss58Format".into(), 39.into());
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

fn mathchain_session_keys(
	aura: AuraId,
	grandpa: GrandpaId,
) -> MathChainSessionKeys {
	MathChainSessionKeys { aura, grandpa }
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

pub fn mathchain_for_genesis() -> Result<MathChainChainSpec, String> {
	let wasm_binary = MATHCHAIN_WASM_BINARY.ok_or_else(|| "MathChain wasm not available".to_string())?;

	const ROOT: &'static str = "0x52c8e8826b91de613ee17d235606e018c1b21b809a4dbaa2a02a201f3e652f46";
	let root: AccountId = array_bytes::hex_str_array_unchecked!(ROOT, 32).into();

	const GENESIS_VALIDATOR_SR1: &'static str =
		"0xcedc29088e59f26c0c8351901155e8635d284a71d613483d50c67ce430de1624";
	const GENESIS_VALIDATOR_ED1: &'static str =
		"0x7a3020e28c13d0bf09da95ffbf6dc5f2c0f761fba989a27def5c9fade3b902e6";

	const GENESIS_VALIDATOR_SR2: &'static str =
		"0x981b1f2a47fef3966bef324f04353f5b7604944735f3335bf0c16f7585561043";
	const GENESIS_VALIDATOR_ED2: &'static str =
		"0xce413ec8fec4d05371cc8a23be9c3737bca673e0930b416e22f6473dad96b031";

	const GENESIS_VALIDATOR_SR3: &'static str =
		"0xd0592370e4916780d04cdd15e3728a21c2bd4a2a0e90311069bdb65666818910";
	const GENESIS_VALIDATOR_ED3: &'static str =
		"0xcab2336b293bdae448fa71960bf24fe75600dbddb5a2ddf0b06d9ba943f40248";

	const GENESIS_VALIDATOR_SR4: &'static str =
		"0xe8dbd251d552fe21bdf4f865388c000c66642ddb5c13447071a867968f91af1c";
	const GENESIS_VALIDATOR_ED4: &'static str =
		"0x85798655f9fcf1f00595a50749c9ff82bab324a64d64b2d1d2ea514cb9e330a0";

	const GENESIS_VALIDATOR_SR5: &'static str =
		"0xda404b5492a4085cffba91ae336a652fd56a173ff756f6188b0216d7b6880062";
	const GENESIS_VALIDATOR_ED5: &'static str =
		"0x7a26e71c884ebc7ebb4d0d4032eaf561db77ccf9c71ba88ab663e847ee289a9d";

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

	let genesis_validator4: (
		AccountId,
		AuraId,
		GrandpaId,
	) = {
		let stash = array_bytes::hex_str_array_unchecked!(GENESIS_VALIDATOR_SR4, 32);
		let session = array_bytes::hex_str_array_unchecked!(GENESIS_VALIDATOR_SR4, 32);
		let grandpa = array_bytes::hex_str_array_unchecked!(GENESIS_VALIDATOR_ED4, 32);

		(
			stash.into(),
			session.unchecked_into(),
			grandpa.unchecked_into(),
		)
	};

	let genesis_validator5: (
		AccountId,
		AuraId,
		GrandpaId,
	) = {
		let stash = array_bytes::hex_str_array_unchecked!(GENESIS_VALIDATOR_SR5, 32);
		let session = array_bytes::hex_str_array_unchecked!(GENESIS_VALIDATOR_SR5, 32);
		let grandpa = array_bytes::hex_str_array_unchecked!(GENESIS_VALIDATOR_ED5, 32);

		(
			stash.into(),
			session.unchecked_into(),
			grandpa.unchecked_into(),
		)
	};

	let endowed_accounts = [
		// Sudo 
		"0x52c8e8826b91de613ee17d235606e018c1b21b809a4dbaa2a02a201f3e652f46",
		// node1
		"0xcedc29088e59f26c0c8351901155e8635d284a71d613483d50c67ce430de1624",
		// node2
		"0x981b1f2a47fef3966bef324f04353f5b7604944735f3335bf0c16f7585561043",
		// node3
		"0xd0592370e4916780d04cdd15e3728a21c2bd4a2a0e90311069bdb65666818910",
		// node4
		"0xe8dbd251d552fe21bdf4f865388c000c66642ddb5c13447071a867968f91af1c",
		// node5
		"0xda404b5492a4085cffba91ae336a652fd56a173ff756f6188b0216d7b6880062",
	]
	.iter()
	.map(|s| array_bytes::hex_str_array_unchecked!(s, 32).into())
	.collect::<Vec<_>>();

	Ok(MathChainChainSpec::from_genesis(
		// Name
		"MathChain",
		// Id
		"MathChain-PoC-1",
		ChainType::Live,
		move || {
			mainnet_genesis(
				wasm_binary,
				// Initial Poa authorities
				vec![
					genesis_validator1.clone(),
					genesis_validator2.clone(),
					genesis_validator3.clone(),
					genesis_validator4.clone(),
					genesis_validator5.clone(),
				],
				root.clone(),
				endowed_accounts.clone(),
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
		Some(math_mainnet_properties()),
		// Extensions
		None
	))
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
		"MathChain-dev",
		// ID
		"MathChain-dev",
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
			balances: endowed_accounts.iter().cloned().map(|k|(k, 10000 * GALOIS_MATH)).collect(),
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
		evm: EVMConfig {
			accounts: evm_accounts,
		},
		ethereum: EthereumConfig {},
		validator_set: ValidatorSetConfig {
			validators: initial_authorities.iter().map(|x| x.0.clone()).collect::<Vec<_>>(),
		},
		session: SessionConfig {
			keys: initial_authorities.iter().map(|x| {
				(x.0.clone(), x.0.clone(), session_keys(x.1.clone(), x.2.clone()))
			}).collect::<Vec<_>>(),
		},
		secret_store: SecretStoreConfig {
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

/// Configure initial storage state for FRAME modules.
fn mainnet_genesis(
	wasm_binary: &[u8],
	initial_authorities: Vec<(AccountId, AuraId, GrandpaId)>,
	root_key: AccountId,
	endowed_accounts: Vec<AccountId>,
	_enable_println: bool,
) -> MathChainGenesisConfig {
	MathChainGenesisConfig {
		system: MathChainSystemConfig {
			// Add Wasm runtime to storage.
			code: wasm_binary.to_vec(),
			changes_trie_config: Default::default(),
		},
		balances: MathChainBalancesConfig {
			// Configure endowed accounts with initial balance of 10000 Math.
			balances: endowed_accounts.iter().cloned().map(|k|(k, 100 * MATH)).collect(),
		},
		aura: MathChainAuraConfig {
			authorities: vec![],
		},
		grandpa: MathChainGrandpaConfig {
			authorities: vec![],
		},
		sudo: MathChainSudoConfig {
			// Assign network admin rights.
			key: root_key,
		},
		evm: MathChainEVMConfig {
			accounts: BTreeMap::new(),
		},
		ethereum: MathChainEthereumConfig {},
		validator_set: MathChainValidatorSetConfig {
			validators: initial_authorities.iter().map(|x| x.0.clone()).collect::<Vec<_>>(),
		},
		session: MathChainSessionConfig {
			keys: initial_authorities.iter().map(|x| {
				(x.0.clone(), x.0.clone(), mathchain_session_keys(x.1.clone(), x.2.clone()))
			}).collect::<Vec<_>>(),
		},
	}
}
