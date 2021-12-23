// Copyright 2015-2020 Parity Technologies (UK) Ltd.
// This file is part of Parity Secret Store.

// Parity Secret Store is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// Parity Secret Store is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with Parity Secret Store.  If not, see <http://www.gnu.org/licenses/>.

//! Test utilities

#![cfg(test)]

use std::collections::BTreeMap;
use sp_runtime::Perbill;
use sp_runtime::testing::Header;
use sp_runtime::traits::{IdentityLookup, BlakeTwo256};
use sp_core::H256;
use frame_support::{impl_outer_origin, impl_outer_event, parameter_types};
use crate::GenesisConfig;
use super::*;

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct TestRuntime;

mod secret_store {
	pub use crate::Event;
}

impl_outer_event! {
	pub enum TestEvent for TestRuntime {
		frame_system<T>,
		pallet_balances<T>,
		secret_store,
	}
}

impl_outer_origin!{
	pub enum Origin for TestRuntime {}
}

parameter_types! {
	pub const BlockHashCount: u64 = 250;
	pub const MaximumBlockWeight: u32 = 1024;
	pub const MaximumBlockLength: u32 = 2 * 1024;
	pub const AvailableBlockRatio: Perbill = Perbill::one();
}

impl frame_system::Config for TestRuntime {
	type Origin = Origin;
	type Index = u64;
	type BlockNumber = u64;
	type Hash = H256;
	type Call = ();
	type Hashing = BlakeTwo256;
	type AccountId = u64;
	type Lookup = IdentityLookup<Self::AccountId>;
	type Header = Header;
	type Event = TestEvent;
	type BlockHashCount = BlockHashCount;
	type MaximumBlockWeight = MaximumBlockWeight;
	type MaximumBlockLength = MaximumBlockLength;
	type AvailableBlockRatio = AvailableBlockRatio;
	type Version = ();
	type ModuleToIndex = ();
	type AccountData = pallet_balances::AccountData<u64>;
	type OnNewAccount = ();
	type OnKilledAccount = ();
}

parameter_types! {
	pub const ExistentialDeposit: u64 = 1;
	pub const TransferFee: u64 = 0;
	pub const CreationFee: u64 = 0;
	pub const TransactionBaseFee: u64 = 1;
	pub const TransactionByteFee: u64 = 0;
}

impl pallet_balances::Config for TestRuntime {
	type Balance = u64;
	type Event = TestEvent;
	type DustRemoval = ();
	type ExistentialDeposit = ExistentialDeposit;
	type AccountStore = frame_system::Module<TestRuntime>;
}

impl Config for TestRuntime {
	type Event = TestEvent;
	type Currency = pallet_balances::Module<Self>;
}

pub const OWNER: u64 = 1;
pub const REQUESTER1: u64 = 2;
pub const REQUESTER2: u64 = 3;
pub const REAL_REQUESTER1: u64 = 4;
pub const REAL_REQUESTER2: u64 = 5;
pub const KEY_SERVER0: u64 = 100;
pub const KEY_SERVER1: u64 = 101;
pub const KEY_SERVER2: u64 = 102;
pub const KEY_SERVER3: u64 = 103;
pub const KEY_SERVER4: u64 = 104;

pub const REAL_REQUESTER1_ADDRESS: [u8; 20] = [0x50, 0x50, 0xa4, 0xf4, 0xb3, 0xf9, 0x33, 0x8c, 0x34, 0x72,
	0xdc, 0xc0, 0x1a, 0x87, 0xc7, 0x6a, 0x14, 0x4b, 0x3c, 0x9c];
pub const REAL_REQUESTER1_PUBLIC: [u8; 64] = [0x4d, 0x4b, 0x6c, 0xd1, 0x36, 0x10, 0x32, 0xca, 0x9b, 0xd2,
	0xae, 0xb9, 0xd9, 0x00, 0xaa, 0x4d, 0x45, 0xd9, 0xea, 0xd8, 0x0a, 0xc9, 0x42, 0x33, 0x74, 0xc4,
	0x51, 0xa7, 0x25, 0x4d, 0x07, 0x66, 0x2a, 0x3e, 0xad, 0xa2, 0xd0, 0xfe, 0x20, 0x8b, 0x6d, 0x25,
	0x7c, 0xeb, 0x0f, 0x06, 0x42, 0x84, 0x66, 0x2e, 0x85, 0x7f, 0x57, 0xb6, 0x6b, 0x54, 0xc1, 0x98,
	0xbd, 0x31, 0x0d, 0xed, 0x36, 0xd0];

pub const REAL_REQUESTER2_ADDRESS: [u8; 20] = [0x33, 0x25, 0xa7, 0x84, 0x25, 0xf1, 0x7a, 0x7e, 0x48, 0x7e,
	0xb5, 0x66, 0x6b, 0x2b, 0xfd, 0x93, 0xab, 0xb0, 0x6c, 0x70];
pub const REAL_REQUESTER2_PUBLIC: [u8; 64] = [0x53, 0x1f, 0xe6, 0x06, 0x81, 0x34, 0x50, 0x3d, 0x27, 0x23,
	0x13, 0x32, 0x27, 0xc8, 0x67, 0xac, 0x8f, 0xa6, 0xc8, 0x3c, 0x53, 0x7e, 0x9a, 0x44, 0xc3, 0xc5,
	0xbd, 0xbd, 0xcb, 0x1f, 0xe3, 0x37, 0x9e, 0x92, 0xc2, 0x65, 0xe7, 0x1e, 0x48, 0x1b, 0xa8, 0x2a,
	0x84, 0x67, 0x5a, 0x47, 0xac, 0x70, 0x5a, 0x20, 0x0f, 0xcd, 0x52, 0x4e, 0x92, 0xd9, 0x3b, 0x0e,
	0x73, 0x86, 0xf2, 0x6a, 0x54, 0x58];

pub const KEY_SERVER0_ID: [u8; 20] = [KEY_SERVER0 as u8; 20];
pub const KEY_SERVER1_ID: [u8; 20] = [KEY_SERVER1 as u8; 20];
pub const KEY_SERVER2_ID: [u8; 20] = [KEY_SERVER2 as u8; 20];
pub const KEY_SERVER3_ID: [u8; 20] = [KEY_SERVER3 as u8; 20];
pub const KEY_SERVER4_ID: [u8; 20] = [KEY_SERVER4 as u8; 20];

type NetworkAddress = Vec<u8>;

pub fn ordered_set(set: Vec<(KeyServerId, NetworkAddress)>) -> Vec<(KeyServerId, NetworkAddress)> {
	set.into_iter().collect::<BTreeMap<_, _>>().into_iter().collect()
}

pub fn default_key_server_set() -> Vec<(KeyServerId, NetworkAddress)> {
	vec![
		(KEY_SERVER0_ID.into(), KEY_SERVER0_ID.to_vec()),
		(KEY_SERVER1_ID.into(), KEY_SERVER1_ID.to_vec()),
	]
}

pub fn default_key_server_set3() -> Vec<(KeyServerId, NetworkAddress)> {
	vec![
		(KEY_SERVER0_ID.into(), KEY_SERVER0_ID.to_vec()),
		(KEY_SERVER1_ID.into(), KEY_SERVER1_ID.to_vec()),
		(KEY_SERVER2_ID.into(), KEY_SERVER2_ID.to_vec()),
	]
}

pub fn default_key_server_set5() -> Vec<(KeyServerId, NetworkAddress)> {
	vec![
		(KEY_SERVER0_ID.into(), KEY_SERVER0_ID.to_vec()),
		(KEY_SERVER1_ID.into(), KEY_SERVER1_ID.to_vec()),
		(KEY_SERVER2_ID.into(), KEY_SERVER2_ID.to_vec()),
		(KEY_SERVER3_ID.into(), KEY_SERVER3_ID.to_vec()),
		(KEY_SERVER4_ID.into(), KEY_SERVER4_ID.to_vec()),
	]
}

fn initialize(
	is_initialization_completed: bool,
	key_server_set: Vec<(KeyServerId, NetworkAddress)>,
) -> sp_io::TestExternalities {
	let mut t = system::GenesisConfig::default().build_storage::<TestRuntime>().unwrap();
	let config = GenesisConfig::<TestRuntime> {
		owner: OWNER,
		is_initialization_completed,
		key_servers: key_server_set,
		claims: vec![
			(OWNER, [OWNER as u8; 20].into()),
			(REQUESTER1, [REQUESTER1 as u8; 20].into()),
			(REAL_REQUESTER1, REAL_REQUESTER1_ADDRESS.into()),
			(REAL_REQUESTER2, REAL_REQUESTER2_ADDRESS.into()),
			(KEY_SERVER0, KEY_SERVER0_ID.into()),
			(KEY_SERVER1, KEY_SERVER1_ID.into()),
			(KEY_SERVER2, KEY_SERVER2_ID.into()),
			(KEY_SERVER3, KEY_SERVER3_ID.into()),
			(KEY_SERVER4, KEY_SERVER4_ID.into()),
		],
		server_key_generation_fee: 1_000_000,
		server_key_retrieval_fee: 1_000_000,
		document_key_store_fee: 1_000_000,
		document_key_shadow_retrieval_fee: 1_000_000,
	};
	config.assimilate_storage(&mut t).unwrap();
	let config = pallet_balances::GenesisConfig::<TestRuntime> {
		balances: vec![
			(OWNER, 10_000_000),
			(REQUESTER1, 10_000_000),
			(REAL_REQUESTER1, 10_000_000),
		],
	};
	config.assimilate_storage(&mut t).unwrap();

	t.into()
}

pub fn basic_initialization() -> sp_io::TestExternalities {
	initialize(false, default_key_server_set())
}

pub fn default_initialization() -> sp_io::TestExternalities {
	initialize(true, default_key_server_set())
}

pub fn default_initialization_with_three_servers() -> sp_io::TestExternalities {
	initialize(true, default_key_server_set3())
}

pub fn default_initialization_with_five_servers() -> sp_io::TestExternalities {
	initialize(true, default_key_server_set5())
}