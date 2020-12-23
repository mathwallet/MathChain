// Copyright (C) 2019-2020 MathChain.
// SPDX-License-Identifier: Apache-2.0

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! # NameService Module
//!
//! - [`account_service::Config`](./trait.Config.html)
//! - [`Call`](./enum.Call.html)
//!
//! ## Overview
//!
//! ## Interface
//!
//! ### Dispatchable Functions
//!
//! * `bind` - Set the MultiAddress with AccountId.
//! * `clear` - Clean the special AccountId MultiAddress bind.
//! * `set` - Change special Address format for AccountId.
//! * `bind_for` - Set the MultiAddress with other person AccountId.
//! * `clear_for` - Clean other AccountId MultiAddress bind
//!
//! [`Call`]: ./enum.Call.html
//! [`Config`]: ./trait.Config.html

#![cfg_attr(not(feature = "std"), no_std)]

use sp_std::prelude::*;
use sp_std::{fmt::Debug, ops::Add, iter::once};
use sp_runtime::{
	traits::{StaticLookup, Zero}
};
use frame_support::{
	decl_module, decl_event, decl_storage, ensure, decl_error,
	traits::{Currency, EnsureOrigin, ReservableCurrency, OnUnbalanced, Get},
};
use frame_system::{ensure_signed, ensure_root};

use codec::{Encode, Decode, Compact, HasCompact, Codec};

pub trait Config: frame_system::Config {
	/// The overarching event type.
	type Event: From<Event<Self>> + Into<<Self as frame_system::Config>::Event>;

	/// The origin which may forcibly set or remove a name. Root can always do this.
	type ForceOrigin: EnsureOrigin<Self::Origin>;

	/// The minimum length a name may be.
	type MinLength: Get<usize>;

	/// The maximum length a name may be.
	type MaxLength: Get<usize>;

}

#[derive(Clone, Encode, Decode, Eq, PartialEq)]
pub struct MultiAddressDetails<
	Info: Codec,
> {
	nickname: Info,
	ethereum: Info
}

#[derive(PartialEq, Eq, Clone, Debug)]
pub enum MultiAddress {
	/// It's some arbitrary raw bytes.
	Raw(Vec<u8>),
	/// It's a 32 byte representation.
	Address32([u8; 32]),
	/// Its a 20 byte representation.
	Address20([u8; 20]),
}

impl Decode for MultiAddress {
	fn decode<I: codec::Input>(input: &mut I) -> sp_std::result::Result<Self, codec::Error> {
		let b = input.read_byte()?;
		Ok(match b {
			// 0 => MultiAddress::Id(<AccountId>::decode(input)?),
			n @ 1 ..= 33 => {
				let mut r = vec![0u8; n as usize - 1];
				input.read(&mut r[..])?;
				MultiAddress::Raw(r)
			}
			34 => MultiAddress::Address32(<[u8; 32]>::decode(input)?),
			35 => MultiAddress::Address20(<[u8; 20]>::decode(input)?),
			_ => return Err(codec::Error::from("invalid leading byte")),
		})
	}
}

impl Encode for MultiAddress {
	fn encode(&self) -> Vec<u8> {
		match self {
			// MultiAddress::Id(ref h) => once(0u8).chain(h.iter().cloned()).collect(),
			MultiAddress::Raw(ref x) => {
				let l = x.len().min(32);
				let mut r = vec![l as u8 + 1; l + 1];
				&mut r[1..].copy_from_slice(&x[..l as usize]);
				r
			},
			MultiAddress::Address32(ref h) => once(34u8).chain(h.iter().cloned()).collect(),
			MultiAddress::Address20(ref h) => once(35u8).chain(h.iter().cloned()).collect(),
		}
	}
}
impl codec::EncodeLike for MultiAddress {}

decl_storage! {
	trait Store for Module<T: Config> as AccountService {
		MultiAddressOf: map hasher(blake2_128_concat) T::AccountId => Option<MultiAddressDetails<
			MultiAddress
		>>;
		FromNickname: map hasher(blake2_128_concat) MultiAddress => T::AccountId;
		FromEthereum: map hasher(blake2_128_concat) MultiAddress => T::AccountId;
	}
}

decl_event!(
	pub enum Event<T> where AccountId = <T as frame_system::Config>::AccountId {
		/// A name was set. \[who\]
		NameSet(AccountId),
		/// A name was forcibly set. \[target\]
		NameForced(AccountId),
		/// A name was changed. \[who\]
		NameChanged(AccountId),
		/// A name was cleared, and the given balance returned. \[who\]
		NameCleared(AccountId),
	}
);

decl_error! {
	/// Error for the nicks module.
	pub enum Error for Module<T: Config> {
		/// A name is too short.
		TooShort,
		/// A name is too long.
		TooLong,
		/// An account isn't named.
		Unnamed,
		/// A name or address has been binded.
		AlreadyTaked,
	}
}

decl_module! {
	/// Nicks module declaration.
	pub struct Module<T: Config> for enum Call where origin: T::Origin {
		type Error = Error<T>;

		fn deposit_event() = default;

		/// The minimum length a name may be.
		const MinLength: u32 = T::MinLength::get() as u32;

		/// The maximum length a name may be.
		const MaxLength: u32 = T::MaxLength::get() as u32;

		/// Set an account's name. The name should be a UTF-8-encoded string by convention, though
		/// we don't check it.
		///
		/// The name may not be more than `T::MaxLength` bytes, nor less than `T::MinLength` bytes.
		///
		/// If the account doesn't already have a name, then a fee of `ReservationFee` is reserved
		/// in the account.
		///
		/// The dispatch origin for this call must be _Signed_.
		///
		/// # <weight>
		/// - O(1).
		/// - At most one balance operation.
		/// - One storage read/write.
		/// - One event.
		/// # </weight>
		#[weight = 50_000_000]
		fn bind(origin, name: MultiAddress) {
			let sender = ensure_signed(origin)?;
			let info = name.clone();
			match info {
				MultiAddress::Raw(info) => {
					ensure!(!FromNickname::<T>::contains_key(MultiAddress::Raw(info.clone())), Error::<T>::AlreadyTaked);
					// <NicknameOf<T>>::insert(&sender, info.clone());
					// FromNickname::<T>::insert(info.clone(), &sender);
					let mut id = match <MultiAddressOf<T>>::get(&sender) {
						Some(mut id) => {
							// Only keep non-positive judgements.
							id
						}
						None => MultiAddressDetails { nickname: MultiAddress::Raw(info.clone()), ethereum: MultiAddress::Address20([0u8; 20])},
					};
					<MultiAddressOf<T>>::insert(&sender, id);
					<FromNickname<T>>::insert(MultiAddress::Raw(info.clone()), &sender);
				},
				MultiAddress::Address20(info) => {
					// ensure!(!COUNT_AIRDROP_RECIPIENTS.is_zero(), Error::<T>::AlreadyTaked)
				},
				_ => {

				}
			}
			Self::deposit_event(RawEvent::NameSet(sender.clone()));

		}
	}
}

// #[cfg(test)]
// mod tests {
// 	use super::*;

// 	use frame_support::{
// 		assert_ok, assert_noop, impl_outer_origin, parameter_types,
// 		ord_parameter_types
// 	};
// 	use sp_core::H256;
// 	use frame_system::EnsureSignedBy;
// 	use sp_runtime::{
// 		testing::Header, traits::{BlakeTwo256, IdentityLookup, BadOrigin},
// 	};

// 	impl_outer_origin! {
// 		pub enum Origin for Test where system = frame_system {}
// 	}

// 	#[derive(Clone, Eq, PartialEq)]
// 	pub struct Test;
// 	parameter_types! {
// 		pub const BlockHashCount: u64 = 250;
// 		pub BlockWeights: frame_system::limits::BlockWeights =
// 			frame_system::limits::BlockWeights::simple_max(1024);
// 	}
// 	impl frame_system::Config for Test {
// 		type BaseCallFilter = ();
// 		type BlockWeights = ();
// 		type BlockLength = ();
// 		type DbWeight = ();
// 		type Origin = Origin;
// 		type Index = u64;
// 		type BlockNumber = u64;
// 		type Hash = H256;
// 		type Call = ();
// 		type Hashing = BlakeTwo256;
// 		type AccountId = u64;
// 		type Lookup = IdentityLookup<Self::AccountId>;
// 		type Header = Header;
// 		type Event = ();
// 		type BlockHashCount = BlockHashCount;
// 		type Version = ();
// 		type PalletInfo = ();
// 		type AccountData = pallet_balances::AccountData<u64>;
// 		type OnNewAccount = ();
// 		type OnKilledAccount = ();
// 		type SystemWeightInfo = ();
// 	}
// 	parameter_types! {
// 		pub const ExistentialDeposit: u64 = 1;
// 	}
// 	impl pallet_balances::Config for Test {
// 		type MaxLocks = ();
// 		type Balance = u64;
// 		type Event = ();
// 		type DustRemoval = ();
// 		type ExistentialDeposit = ExistentialDeposit;
// 		type AccountStore = System;
// 		type WeightInfo = ();
// 	}
// 	parameter_types! {
// 		pub const ReservationFee: u64 = 2;
// 		pub const MinLength: usize = 3;
// 		pub const MaxLength: usize = 16;
// 	}
// 	ord_parameter_types! {
// 		pub const One: u64 = 1;
// 	}
// 	impl Config for Test {
// 		type Event = ();
// 		type Currency = Balances;
// 		type ReservationFee = ReservationFee;
// 		type Slashed = ();
// 		type ForceOrigin = EnsureSignedBy<One, u64>;
// 		type MinLength = MinLength;
// 		type MaxLength = MaxLength;
// 	}
// 	type System = frame_system::Module<Test>;
// 	type Balances = pallet_balances::Module<Test>;
// 	type Nicks = Module<Test>;

// 	fn new_test_ext() -> sp_io::TestExternalities {
// 		let mut t = frame_system::GenesisConfig::default().build_storage::<Test>().unwrap();
// 		pallet_balances::GenesisConfig::<Test> {
// 			balances: vec![
// 				(1, 10),
// 				(2, 10),
// 			],
// 		}.assimilate_storage(&mut t).unwrap();
// 		t.into()
// 	}

// 	#[test]
// 	fn kill_name_should_work() {
// 		new_test_ext().execute_with(|| {
// 			assert_ok!(Nicks::set_name(Origin::signed(2), b"Dave".to_vec()));
// 			assert_eq!(Balances::total_balance(&2), 10);
// 			assert_ok!(Nicks::kill_name(Origin::signed(1), 2));
// 			assert_eq!(Balances::total_balance(&2), 8);
// 			assert_eq!(<NameOf<Test>>::get(2), None);
// 		});
// 	}

// 	#[test]
// 	fn force_name_should_work() {
// 		new_test_ext().execute_with(|| {
// 			assert_noop!(
// 				Nicks::set_name(Origin::signed(2), b"Dr. David Brubeck, III".to_vec()),
// 				Error::<Test>::TooLong,
// 			);

// 			assert_ok!(Nicks::set_name(Origin::signed(2), b"Dave".to_vec()));
// 			assert_eq!(Balances::reserved_balance(2), 2);
// 			assert_ok!(Nicks::force_name(Origin::signed(1), 2, b"Dr. David Brubeck, III".to_vec()));
// 			assert_eq!(Balances::reserved_balance(2), 2);
// 			assert_eq!(<NameOf<Test>>::get(2).unwrap(), (b"Dr. David Brubeck, III".to_vec(), 2));
// 		});
// 	}

// 	#[test]
// 	fn normal_operation_should_work() {
// 		new_test_ext().execute_with(|| {
// 			assert_ok!(Nicks::set_name(Origin::signed(1), b"Gav".to_vec()));
// 			assert_eq!(Balances::reserved_balance(1), 2);
// 			assert_eq!(Balances::free_balance(1), 8);
// 			assert_eq!(<NameOf<Test>>::get(1).unwrap().0, b"Gav".to_vec());

// 			assert_ok!(Nicks::set_name(Origin::signed(1), b"Gavin".to_vec()));
// 			assert_eq!(Balances::reserved_balance(1), 2);
// 			assert_eq!(Balances::free_balance(1), 8);
// 			assert_eq!(<NameOf<Test>>::get(1).unwrap().0, b"Gavin".to_vec());

// 			assert_ok!(Nicks::clear_name(Origin::signed(1)));
// 			assert_eq!(Balances::reserved_balance(1), 0);
// 			assert_eq!(Balances::free_balance(1), 10);
// 		});
// 	}

// 	#[test]
// 	fn error_catching_should_work() {
// 		new_test_ext().execute_with(|| {
// 			assert_noop!(Nicks::clear_name(Origin::signed(1)), Error::<Test>::Unnamed);

// 			assert_noop!(
// 				Nicks::set_name(Origin::signed(3), b"Dave".to_vec()),
// 				pallet_balances::Error::<Test, _>::InsufficientBalance
// 			);

// 			assert_noop!(Nicks::set_name(Origin::signed(1), b"Ga".to_vec()), Error::<Test>::TooShort);
// 			assert_noop!(
// 				Nicks::set_name(Origin::signed(1), b"Gavin James Wood, Esquire".to_vec()),
// 				Error::<Test>::TooLong
// 			);
// 			assert_ok!(Nicks::set_name(Origin::signed(1), b"Dave".to_vec()));
// 			assert_noop!(Nicks::kill_name(Origin::signed(2), 1), BadOrigin);
// 			assert_noop!(Nicks::force_name(Origin::signed(2), 1, b"Whatever".to_vec()), BadOrigin);
// 		});
// 	}
// }
