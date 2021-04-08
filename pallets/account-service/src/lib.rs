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
//! * `bind_for` - Set the MultiAddress with other person AccountId.
//! * `clear_for` - Clean other AccountId MultiAddress bind
//!
//! [`Call`]: ./enum.Call.html
//! [`Config`]: ./trait.Config.html

#![cfg_attr(not(feature = "std"), no_std)]

use sp_std::prelude::*;
use sp_std::fmt::Debug;

use frame_support::{
	decl_module, decl_event, decl_storage, ensure, decl_error,
	traits::{EnsureOrigin, Get},
};
use frame_system::{ensure_signed, ensure_root};
use core::primitive::str;

use codec::{Encode, Decode, Codec};

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
	ethereum: Info,
	twitter: Info,
}

#[derive(Encode, Decode, PartialEq, Eq, Clone, Debug)]
pub enum AccountServiceEnum {
	/// It's some arbitrary raw bytes.
	Nickname(Vec<u8>),
	/// Its a 20 byte representation.
	Ethereum([u8; 20]),
	/// It's a twitter nickname.
	Twitter(Vec<u8>),
}

decl_storage! {
	trait Store for Module<T: Config> as AccountService {
		MultiAddressOf get(fn multi_address_of): map hasher(blake2_128_concat) <T as frame_system::Config>::AccountId => Option<MultiAddressDetails<
			AccountServiceEnum
		>>;
		FromNickname get(fn from_nick_name): map hasher(blake2_128_concat) AccountServiceEnum => <T as frame_system::Config>::AccountId;
		FromEthereum get(fn from_ethereum): map hasher(blake2_128_concat) AccountServiceEnum => <T as frame_system::Config>::AccountId;
		FromTwitter get(fn from_twitter): map hasher(blake2_128_concat) AccountServiceEnum => <T as frame_system::Config>::AccountId;
		AccountRoot get(fn account_root) config(): <T as frame_system::Config>::AccountId;
	}
}

decl_event!(
	pub enum Event<T> where AccountId = <T as frame_system::Config>::AccountId {
		/// A name was forcibly set. \[target\]
		NameForced(AccountId, AccountServiceEnum),
		/// A name was changed. \[who, to\]
		NameChanged(AccountId, AccountServiceEnum),
		/// A name was cleared, and the given balance returned. \[who\]
		NameCleared(AccountId),
		/// Account root key set
		KeyChanged(AccountId),
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
		/// Not allow to bind
		NotAllowed,
		/// WrongFormat
		WrongFormat,
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
		fn bind(origin, account_service: AccountServiceEnum) {
			let sender = ensure_signed(origin)?;
			let info = account_service.clone();
			match info {
				AccountServiceEnum::Nickname(_) => {
					ensure!(!FromNickname::<T>::contains_key(info.clone()), Error::<T>::AlreadyTaked);
					let id = match <MultiAddressOf<T>>::get(&sender) {
						Some(mut id) => {
							id.nickname = info.clone();
							id
						}
						None =>	MultiAddressDetails { nickname: info.clone(), ethereum: AccountServiceEnum::Ethereum([0u8; 20]), twitter: AccountServiceEnum::Twitter(vec![0]) },
					};
					<MultiAddressOf<T>>::insert(&sender, id);
					<FromNickname<T>>::insert(info.clone(), &sender);	
				},
				AccountServiceEnum::Ethereum(_) => {
					ensure!(false, Error::<T>::NotAllowed);
					// ensure!(!FromEthereum::<T>::contains_key(info.clone()), Error::<T>::AlreadyTaked);
					// let id = match <MultiAddressOf<T>>::get(&sender) {
					// 	Some(mut id) => {
					// 		id.ethereum = info.clone();
					// 		id
					// 	}
					// 	None => MultiAddressDetails { nickname: AccountService::Nickname(vec![0]), ethereum: info.clone()},
					// };
					// <MultiAddressOf<T>>::insert(&sender, id);
					// <FromEthereum<T>>::insert(info.clone(), &sender);	
				},
				AccountServiceEnum::Twitter(_) => {
					ensure!(false, Error::<T>::NotAllowed);
					// ensure!(!FromEthereum::<T>::contains_key(info.clone()), Error::<T>::AlreadyTaked);
					// let id = match <MultiAddressOf<T>>::get(&sender) {
					// 	Some(mut id) => {
					// 		id.ethereum = info.clone();
					// 		id
					// 	}
					// 	None => MultiAddressDetails { nickname: AccountService::Nickname(vec![0]), ethereum: info.clone()},
					// };
					// <MultiAddressOf<T>>::insert(&sender, id);
					// <FromEthereum<T>>::insert(info.clone(), &sender);	
				}
			}
			Self::deposit_event(RawEvent::NameChanged(sender.clone(), info.clone()));
		}

		#[weight = 50_000_000]
		fn clear(origin) {
			let sender = ensure_signed(origin)?;
			match <MultiAddressOf<T>>::take(&sender) {
				Some(multi_address_detail) => {
					<FromNickname<T>>::remove(&multi_address_detail.nickname);
					<FromEthereum<T>>::remove(&multi_address_detail.ethereum);
				}
				_ => {}
			};
			Self::deposit_event(RawEvent::NameCleared(sender.clone()));
		}

		#[weight = 50_000_000]
		fn force_bind(origin, dest: <T as frame_system::Config>::AccountId, account_service: AccountServiceEnum) {
			let sender = ensure_signed(origin)?;
			ensure!(sender == Self::account_root(), Error::<T>::NotAllowed);
			let info = account_service.clone();
			let account_info = info.clone();
			match account_info {
				AccountServiceEnum::Nickname(_) => {
					ensure!(!FromNickname::<T>::contains_key(info.clone()), Error::<T>::AlreadyTaked);
					let id = match <MultiAddressOf<T>>::get(&dest) {
						Some(mut id) => {
							id.nickname = info.clone();
							id
						}
						None =>	MultiAddressDetails { nickname: info.clone(), ethereum: AccountServiceEnum::Ethereum([0u8; 20]), twitter: AccountServiceEnum::Twitter(vec![0]) },
					};
					<MultiAddressOf<T>>::insert(&dest, id);
					<FromNickname<T>>::insert(info.clone(), &dest);	
				},
				AccountServiceEnum::Ethereum(_) => {
					// ensure!(false, Error::<T>::NotAllowed);
					ensure!(!FromEthereum::<T>::contains_key(info.clone()), Error::<T>::AlreadyTaked);
					let id = match <MultiAddressOf<T>>::get(&dest) {
						Some(mut id) => {
							id.ethereum = info.clone();
							id
						}
						None => MultiAddressDetails { nickname: AccountServiceEnum::Nickname(vec![0]), ethereum: info.clone(), twitter: AccountServiceEnum::Twitter(vec![0]) },
					};
					<MultiAddressOf<T>>::insert(&dest, id);
					<FromEthereum<T>>::insert(info.clone(), &dest);	
				},
				AccountServiceEnum::Twitter(twitter) => {
					ensure!(!FromTwitter::<T>::contains_key(info.clone()), Error::<T>::AlreadyTaked);
					ensure!(twitter.len() > 8, Error::<T>::WrongFormat);
					let words = "twitter@".as_bytes();
					let prefix = &twitter[0..8];
					ensure!(prefix == words, Error::<T>::WrongFormat);
					let id = match <MultiAddressOf<T>>::get(&dest) {
						Some(mut id) => {
							id.twitter = info.clone();
							id
						}
						None =>	MultiAddressDetails { nickname: AccountServiceEnum::Nickname(vec![0]), ethereum: AccountServiceEnum::Ethereum([0u8; 20]), twitter: info.clone() },
					};
					<MultiAddressOf<T>>::insert(&dest, id);
					<FromTwitter<T>>::insert(info.clone(), &dest);	
				}
			}
			Self::deposit_event(RawEvent::NameChanged(dest.clone(), info.clone()));
		}

		/// Authenticates the current account root key and sets the given AccountId (`new`) as the new account root key.
		///
		/// The dispatch origin for this call must be _Signed_.
		///
		/// # <weight>
		/// - O(1).
		/// - Limited storage reads.
		/// - One DB change.
		/// # </weight>
		#[weight = 5_000_000]
		fn set_key(origin, new: <T as frame_system::Config>::AccountId) {
			// This is a public call, so we ensure that the origin is some signed account.
			let _sender = ensure_root(origin)?;

			Self::deposit_event(RawEvent::KeyChanged(new.clone()));
			<AccountRoot<T>>::put(&new);
		}

		#[weight = 50_000_000]
		fn force_clear(origin, dest: <T as frame_system::Config>::AccountId) {
			let sender = ensure_signed(origin)?;
			ensure!(sender == Self::account_root(), Error::<T>::NotAllowed);
			match <MultiAddressOf<T>>::take(&dest) {
				Some(multi_address_detail) => {
					<FromNickname<T>>::remove(&multi_address_detail.nickname);
					<FromEthereum<T>>::remove(&multi_address_detail.ethereum);
				}
				_ => {}
			};
			Self::deposit_event(RawEvent::NameCleared(dest));
			
		}
	}
}
