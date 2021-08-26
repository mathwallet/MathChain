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

#![cfg_attr(not(feature = "std"), no_std)]

mod key_servers_mask;

pub mod acl_storage;
pub mod key_server_set;
pub mod service;

pub use key_servers_mask::KeyServersMask;

/// Server key id.
pub type ServerKeyId = sp_core::H256;
/// Entity address.
pub type EntityId = sp_core::H160;
/// Key server address.
pub type KeyServerId = sp_core::H160;
