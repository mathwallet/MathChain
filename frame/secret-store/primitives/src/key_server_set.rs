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

use codec::{Decode, Encode};
use sp_core::H256;
use sp_runtime::RuntimeDebug;
use sp_std::vec::Vec;
use crate::KeyServerId;

/// Migration id.
pub type MigrationId = H256;

/// Opaque key server network address type.
pub type KeyServerNetworkAddress = Vec<u8>;

/// Key server set snapshot.
#[derive(Decode, Encode, PartialEq, RuntimeDebug)]
pub struct KeyServerSetSnapshot {
	/// Current set of key servers.
	pub current_set: Vec<(KeyServerId, KeyServerNetworkAddress)>,
	/// New set of key servers.
	pub new_set: Vec<(KeyServerId, KeyServerNetworkAddress)>,
	/// Current migration data.
	pub migration: Option<KeyServerSetMigration>,
}

/// Key server set migration.
#[derive(Decode, Encode, PartialEq, RuntimeDebug)]
pub struct KeyServerSetMigration {
	/// Migration id.
	pub id: MigrationId,
	/// Migration set of key servers. It is the new_set at the moment of migration start.
	pub set: Vec<(KeyServerId, KeyServerNetworkAddress)>,
	/// Master node of the migration process.
	pub master: KeyServerId,
	/// Is migration confirmed by this node?
	pub is_confirmed: bool,
}

sp_api::decl_runtime_apis! {
	/// Runtime API that backs the key server set.
	pub trait SecretStoreKeyServerSetApi {
		/// Get server set state.
		fn snapshot(key_server: KeyServerId) -> KeyServerSetSnapshot;
	
		/// Get current key servers with indices.
		fn current_set_with_indices() -> Vec<(KeyServerId, u8)>;
	}
}
