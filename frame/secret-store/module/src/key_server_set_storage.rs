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

use codec::{Encode, Decode};
use frame_support::{IterableStorageMap, StorageValue, StorageMap, ensure};
use frame_system::ensure_signed;
use sp_std::{
	collections::btree_map::BTreeMap,
	marker::PhantomData,
	vec::Vec,
};
use primitives::{KeyServerId, KeyServersMask, key_server_set::{MigrationId as MigrationIdT, KeyServerNetworkAddress}};
use crate::{
	Config,
	Owner, IsInitialized,
	MigrationId, MigrationConfirmations, CurrentSetChangeBlock,
	CurrentKeyServers, MigrationKeyServers, NewKeyServers,
};

/// Single key server data.
#[derive(Encode, Decode, PartialEq)]
pub(crate) struct KeyServer {
	/// Index in the list.
	pub index: u8,
	/// Public key of key server.
	pub id: KeyServerId,
	/// Network address of the key server.
	pub address: KeyServerNetworkAddress,
}

/// The storage of single key server set.
pub(crate) trait Storage {
	/// Ensure that the set contains given server.
	fn ensure_contains(&self, id: &KeyServerId) -> Result<(), &'static str> {
		ensure!(
			self.contains(id),
			"Key server is not in the set",
		);
		Ok(())
	}
	/// Ensure that the set does not contains given server.
	fn ensure_not_contains(&self, id: &KeyServerId) -> Result<(), &'static str> {
		ensure!(
			!self.contains(id),
			"The server is already in the set",
		);
		Ok(())
	}

	/// Returns all servers from the set.
	fn get(&self) -> Vec<KeyServer>;
	/// Returns all servers from the set as map.
	fn get_as_map(&self) -> BTreeMap<KeyServerId, KeyServer> {
		self.get().into_iter().map(|ks| (ks.id.clone(), ks)).collect()
	}

	/// Returns true if the set contains server with given id.
	fn contains(&self, id: &KeyServerId) -> bool;
	/// Append key server to the set. Should fail if the server is
	/// already in the set.
	fn append(&mut self, id: KeyServerId, address: KeyServerNetworkAddress) -> Result<(), &'static str>;
	/// Remove key server from the set. Should fail if the server is not
	/// in the set.
	fn remove(&mut self, id: &KeyServerId) -> Result<(), &'static str>;
	/// Update key server from the set. Should fail if the server is not
	/// in the set or if the address is the same.
	fn update(&mut self, id: &KeyServerId, address: KeyServerNetworkAddress) -> Result<(), &'static str>;
	/// 
	fn fill_from(&mut self, key_servers: BTreeMap<KeyServerId, KeyServer>);
	///
	fn clear(&mut self);
}

/// The storage of key server set that suports migration.
pub(crate) trait StorageWithMigration {
	/// Entity id type.
	type EntityId;
	/// Block number type.
	type BlockNumber;

	/// Ensure that the storage is empty.
	fn ensure_empty(&self) -> Result<(), &'static str> {
		ensure!(
			self.current().get().is_empty(),
			"The key server set is not empty",
		);
		Ok(())
	}
	/// Ensure that the initialization has not yet completed.
	fn ensure_not_initialized(&self) -> Result<(), &'static str> {
		ensure!(
			!self.is_initialized(),
			"The key server set is already initialized",
		);
		Ok(())
	}
	/// Ensure that migration with given id is in progress.
	fn ensure_migration(&self, migration_id: &MigrationIdT) -> Result<(), &'static str> {
		ensure!(
			self.migration_id().map(|(mid, _)| mid).as_ref() == Some(&migration_id),
			"The migration is not active",
		);
		Ok(())
	}
	/// Ensure that migration is not confirmed by given key server.
	fn ensure_migration_not_confirmed(&self, id: &KeyServerId) -> Result<(), &'static str> {
		ensure!(
			!self.is_migration_confirmed(id),
			"Migration is already confirmed by the key server",
		);
		Ok(())
	}
	/// Ensure that there's no active migration.
	fn ensure_no_migration(&self) -> Result<(), &'static str> {
		ensure!(
			self.migration_id().is_none(),
			"The key servers migration has already started",
		);
		Ok(())
	}
	/// Ensure that the entity could make modifications to the list.
	fn ensure_can_modify(&self, caller: Self::EntityId) -> Result<(), &'static str>;

	/// Returns true if set initialization has been completed already.
	fn is_initialized(&self) -> bool;
	/// After this call, all calls of `is_initialized` will return true.
	fn initialized(&mut self);

	/// If migration is active, returns migration id and id of migration master (key
	/// server that has initiated migration).
	fn migration_id(&self) -> Option<(MigrationIdT, KeyServerId)>;
	/// Sets migration id and migration maste id.
	fn set_migration_id(&mut self, id: Option<(MigrationIdT, KeyServerId)>);

	/// Returns true if there's active migration and the caller has already confirmed
	/// migration conmpletion.
	fn is_migration_confirmed(&self, id: &KeyServerId) -> bool;
	/// Marks current migration completed by given key server.
	fn confirm_migration(&mut self, id: &KeyServerId);
	/// Clear migration confirmations from given key servers.
	fn clear_migration_confirmations(&mut self, key_servers: &BTreeMap<KeyServerId, KeyServer>);
	/// Set current set change block number.
	fn set_current_change_block(&mut self, block: Self::BlockNumber);

	/// Returns reference to the current servers subset.
	fn current(&self) -> &dyn Storage;
	/// Returns reference to the migration servers subset.
	fn migration(&self) -> &dyn Storage;
	/// Returns reference to the new servers subset.
	fn new(&self) -> &dyn Storage;
	/// Returns reference to the current servers subset.
	fn current_mut(&mut self) -> &mut dyn Storage;
	/// Returns reference to the migration servers subset.
	fn migration_mut(&mut self) -> &mut dyn Storage;
	/// Returns reference to the new servers subset.
	fn new_mut(&mut self) -> &mut dyn Storage;
}

/// The storage of single key server set.
pub(crate) struct RuntimeStorage<M>(PhantomData<M>);

impl<M> Default for RuntimeStorage<M> {
	fn default() -> Self {
		RuntimeStorage(Default::default())
	}
}

impl<M> Storage for RuntimeStorage<M> where
	M: IterableStorageMap<KeyServerId, KeyServer, Query=Option<KeyServer>>,
{
	fn get(&self) -> Vec<KeyServer> {
		M::iter().map(|(_, ks)| ks).collect()
	}

	fn get_as_map(&self) -> BTreeMap<KeyServerId, KeyServer> {
		M::iter().collect()
	}

	fn contains(&self, id: &KeyServerId) -> bool {
		M::contains_key(id)
	}

	fn append(&mut self, id: KeyServerId, address: KeyServerNetworkAddress) -> Result<(), &'static str> {
		let mut existing_servers_mask = KeyServersMask::default();
		for (existing_id, existing_server) in M::iter() {
			ensure!(
				existing_id != id,
				"Key server is already in the set",
			);
			existing_servers_mask.set(existing_server.index);
		}

		M::insert(
			id.clone(),
			KeyServer {
				id,
				address,
				index: existing_servers_mask
					.lowest_unoccupied_index()
					.ok_or("Number of key servers in the set cannot be more than 256")?,
			},
		);

		Ok(())
	}

	fn remove(&mut self, id: &KeyServerId) -> Result<(), &'static str> {
		match M::take(id) {
			Some(_) => Ok(()),
			None => Err("Key server is not in the set"),
		}
	}

	fn update(&mut self, id: &KeyServerId, address: KeyServerNetworkAddress) -> Result<(), &'static str> {
		self.ensure_contains(id)?;

		M::mutate(id, |key_server| {
			let mut key_server = key_server.as_mut().expect("ensure_contains check passed; qed");
			match key_server.address == address {
				true => Err("Nothing to update"),
				false => {
					key_server.address = address;
					Ok(())
				}
			}
		})
	}

	fn fill_from(&mut self, key_servers: BTreeMap<KeyServerId, KeyServer>) {
		self.clear();
		for (id, server) in key_servers {
			M::insert(id, server);
		}
	}

	fn clear(&mut self) {
		let ids = M::iter().map(|(id, _)| id).collect::<Vec<_>>();
		for id in ids {
			M::remove(id);
		}
	}
}

/// The storage of 'migratable' key server set that supports migration.
pub(crate) struct RuntimeStorageWithMigration<T> {
	current: RuntimeStorage<CurrentKeyServers>,
	migration: RuntimeStorage<MigrationKeyServers>,
	new: RuntimeStorage<NewKeyServers>,
	_phantom: PhantomData<T>,
}

impl<T> Default for RuntimeStorageWithMigration<T> {
	fn default() -> Self {
		RuntimeStorageWithMigration {
			current: Default::default(),
			migration: Default::default(),
			new: Default::default(),
			_phantom: Default::default(),
		}
	}
}

impl<T: Config> StorageWithMigration for RuntimeStorageWithMigration<T> {
	type EntityId = T::Origin;
	type BlockNumber = <T as frame_system::Config>::BlockNumber;

	fn ensure_can_modify(&self, caller: Self::EntityId) -> Result<(), &'static str> {
		ensure!(
			ensure_signed(caller)? == Owner::<T>::get(),
			"This operation can only be performed by the set owner",
		);
		Ok(())
	}

	fn is_initialized(&self) -> bool {
		IsInitialized::get()
	}

	fn initialized(&mut self) {
		IsInitialized::put(true);
	}

	fn migration_id(&self) -> Option<(MigrationIdT, KeyServerId)> {
		MigrationId::get()
	}

	fn set_migration_id(&mut self, id: Option<(MigrationIdT, KeyServerId)>) {
		match id {
			Some((migration_id, master_id)) => MigrationId::put((migration_id, master_id)),
			None => MigrationId::kill(),
		}
	}

	fn is_migration_confirmed(&self, id: &KeyServerId) -> bool {
		MigrationConfirmations::contains_key(id)
	}

	fn confirm_migration(&mut self, id: &KeyServerId) {
		MigrationConfirmations::insert(id, ())
	}

	fn clear_migration_confirmations(&mut self, key_servers: &BTreeMap<KeyServerId, KeyServer>) {
		for id in key_servers.keys() {
			MigrationConfirmations::remove(id);
		}
	}

	fn set_current_change_block(&mut self, block: Self::BlockNumber) {
		CurrentSetChangeBlock::<T>::put(block);
	}

	fn current(&self) -> &dyn Storage {
		&self.current
	}

	fn migration(&self) -> &dyn Storage {
		&self.migration
	}

	fn new(&self) -> &dyn Storage {
		&self.new
	}

	fn current_mut(&mut self) -> &mut dyn Storage {
		&mut self.current
	}

	fn migration_mut(&mut self) -> &mut dyn Storage {
		&mut self.migration
	}

	fn new_mut(&mut self) -> &mut dyn Storage {
		&mut self.new
	}
}
