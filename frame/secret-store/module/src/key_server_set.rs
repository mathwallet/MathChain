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

//! Implementation of key server set that supports auto-migration process.
//!
//! The set has three subsets. The servers that are in the current subset are
//! responsible for running current Secret Store operations. There's new subset
//! that initially holds the same key servers that the current subset. All
//! modifications operations are modifying the new subset. Once one of current
//! key servers recognizes that new subset != current subset, it starts migration
//! process.
//!
//! When migration starts, the new subset is copied into migration subset and
//! migration id is assigned. During migration all servers that are added (i.e.
//! that are in migration set, but not in the current set) are receiving new key
//! shares for all existing keys. All honest key servers that are removed, are
//! erasing their shares for all existing keys. When all servers from migration
//! set have confirmed that migration has completed, the migration set is cleared.
//!
//! The set holds at most 256 servers.

use frame_support::ensure;
use sp_std::vec::Vec;
use primitives::{
	KeyServerId,
	key_server_set::{KeyServerSetSnapshot, KeyServerSetMigration, MigrationId, KeyServerNetworkAddress},
};
use crate::Event;
use crate::blockchain_storage::Storage as BlockchainStorage;
use crate::entity_id_storage::Storage as EntityIdStorage;
use crate::key_server_set_storage::StorageWithMigration;

/// Implementation of key server set with migration support.
pub(crate) struct KeyServerSetWithMigration<BS, ES, SS> {
	blockchain_storage: BS,
	entity_id_storage: ES,
	server_set_storage: SS,
}

impl<BS, ES, SS> KeyServerSetWithMigration<BS, ES, SS> where
	BS: BlockchainStorage,
	ES: EntityIdStorage,
	SS: StorageWithMigration<EntityId=ES::EntityId, BlockNumber=BS::BlockNumber>,
{
	/// Create key server set using given storage.
	pub fn with_storage(blockchain_storage: BS, entity_id_storage: ES, server_set_storage: SS) -> Self {
		KeyServerSetWithMigration { blockchain_storage, entity_id_storage, server_set_storage }
	}

	/// Fill uninitialized key server set with given key servers.
	///
	/// This function should only be called once, during module initialization.
	pub fn fill(
		&mut self,
		key_servers: &[(KeyServerId, KeyServerNetworkAddress)],
		is_initialization_completed: bool,
	) -> Result<(), &'static str> {
		self.server_set_storage.ensure_empty()?;

		for (id, address) in key_servers {
			self.server_set_storage.current().ensure_not_contains(id)?;
			self.server_set_storage.current_mut().append(id.clone(), address.clone())?;
			self.server_set_storage.new_mut().append(id.clone(), address.clone())?;
		}

		if is_initialization_completed {
			self.server_set_storage.initialized();
		}

		Ok(())
	}

	/// Get key server set snapshot.
	pub fn snapshot(&self, key_server: KeyServerId) -> KeyServerSetSnapshot {
		KeyServerSetSnapshot {
			current_set: self.server_set_storage.current().get().into_iter().map(|ks| (ks.id, ks.address)).collect(),
			new_set: self.server_set_storage.new().get().into_iter().map(|ks| (ks.id, ks.address)).collect(),
			migration: self.server_set_storage.migration_id().map(|(migration_id, migration_master_id)|
				KeyServerSetMigration {
					id: migration_id,
					set: self.server_set_storage.migration().get().into_iter().map(|ks| (ks.id, ks.address)).collect(),
					master: migration_master_id,
					is_confirmed: self.server_set_storage.is_migration_confirmed(&key_server),
				},
			),
		}
	}

	/// Get current key servers with indices.
	pub fn current_set_with_indices(&self) -> Vec<(KeyServerId, u8)> {
		self.server_set_storage.current().get().into_iter().map(|ks| (ks.id, ks.index)).collect()
	}

	/// Complete key servers set initialization.
	pub fn complete_initialization(&mut self, caller: ES::EntityId) -> Result<(), &'static str> {
		self.server_set_storage.ensure_not_initialized()?;
		self.server_set_storage.ensure_can_modify(caller)?;

		self.server_set_storage.initialized();

		Ok(())
	}

	/// Add key server to the set.
	///
	/// If initialization is already completed, the changes are applied only when
	/// migration is completed.
	pub fn add_key_server(
		&mut self,
		caller: ES::EntityId,
		id: KeyServerId,
		address: KeyServerNetworkAddress,
	) -> Result<(), &'static str> {
		self.server_set_storage.ensure_can_modify(caller)?;

		if !self.server_set_storage.is_initialized() {
			self.server_set_storage.current_mut().append(id.clone(), address.clone())?;
		}
		self.server_set_storage.new_mut().append(id, address)?;

		self.blockchain_storage.deposit_event(Event::KeyServerAdded(id));

		Ok(())
	}

	/// Remove key server from the set.
	///
	/// If initialization is already completed, the changes are applied only when
	/// migration is completed.
	pub fn remove_key_server(
		&mut self,
		caller: ES::EntityId,
		id: KeyServerId,
	) -> Result<(), &'static str> {
		self.server_set_storage.ensure_can_modify(caller)?;

		if !self.server_set_storage.is_initialized() {
			self.server_set_storage.current_mut().remove(&id)?;
		}
		self.server_set_storage.new_mut().remove(&id)?;

		self.blockchain_storage.deposit_event(Event::KeyServerRemoved(id));

		Ok(())
	}

	/// Start migration from the current set to the new set.
	pub fn start_migration(
		&mut self,
		caller: ES::EntityId,
		migration_id: MigrationId,
	) -> Result<(), &'static str> {
		self.server_set_storage.ensure_no_migration()?;

		let current = self.server_set_storage.current().get_as_map();
		let new = self.server_set_storage.new().get_as_map();

		ensure!(
			!new.is_empty(),
			"Cannot migrate to empty key server set",
		);

		/*let have_different_network_address = |id|
			current.get(id).map(|ks| ks.address) !=
				new.get(id).map(|ks| ks.address);*/

		ensure!(
			current != new,
			"No changes to key server set",
		);

		let master_id = self.entity_id_storage.resolve_key_server_id(caller)?;
		ensure!(
			current.contains_key(&master_id) || new.contains_key(&master_id),
			"The caller has no rights to start migration",
		);

		// when all prerequisites are satisfied: start migration
		self.server_set_storage.migration_mut().fill_from(new);
		self.server_set_storage.set_migration_id(Some((migration_id, master_id)));

		self.blockchain_storage.deposit_event(Event::MigrationStarted);

		Ok(())
	}

	/// Confirm migration completetion.
	pub fn confirm_migration(
		&mut self,
		caller: ES::EntityId,
		migration_id: MigrationId,
	) -> Result<(), &'static str> {
		self.server_set_storage.ensure_migration(&migration_id)?;

		let server_id = self.entity_id_storage.resolve_key_server_id(caller)?;
		self.server_set_storage.migration().ensure_contains(&server_id)?;
		self.server_set_storage.ensure_migration_not_confirmed(&server_id)?;

		// remember confirmation
		self.server_set_storage.confirm_migration(&server_id);

		// check if every server from migration set has confirmed migration
		let migration = self.server_set_storage.migration().get_as_map();
		let has_all_confirmations = migration.keys().all(|id| self.server_set_storage.is_migration_confirmed(id));
		if !has_all_confirmations {
			return Ok(());
		}

		// forget everything about current migration
		let current_block_number = self.blockchain_storage.current_block_number();
		self.server_set_storage.clear_migration_confirmations(&migration);
		self.server_set_storage.current_mut().fill_from(migration);
		self.server_set_storage.migration_mut().clear();
		self.server_set_storage.set_current_change_block(current_block_number);
		self.server_set_storage.set_migration_id(None);

		self.blockchain_storage.deposit_event(Event::MigrationCompleted);

		Ok(())
	}
}

#[cfg(test)]
mod tests {
	use frame_support::{StorageMap, StorageValue};
	use crate::{CurrentSetChangeBlock, MigrationConfirmations};
	use crate::mock::*;
	use super::*;

	fn key_server_set() -> crate::KeyServerSet<TestRuntime> {
		crate::key_server_set()
	}

	#[test]
	fn should_not_allow_double_initialization() {
		default_initialization().execute_with(|| {
			// default_initialization() creates initialized contract
			key_server_set().complete_initialization(
				Origin::signed(OWNER),
			).unwrap_err();
		});
	}

	#[test]
	fn should_not_allow_initialization_by_non_owner() {
		basic_initialization().execute_with(|| {
			// basic_initialization() creates uninitialized contract
			key_server_set().complete_initialization(
				Origin::signed(REQUESTER1),
			).unwrap_err();
		});
	}

	#[test]
	fn should_allow_initialization_by_owner() {
		basic_initialization().execute_with(|| {
			// basic_initialization() creates uninitialized contract
			key_server_set().complete_initialization(
				Origin::signed(OWNER),
			).unwrap();
		});
	}

	#[test]
	fn should_return_current_set_after_initialization() {
		default_initialization().execute_with(|| {
			// just after initialization: the same as in the genesis config
			assert_eq!(
				ordered_set(key_server_set().snapshot(KEY_SERVER1_ID.into()).current_set),
				default_key_server_set(),
			);
		});
	}

	#[test]
	fn should_return_new_set_after_initialization() {
		default_initialization().execute_with(|| {
			// just after initialization: the same as in the genesis config
			assert_eq!(
				ordered_set(key_server_set().snapshot(KEY_SERVER1_ID.into()).new_set),
				default_key_server_set(),
			);
		});
	}

	#[test]
	fn should_return_migration_after_initialization() {
		default_initialization().execute_with(|| {
			// just after initialization: no active migration
			assert_eq!(
				key_server_set().snapshot(KEY_SERVER1_ID.into()).migration,
				None,
			);
		});
	}

	#[test]
	fn should_accept_add_key_server_from_owner() {
		default_initialization().execute_with(|| {
			// add server#3 once initialization has completed
			key_server_set().add_key_server(
				Origin::signed(OWNER),
				KEY_SERVER2_ID.into(),
				KEY_SERVER2_ID.to_vec(),
			).unwrap();

			let snapshot = key_server_set().snapshot(KEY_SERVER1_ID.into());

			// the server#3 is not on current set
			assert_eq!(ordered_set(snapshot.current_set), default_key_server_set());
			// the server#3 is on new set
			let mut new_set = default_key_server_set();
			new_set.push((KEY_SERVER2_ID.into(), KEY_SERVER2_ID.to_vec()));
			assert_eq!(ordered_set(snapshot.new_set), ordered_set(new_set));
			// the migration has not yet started
			assert_eq!(snapshot.migration, None);
		});
	}

	#[test]
	fn should_not_accept_add_key_server_from_non_owner() {
		default_initialization().execute_with(|| {
			// add server#3 once initialization has completed
			key_server_set().add_key_server(
				Origin::signed(REQUESTER1),
				KEY_SERVER2_ID.into(),
				KEY_SERVER2_ID.to_vec(),
			).unwrap_err();
		});
	}

	#[test]
	fn should_not_accept_add_existing_key_server() {
		default_initialization().execute_with(|| {
			// add server#3 once initialization has completed
			key_server_set().add_key_server(
				Origin::signed(OWNER),
				KEY_SERVER1_ID.into(),
				KEY_SERVER1_ID.to_vec(),
			).unwrap_err();
		});
	}

	#[test]
	fn should_accept_remove_key_server_from_owner() {
		default_initialization().execute_with(|| {
			// remove server#2 once initialization has completed
			key_server_set().remove_key_server(
				Origin::signed(OWNER),
				KEY_SERVER1_ID.into(),
			).unwrap();

			let snapshot = key_server_set().snapshot(KEY_SERVER1_ID.into());

			// the server#2 is on current set
			assert_eq!(ordered_set(snapshot.current_set), default_key_server_set());
			// the server#2 is not on new set
			let mut new_set = default_key_server_set();
			new_set.pop();
			assert_eq!(ordered_set(snapshot.new_set), ordered_set(new_set));
			// the migration has not yet started
			assert_eq!(snapshot.migration, None);
		});
	}

	#[test]
	fn should_not_accept_remove_key_server_from_non_owner() {
		default_initialization().execute_with(|| {
			// remove server#2 once initialization has completed
			key_server_set().remove_key_server(
				Origin::signed(REQUESTER1),
				KEY_SERVER1_ID.into(),
			).unwrap_err();
		});
	}

	#[test]
	fn should_not_accept_remove_unknown_key_server_from_non_owner() {
		default_initialization().execute_with(|| {
			// remove server#2 once initialization has completed
			key_server_set().remove_key_server(
				Origin::signed(OWNER),
				KEY_SERVER2_ID.into(),
			).unwrap_err();
		});
	}

	#[test]
	fn should_start_migration() {
		default_initialization().execute_with(|| {
			// add server#3 once initialization has completed
			key_server_set().add_key_server(
				Origin::signed(OWNER),
				KEY_SERVER2_ID.into(),
				KEY_SERVER2_ID.to_vec(),
			).unwrap();
			// and then server#1 starts migration
			key_server_set().start_migration(
				Origin::signed(KEY_SERVER1),
				[42; 32].into(),
			).unwrap();

			let snapshot = key_server_set().snapshot(KEY_SERVER1_ID.into());
			let mut new_set = default_key_server_set();
			new_set.push((KEY_SERVER2_ID.into(), KEY_SERVER2_ID.to_vec()));

			// check that migration has started
			assert_eq!(
				KeyServerSetSnapshot {
					current_set: ordered_set(snapshot.current_set),
					new_set: ordered_set(snapshot.new_set),
					migration: snapshot.migration.map(|migration| KeyServerSetMigration {
						id: migration.id,
						set: ordered_set(migration.set),
						master: migration.master,
						is_confirmed: migration.is_confirmed,
					}),
				},
				KeyServerSetSnapshot {
					current_set: default_key_server_set(),
					new_set: ordered_set(new_set.clone()),
					migration: Some(KeyServerSetMigration {
						id: [42; 32].into(),
						set: ordered_set(new_set),
						master: KEY_SERVER1_ID.into(),
						is_confirmed: false,
					}),
				},
			);
		});
	}

	#[test]
	fn should_not_start_migration_when_another_migration_in_progress() {
		default_initialization().execute_with(|| {
			// add server#3 once initialization has completed
			key_server_set().add_key_server(
				Origin::signed(OWNER),
				KEY_SERVER2_ID.into(),
				KEY_SERVER2_ID.to_vec(),
			).unwrap();
			// and then server#1 starts migration
			key_server_set().start_migration(
				Origin::signed(KEY_SERVER1),
				[42; 32].into(),
			).unwrap();
			// and then again server#1 starts migration
			key_server_set().start_migration(
				Origin::signed(KEY_SERVER1),
				[42; 32].into(),
			).unwrap_err();
		});
	}

	#[test]
	fn should_not_start_migration_when_it_is_not_required() {
		default_initialization().execute_with(|| {
			// try to start migration when current set is equal to new set
			key_server_set().start_migration(
				Origin::signed(KEY_SERVER1),
				[42; 32].into(),
			).unwrap_err();
		});
	}

	#[test]
	fn should_not_start_migration_to_empty_set() {
		default_initialization().execute_with(|| {
			// remove server#1 and server#2 once initialization has completed
			key_server_set().remove_key_server(
				Origin::signed(OWNER),
				KEY_SERVER0_ID.into(),
			).unwrap();
			key_server_set().remove_key_server(
				Origin::signed(OWNER),
				KEY_SERVER1_ID.into(),
			).unwrap();

			// try to start migration when new set is empty
			key_server_set().start_migration(
				Origin::signed(KEY_SERVER1),
				[42; 32].into(),
			).unwrap_err();
		});
	}

	#[test]
	fn should_not_start_migration_by_unrelated_server() {
		default_initialization().execute_with(|| {
			// add server#3 once initialization has completed
			key_server_set().add_key_server(
				Origin::signed(OWNER),
				KEY_SERVER2_ID.into(),
				KEY_SERVER2_ID.to_vec(),
			).unwrap();

			// try to start migration by server#4
			key_server_set().start_migration(
				Origin::signed(KEY_SERVER3),
				[42; 32].into(),
			).unwrap_err();
		});
	}

	#[test]
	fn should_accept_confirm_migration() {
		default_initialization().execute_with(|| {
			// set block number to 42 to check that last set change block changes when migration completes
			frame_system::Module::<TestRuntime>::set_block_number(42);

			// add server#3 once initialization has completed
			key_server_set().add_key_server(
				Origin::signed(OWNER),
				KEY_SERVER2_ID.into(),
				KEY_SERVER2_ID.to_vec(),
			).unwrap();
			// and then server#1 starts migration
			key_server_set().start_migration(
				Origin::signed(KEY_SERVER1),
				[42; 32].into(),
			).unwrap();

			// check that noone has confirmed migration yet
			assert!(
				!key_server_set().snapshot(KEY_SERVER0_ID.into()).migration.unwrap().is_confirmed
			);
			assert!(
				!key_server_set().snapshot(KEY_SERVER1_ID.into()).migration.unwrap().is_confirmed
			);
			assert!(
				!key_server_set().snapshot(KEY_SERVER2_ID.into()).migration.unwrap().is_confirmed
			);
			assert_eq!(CurrentSetChangeBlock::<TestRuntime>::get(), 0);

			// confirm migration by server#1
			key_server_set().confirm_migration(
				Origin::signed(KEY_SERVER0),
				[42; 32].into(),
			).unwrap();

			// check that migration has confirmed by: server#1
			assert!(
				key_server_set().snapshot(KEY_SERVER0_ID.into()).migration.unwrap().is_confirmed
			);
			assert!(
				!key_server_set().snapshot(KEY_SERVER1_ID.into()).migration.unwrap().is_confirmed
			);
			assert!(
				!key_server_set().snapshot(KEY_SERVER2_ID.into()).migration.unwrap().is_confirmed
			);
			assert_eq!(CurrentSetChangeBlock::<TestRuntime>::get(), 0);

			// confirm migration by server#2
			key_server_set().confirm_migration(
				Origin::signed(KEY_SERVER1),
				[42; 32].into(),
			).unwrap();

			// check that migration has confirmed by: server#1, server#2
			assert!(
				key_server_set().snapshot(KEY_SERVER0_ID.into()).migration.unwrap().is_confirmed
			);
			assert!(
				key_server_set().snapshot(KEY_SERVER1_ID.into()).migration.unwrap().is_confirmed
			);
			assert!(
				!key_server_set().snapshot(KEY_SERVER2_ID.into()).migration.unwrap().is_confirmed
			);
			assert_eq!(CurrentSetChangeBlock::<TestRuntime>::get(), 0);
			assert!( MigrationConfirmations::contains_key(KeyServerId::from(KEY_SERVER0_ID)));
			assert!( MigrationConfirmations::contains_key(KeyServerId::from(KEY_SERVER1_ID)));
			assert!(!MigrationConfirmations::contains_key(KeyServerId::from(KEY_SERVER2_ID)));

			// confirm migration by server#3
			key_server_set().confirm_migration(
				Origin::signed(KEY_SERVER2),
				[42; 32].into(),
			).unwrap();

			// check that migration has completed
			let snapshot = key_server_set().snapshot(KEY_SERVER1_ID.into());
			let mut new_set = default_key_server_set();
			new_set.push((KEY_SERVER2_ID.into(), KEY_SERVER2_ID.to_vec()));
			assert_eq!(snapshot.migration, None);
			assert_eq!(ordered_set(snapshot.current_set), new_set);
			assert_eq!(ordered_set(snapshot.new_set), new_set);
			assert_eq!(CurrentSetChangeBlock::<TestRuntime>::get(), 42);
			assert!(!MigrationConfirmations::contains_key(KeyServerId::from(KEY_SERVER0_ID)));
			assert!(!MigrationConfirmations::contains_key(KeyServerId::from(KEY_SERVER1_ID)));
			assert!(!MigrationConfirmations::contains_key(KeyServerId::from(KEY_SERVER2_ID)));
		});
	}

	#[test]
	fn should_not_accept_wrong_id_in_confirm_migration() {
		default_initialization().execute_with(|| {
			// add server#3 once initialization has completed
			key_server_set().add_key_server(
				Origin::signed(OWNER),
				KEY_SERVER2_ID.into(),
				KEY_SERVER2_ID.to_vec(),
			).unwrap();
			// and then server#1 starts migration
			key_server_set().start_migration(
				Origin::signed(KEY_SERVER1),
				[42; 32].into(),
			).unwrap();

			// try to confirm other migration by server#1
			key_server_set().confirm_migration(
				Origin::signed(KEY_SERVER1),
				[10; 32].into(),
			).unwrap_err();
		});
	}

	#[test]
	fn should_not_accept_confirm_migration_from_non_participant() {
		default_initialization().execute_with(|| {
			// add server#3 once initialization has completed
			key_server_set().add_key_server(
				Origin::signed(OWNER),
				KEY_SERVER2_ID.into(),
				KEY_SERVER2_ID.to_vec(),
			).unwrap();
			// and then server#1 starts migration
			key_server_set().start_migration(
				Origin::signed(KEY_SERVER1),
				[42; 32].into(),
			).unwrap();

			// try to confirm other migration by server#4
			key_server_set().confirm_migration(
				Origin::signed(KEY_SERVER3),
				[42; 32].into(),
			).unwrap_err();
		});
	}

	#[test]
	fn should_not_accept_confirm_migration_twice() {
		default_initialization().execute_with(|| {
			// add server#3 once initialization has completed
			key_server_set().add_key_server(
				Origin::signed(OWNER),
				KEY_SERVER2_ID.into(),
				KEY_SERVER2_ID.to_vec(),
			).unwrap();
			// and then server#1 starts migration
			key_server_set().start_migration(
				Origin::signed(KEY_SERVER1),
				[42; 32].into(),
			).unwrap();

			// try to confirm migration by server#1
			key_server_set().confirm_migration(
				Origin::signed(KEY_SERVER1),
				[42; 32].into(),
			).unwrap();
			// and then again - try to confirm migration by server#1
			key_server_set().confirm_migration(
				Origin::signed(KEY_SERVER1),
				[42; 32].into(),
			).unwrap_err();
		});
	}

	#[test]
	fn should_fail_when_trying_to_add_more_than_256_key_servers() {
		default_initialization().execute_with(|| {
			// add new key servers so that there are now 256 key servers in the new set
			let mut server_id = [0; 20];
			let mut server_addr = vec![0, 0];
			for i in 2..256 {
				server_id[1] = i as u8;
				server_addr[1] = i as u8;
				key_server_set().add_key_server(
					Origin::signed(OWNER),
					server_id.into(),
					server_addr.clone(),
				).unwrap();
			}

			// adding server#256 should fail
			server_id[0] = 42;
			server_addr[0] = 42;
			key_server_set().add_key_server(
				Origin::signed(OWNER),
				server_id.into(),
				server_addr,
			).unwrap_err();
		});
	}
}