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

use sp_std::prelude::*;

mod blockchain_storage;
mod entity_id_storage;
mod document_key_shadow_retrieval;
mod document_key_store;
mod key_server_set;
mod key_server_set_storage;
mod mock;
mod server_key_generation;
mod server_key_retrieval;
mod service;

use frame_support::{StorageMap, traits::Currency, decl_module, decl_event, decl_storage, ensure};
use frame_system::{self as system, ensure_signed};
use primitives::{
	EntityId,
	KeyServerId,
	ServerKeyId,
	KeyServersMask,
	key_server_set::{KeyServerSetSnapshot, KeyServerNetworkAddress, MigrationId as MigrationIdT},
};
use document_key_shadow_retrieval::{
	DocumentKeyShadowRetrievalRequest,
	DocumentKeyShadowRetrievalPersonalData,
	DocumentKeyShadowRetrievalService,
};
use document_key_store::{DocumentKeyStoreRequest, DocumentKeyStoreService};
use server_key_generation::{ServerKeyGenerationRequest, ServerKeyGenerationService};
use server_key_retrieval::{ServerKeyRetrievalRequest, ServerKeyRetrievalService};
use key_server_set_storage::KeyServer;

pub type BalanceOf<T> = <<T as Config>::Currency as Currency<<T as frame_system::Config>::AccountId>>::Balance;

/// The module configuration trait
pub trait Config: frame_system::Config {
	/// They overarching event type.
	type Event: From<Event> + Into<<Self as frame_system::Config>::Event>;

	/// The currency type used for paying services.
	type Currency: Currency<Self::AccountId>;
}

decl_module! {
	pub struct Module<T: Config> for enum Call where origin: T::Origin {
		fn deposit_event() = default;

		#[weight = 50_000_000]
		pub fn change_owner(origin, new_owner: T::AccountId) {
			let origin = ensure_signed(origin)?;
			ensure!(
				origin == Owner::<T>::get(),
				"Only owner can change owner",
			);

			Owner::<T>::put(new_owner);
		}

		/// Claim given id.
		///
		/// Any account may claim single entity id.
		/// Entity id may only be claimed by at most one account.
		#[weight = 50_000_000]
		pub fn claim_id(origin, id: EntityId) {
			ensure!(
				!<ClaimedBy<T>>::contains_key(&id),
				"Id is already claimed",
			);

			let origin = ensure_signed(origin)?;
			ensure!(
				!<ClaimedId<T>>::contains_key(&origin),
				"Account has already claimed an id",
			);

			<ClaimedBy<T>>::insert(id, origin.clone());
			<ClaimedId<T>>::insert(origin, id);
		}

		/// Complete key servers set initialization.
		///
		/// Can only be called by owner.
		#[weight = 50_000_000]
		pub fn complete_initialization(origin) {
			key_server_set::<T>().complete_initialization(origin)?;
		}

		/// Add key server to the set.
		///
		/// Can only be called by owner.
		#[weight = 50_000_000]
		pub fn add_key_server(origin, id: KeyServerId, network_address: KeyServerNetworkAddress) {
			key_server_set::<T>().add_key_server(origin, id, network_address)?;
		}

		/// Remove key server from the set.
		///
		/// Can only be called by owner.
		#[weight = 50_000_000]
		pub fn remove_key_server(origin, id: KeyServerId) {
			key_server_set::<T>().remove_key_server(origin, id)?;
		}

		/// Start migration.
		///
		/// Can only be called by one of key servers from UNION(current, new) set.
		/// Can only be called when migration is required.
		#[weight = 50_000_000]
		pub fn start_migration(origin, migration_id: MigrationIdT) {
			key_server_set::<T>().start_migration(origin, migration_id)?;
		}

		/// Confirm migration.
		///
		/// Can only be called by one of key servers from migration set.
		/// Can only be called when migration is active.
		#[weight = 50_000_000]
		pub fn confirm_migration(origin, migration_id: MigrationIdT) {
			key_server_set::<T>().confirm_migration(origin, migration_id)?;
		}

		/// Claim key ownership.
		///
		/// This is an example of how key access could be managed - we allow at most
		/// 1 key 'owner' at a time. By calling this method you're giving yourself access
		/// to private portion of key with given id.
		///
		/// **IMPORTANT**: it is a good idea to claim ownership **before** key generation.
		/// Otherwise anyone could claim (i.e. steal) your key.
		#[weight = 50_000_000]
		pub fn claim_key(origin, id: ServerKeyId) {
			ensure!(
				!KeyOwners::contains_key(&id),
				"Key is already claimed",
			);

			let origin = ensure_signed(origin)?;
			let origin = resolve_entity_id::<T>(&origin)?;
			KeyOwners::append(id, origin);
		}

		/// Transfer key ownership.
		///
		/// This is an example of how key access could be managed - we allow at most
		/// 1 key 'owner' at a time. By calling this method you're transferring access
		/// to private portion of key with given id from yourself to given account.
		#[weight = 50_000_000]
		pub fn transfer_key(origin, id: ServerKeyId, new_claimant: EntityId) {
			let origin = ensure_signed(origin)?;
			let origin = resolve_entity_id::<T>(&origin)?;
			ensure!(
				KeyOwners::get(&id).contains(&origin),
				"You're not owner of the key",
			);

			KeyOwners::insert(id, vec![new_claimant]);
		}

		/// Generate server key.
		///
		/// The caller should be able to pay ServerKeyGenerationFee.
		/// Generated server key will be published using ServerKeyGenerated event.
		/// If SecretStore will be unable to generate server key, then it will emit
		/// ServerKeyGenerationError event.
		#[weight = 50_000_000]
		pub fn generate_server_key(origin, id: ServerKeyId, threshold: u8) {
			ServerKeyGenerationService::<T>::generate(origin, id, threshold)?;
		}

		/// Called when generation is reported by key server.
		///
		/// Can only be called by key servers from the current set.
		#[weight = 50_000_000]
		pub fn server_key_generated(origin, id: ServerKeyId, server_key_public: sp_core::H512) {
			ServerKeyGenerationService::<T>::on_generated(origin, id, server_key_public)?;
		}

		/// Called when generation error is reported by key server.
		///
		/// Can only be called by key servers from the current set.
		#[weight = 50_000_000]
		pub fn server_key_generation_error(origin, id: ServerKeyId) {
			ServerKeyGenerationService::<T>::on_generation_error(origin, id)?;
		}

		/// Retrieve server key.
		///
		/// The caller should be able to pay ServerKeyRetrievalFee.
		/// Retrieved server key will be published using ServerKeyRetrieved event.
		/// If SecretStore will be unable to retrieve server key, then it will emit
		/// ServerKeyRetrievalError event.
		#[weight = 50_000_000]
		pub fn retrieve_server_key(origin, id: ServerKeyId) {
			ServerKeyRetrievalService::<T>::retrieve(origin, id)?;
		}

		/// Called when generation is reported by key server.
		///
		/// Can only be called by key servers from the current set.
		#[weight = 50_000_000]
		pub fn server_key_retrieved(origin, id: ServerKeyId, server_key_public: sp_core::H512, threshold: u8) {
			ServerKeyRetrievalService::<T>::on_retrieved(origin, id, server_key_public, threshold)?;
		}

		/// Called when generation error is reported by key server.
		///
		/// Can only be called by key servers from the current set.
		#[weight = 50_000_000]
		pub fn server_key_retrieval_error(origin, id: ServerKeyId) {
			ServerKeyRetrievalService::<T>::on_retrieval_error(origin, id)?;
		}

		/// Store document key.
		///
		/// The caller should be able to pay DocumentKeyStoreFee.
		/// Store confirmation will be published using DocumentKeyStored event.
		/// If SecretStore will be unable to store document key, then it will emit
		/// DocumentKeyStoreError event.
		#[weight = 50_000_000]
		pub fn store_document_key(origin, id: ServerKeyId, common_point: sp_core::H512, encrypted_point: sp_core::H512) {
			DocumentKeyStoreService::<T>::store(origin, id, common_point, encrypted_point)?;
		}

		/// Called when store is reported by key server.
		///
		/// Can only be called by key servers from the current set.
		#[weight = 50_000_000]
		pub fn document_key_stored(origin, id: ServerKeyId) {
			DocumentKeyStoreService::<T>::on_stored(origin, id)?;
		}

		/// Called when store error is reported by key server.
		///
		/// Can only be called by key servers from the current set.
		#[weight = 50_000_000]
		pub fn document_key_store_error(origin, id: ServerKeyId) {
			DocumentKeyStoreService::<T>::on_store_error(origin, id)?;
		}

		/// Retrieve document key shadow.
		///
		/// The caller should be able to pay DocumentKeyShadowRetrievalFee.
		/// Doument key shadow will be published using DocumentKeyCommonRetrieved and
		/// series of DocumentKeyPersonalRetrieved event (see DocumentKeyCommonRetrieved
		/// description for details). If SecretStore will be unable to retrieve document
		/// key shadow, then it will emit DocumentKeyShadowRetrievalError event.
		#[weight = 50_000_000]
		pub fn retrieve_document_key_shadow(origin, id: ServerKeyId, requester_public: sp_core::H512) {
			DocumentKeyShadowRetrievalService::<T>::retrieve(origin, id, requester_public)?;
		}

		/// Called when document key common part is reported by key server.
		///
		/// Can only be called by key servers from the current set.
		#[weight = 50_000_000]
		pub fn document_key_common_retrieved(
			origin,
			id: ServerKeyId,
			requester: EntityId,
			common_point: sp_core::H512,
			threshold: u8,
		) {
			DocumentKeyShadowRetrievalService::<T>::on_common_retrieved(
				origin,
				id,
				requester,
				common_point,
				threshold,
			)?;
		}

		/// Called when document key personal part is reported by key server.
		///
		/// Can only be called by key servers from the current set.
		#[weight = 50_000_000]
		pub fn document_key_personal_retrieved(
			origin,
			id: ServerKeyId,
			requester: EntityId,
			participants: KeyServersMask,
			decrypted_secret: sp_core::H512,
			shadow: Vec<u8>,
		) {
			DocumentKeyShadowRetrievalService::<T>::on_personal_retrieved(
				origin,
				id,
				requester,
				participants,
				decrypted_secret,
				shadow,
			)?;
		}

		/// Called when document key shadow retrieval error is reported by key server.
		///
		/// Can only be called by key servers from the current set.
		#[weight = 50_000_000]
		pub fn document_key_shadow_retrieval_error(origin, id: ServerKeyId, requester: EntityId) {
			DocumentKeyShadowRetrievalService::<T>::on_retrieval_error(origin, id, requester)?;
		}
	}
}

decl_event!(
	/// There are two categories of events: (KeyServer) events are primarily used by
	/// key servers to receive notifications of what is happening in the module.
	/// (Client) events are for SecretStore clients - these are responses to previously
	/// submitted requests.
	pub enum Event {
		/// (KeyServer) Key server set: key server added to the new set.
		KeyServerAdded(KeyServerId),
		/// (KeyServer) Key server set: key server added to the new set.
		KeyServerRemoved(KeyServerId),
		/// (KeyServer) Key server set: key server address has been updated.
		KeyServerUpdated(KeyServerId),
		/// (KeyServer) Key server set: migration has started.
		MigrationStarted,
		/// (KeyServer) Key server set: migration has completed.
		MigrationCompleted,

		/// (KeyServer) Server key generation: new key generation requested.
		ServerKeyGenerationRequested(ServerKeyId, EntityId, u8),
		/// (Client) Server key generation: key is generated.
		ServerKeyGenerated(ServerKeyId, sp_core::H512),
		/// (Client) Server key generation: key generation has failed.
		ServerKeyGenerationError(ServerKeyId),

		/// (KeyServer) Server key retrieval: new key retrieval requested.
		ServerKeyRetrievalRequested(ServerKeyId),
		/// (Client) Server key retrieval: key is retrieved.
		ServerKeyRetrieved(ServerKeyId, sp_core::H512),
		/// (Client) Server key retrieval: key retrieval has failed.
		ServerKeyRetrievalError(ServerKeyId),

		/// (KeyServer) Document key store: new document key store requested.
		DocumentKeyStoreRequested(ServerKeyId, EntityId, sp_core::H512, sp_core::H512),
		/// (Client) Document key store: key is stored.
		DocumentKeyStored(ServerKeyId),
		/// (Client) Document key store: key store has failed.
		DocumentKeyStoreError(ServerKeyId),

		/// (KeyServer) Document key shadow retrieval: new retrieval requested.
		DocumentKeyShadowRetrievalRequested(ServerKeyId, EntityId),
		/// (Client) Document key shadow retrieval: commmon portion of document key
		/// has been retrieved. Once client sees this event, it should start waiting
		/// for `threshold + 1` DocumentKeyPersonalRetrieved events with the same
		/// 'decrypted_secret'. Once they are received, the client may decrypt document
		/// key using its own secret key.
		DocumentKeyCommonRetrieved(ServerKeyId, EntityId, sp_core::H512, u8),
		/// (KeyServer) Document key shadow retrieval: common portion has been retrieved
		/// and we now need to retrieve personal portion.
		DocumentKeyPersonalRetrievalRequested(ServerKeyId, sp_core::H512),
		/// (Client) Document key shadow retrieval: retrieval has failed.
		DocumentKeyShadowRetrievalError(ServerKeyId, EntityId),
		/// (Client) Document key shadow retrieval: personal portion has been reported
		/// by one of key servers.
		DocumentKeyPersonalRetrieved(ServerKeyId, EntityId, sp_core::H512, Vec<u8>),
	}
);

decl_storage! {
	trait Store for Module<T: Config> as SecretStore {
		/// Owner can perform some actions that are unavailable to regular users.
		/// https://github.com/paritytech/secret-store/issues/30
		pub Owner get(fn owner) config(): T::AccountId;

		/// Claimed entity ID by account ID.
		ClaimedId get(fn claimed_address): map hasher(blake2_128_concat) T::AccountId => Option<EntityId>;
		/// Claimed account ID by entity ID.
		ClaimedBy get(fn claimed_by): map hasher(blake2_128_concat) EntityId => Option<T::AccountId>;

		/// When it is false, all changes to key server set are applied to both current and new sets,
		/// so no migration is required.
		/// When it is true, all changes to key server set are applied to new set only, so migration
		/// is required.
		IsInitialized: bool;
		/// Number of block where last changes have been applied to **current** key server set.
		CurrentSetChangeBlock: <T as frame_system::Config>::BlockNumber;

		/// Current key servers set. This is the set of key servers that are running key server
		/// operations at this moment.
		CurrentKeyServers: map hasher(blake2_128_concat) KeyServerId => Option<KeyServer>;
		/// Migration key servers set. That is the set of key servers we are currently migrating
		/// to from current set.
		MigrationKeyServers: map hasher(blake2_128_concat) KeyServerId => Option<KeyServer>;
		/// New key servers set. That is the set of key servers we will be migrating to in
		/// the future.
		NewKeyServers: map hasher(blake2_128_concat) KeyServerId => Option<KeyServer>;
		/// ID and the 'master' server of current migration process. ID is used to distinguish
		/// confirmations of different migrations. Master is the key server which starts
		/// auto-migration session.
		MigrationId: Option<(MigrationIdT, KeyServerId)>;
		/// Confirmations of current migration.
		MigrationConfirmations: map hasher(blake2_128_concat) KeyServerId => ();

		/// Key owners. All operations that require access to the private portion
		/// of server key (StoreDocumentKey, RetrieveDocumentKey, RetrieveDocumentKeyShadow, ...)
		/// are only available for entities that 'own' this key.
		///
		/// In current (example) implementation we have at most 1 key owner.
		KeyOwners: map hasher(blake2_128_concat) ServerKeyId => Vec<EntityId>;

		/// Current server key generation fee. Splitted among all key servers from current set.
		ServerKeyGenerationFee get(fn server_key_generation_fee) config(): BalanceOf<T>;
		/// IDs of server keys that we're generating/going to generate. Every key has its
		/// entry in ServerKeyGenerationRequests.
		ServerKeyGenerationRequestsKeys: Vec<ServerKeyId>;
		/// All active server key generation requests.
		ServerKeyGenerationRequests: map hasher(blake2_128_concat) ServerKeyId
			=> Option<ServerKeyGenerationRequest<<T as frame_system::Config>::BlockNumber>>;
		/// Reported server keys.
		ServerKeyGenerationResponses: double_map
			hasher(blake2_128_concat) ServerKeyId,
			hasher(blake2_128_concat) sp_core::H512 => u8;

		/// Current server key retrieval fee. Splitted among all key servers from current set.
		pub ServerKeyRetrievalFee get(fn server_key_retrieval_fee) config(): BalanceOf<T>;
		/// IDs of server keys that we're retrieving/going to retrieve. Every key has its
		/// entry in ServerKeyRetrievalRequests.
		ServerKeyRetrievalRequestsKeys: Vec<ServerKeyId>;
		/// All active server key retrieval requests.
		ServerKeyRetrievalRequests: map
			hasher(blake2_128_concat) ServerKeyId
			=> Option<ServerKeyRetrievalRequest<<T as frame_system::Config>::BlockNumber>>;
		/// Reported server keys.
		ServerKeyRetrievalResponses: double_map
			hasher(blake2_128_concat) ServerKeyId,
			hasher(blake2_128_concat) sp_core::H512 => u8;
		/// Reported server keys thresholds.
		ServerKeyRetrievalThresholdResponses: double_map
			hasher(blake2_128_concat) ServerKeyId,
			hasher(twox_64_concat) u8 => u8;

		/// Current document key store fee. Splitted among all key servers from current set.
		pub DocumentKeyStoreFee get(fn document_key_store_fee) config(): BalanceOf<T>;
		/// IDs of server keys that we're binding with document keys. Every key has its
		/// entry in DocumentKeyStoreRequests.
		DocumentKeyStoreRequestsKeys: Vec<ServerKeyId>;
		/// All active document key store requests.
		DocumentKeyStoreRequests: map hasher(blake2_128_concat) ServerKeyId
			=> Option<DocumentKeyStoreRequest<<T as frame_system::Config>::BlockNumber>>;
		/// Document key store confirmations.
		DocumentKeyStoreResponses: double_map
			hasher(blake2_128_concat) ServerKeyId,
			hasher(twox_64_concat) () => u8;

		/// Current document key shadow retrieval fee. Splitted among all key servers from current set.
		pub DocumentKeyShadowRetrievalFee get(fn document_key_shadow_retrieval_fee) config(): BalanceOf<T>;
		/// IDs of (server key, requester) that we're retrieving/goint to retrieve associated document
		/// key shadows from/for. Every key has its entry in DocumentKeyShadowRetrievalRequests.
		pub DocumentKeyShadowRetrievalRequestsKeys: Vec<(ServerKeyId, EntityId)>;
		/// All active document key shadow retrieval requests
		pub DocumentKeyShadowRetrievalRequests: map hasher(blake2_128_concat) (ServerKeyId, EntityId)
			=> Option<DocumentKeyShadowRetrievalRequest<<T as frame_system::Config>::BlockNumber>>;
		/// Reported common portions of document keys.
		DocumentKeyShadowRetrievalCommonResponses: double_map
			hasher(blake2_128_concat) (ServerKeyId, EntityId),
			hasher(blake2_128_concat) (sp_core::H512, u8) => u8;
		/// Reported personal portions of document keys.
		DocumentKeyShadowRetrievalPersonalResponses: double_map
			hasher(blake2_128_concat) (ServerKeyId, EntityId),
			hasher(blake2_128_concat) (KeyServersMask, sp_core::H512) => DocumentKeyShadowRetrievalPersonalData;
	}
	add_extra_genesis {
		config(is_initialization_completed): bool;
		config(key_servers): Vec<(KeyServerId, KeyServerNetworkAddress)>;
		config(claims): Vec<(T::AccountId, EntityId)>;
		build(|config| {
			key_server_set::<T>()
				.fill(
					&config.key_servers,
					config.is_initialization_completed,
				).expect("invalid key servers set in configuration");

			let mut claimed_by_accounts = std::collections::BTreeSet::new();
			let mut claimed_entities = std::collections::BTreeSet::new();
			for (account_id, entity_id) in &config.claims {
				if !claimed_by_accounts.insert(account_id.clone()) {
					panic!("Account has already claimed EntityId");
				}
				if !claimed_entities.insert(*entity_id) {
					panic!("EntityId already claimed");
				}

				ClaimedId::<T>::insert(account_id.clone(), *entity_id);
				ClaimedBy::<T>::insert(*entity_id, account_id.clone());
			}
		})
	}
}

impl<T: Config> Module<T> {
	/// Get snapshot of key servers set state.
	pub fn key_server_set_snapshot(key_server: KeyServerId) -> KeyServerSetSnapshot {
		key_server_set::<T>().snapshot(key_server)
	}

	/// Get current key servers with indices.
	pub fn key_server_set_with_indices() -> Vec<(KeyServerId, u8)> {
		key_server_set::<T>().current_set_with_indices()
	}

	/// Check if requester has access to private portion of server key.
	pub fn check_key_access(key: ServerKeyId, requester: EntityId) -> bool {
		KeyOwners::get(key).contains(&requester)
	}

	/// Get pending server key generation tasks.
	pub fn server_key_generation_tasks(begin: u32, end: u32) -> Vec<primitives::service::ServiceTask> {
		ServerKeyGenerationRequestsKeys::get()
			.into_iter()
			.skip(begin as usize)
			.take(end.saturating_sub(begin) as usize)
			.map(|key_id| {
				let request = ServerKeyGenerationRequests::<T>::get(&key_id)
					.expect("every key from ServerKeyGenerationRequestsKeys has corresponding
						entry in ServerKeyGenerationRequests; qed");
				primitives::service::ServiceTask::GenerateServerKey(
					key_id,
					request.author,
					request.threshold,
				)
			})
			.collect()
	}

	/// Returns true if given key server should submit its response to given server key
	/// generation request.
	pub fn is_server_key_generation_response_required(key_server: KeyServerId, key_id: ServerKeyId) -> bool {
		ServerKeyGenerationService::<T>::is_response_required(key_server, key_id)
	}

	/// Get pending server key retrieval tasks.
	pub fn server_key_retrieval_tasks(begin: u32, end: u32) -> Vec<primitives::service::ServiceTask> {
		ServerKeyRetrievalRequestsKeys::get()
			.into_iter()
			.skip(begin as usize)
			.take(end.saturating_sub(begin) as usize)
			.map(|key_id| {
				primitives::service::ServiceTask::RetrieveServerKey(
					key_id,
				)
			})
			.collect()
	}

	/// Returns true if given key server should submit its response to given server key
	/// retrieval request.
	pub fn is_server_key_retrieval_response_required(key_server: KeyServerId, key_id: ServerKeyId) -> bool {
		ServerKeyRetrievalService::<T>::is_response_required(key_server, key_id)
	}

	/// Get pending document key store tasks.
	pub fn document_key_store_tasks(begin: u32, end: u32) -> Vec<primitives::service::ServiceTask> {
		DocumentKeyStoreRequestsKeys::get()
			.into_iter()
			.skip(begin as usize)
			.take(end.saturating_sub(begin) as usize)
			.map(|key_id| {
				let request = DocumentKeyStoreRequests::<T>::get(&key_id)
					.expect("every key from DocumentKeyStoreRequestsKeys has corresponding
						entry in DocumentKeyStoreRequests; qed");
				primitives::service::ServiceTask::StoreDocumentKey(
					key_id,
					request.author,
					request.common_point,
					request.encrypted_point,
				)
			})
			.collect()
	}

	/// Returns true if given key server should submit its response to given document key
	/// store request.
	pub fn is_document_key_store_response_required(key_server: KeyServerId, key_id: ServerKeyId) -> bool {
		DocumentKeyStoreService::<T>::is_response_required(key_server, key_id)
	}

	/// Get pending document key shadow retrieval tasks.
	pub fn document_key_shadow_retrieval_tasks(begin: u32, end: u32) -> Vec<primitives::service::ServiceTask> {
		DocumentKeyShadowRetrievalRequestsKeys::get()
			.into_iter()
			.skip(begin as usize)
			.take(end.saturating_sub(begin) as usize)
			.map(|(key_id, requester)| {
				let request = DocumentKeyShadowRetrievalRequests::<T>::get(&(key_id, requester))
					.expect("every key from DocumentKeyStoreRequestsKeys has corresponding
						entry in DocumentKeyStoreRequests; qed");
				match request.threshold.is_some() {
					false => primitives::service::ServiceTask::RetrieveShadowDocumentKeyCommon(
						key_id,
						requester,
					),
					true => primitives::service::ServiceTask::RetrieveShadowDocumentKeyPersonal(
						key_id,
						request.requester_public,
					),
				}
			})
			.collect()
	}

	/// Returns true if given key server should submit its response to given document key
	/// store request.
	pub fn is_document_key_shadow_retrieval_response_required(
		key_server: KeyServerId,
		key_id: ServerKeyId,
		requester: EntityId,
	) -> bool {
		DocumentKeyShadowRetrievalService::<T>::is_response_required(key_server, key_id, requester)
	}
}

/// Type alias of used KeyServerSet implementation.
pub(crate) type KeyServerSet<T> = key_server_set::KeyServerSetWithMigration<
	blockchain_storage::RuntimeStorage<T>,
	entity_id_storage::RuntimeStorage<T>,
	key_server_set_storage::RuntimeStorageWithMigration<T>,
>;

/// Create key server set.
pub(crate) fn key_server_set<T: Config>() -> KeyServerSet<T> {
	key_server_set::KeyServerSetWithMigration::with_storage(
		Default::default(),
		Default::default(),
		Default::default(),
	)
}

/// Returns entity ID associated with given account. Fails if there's no association.
pub fn resolve_entity_id<T: Config>(origin: &T::AccountId) -> Result<EntityId, &'static str> {
	let origin_id = ClaimedId::<T>::get(origin);
	match origin_id {
		Some(id) => Ok(id),
		None => Err("No associated id for this account"),
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::mock::*;

	#[test]
	fn should_allow_change_owner_by_owner() {
		basic_initialization().execute_with(|| {
			Module::<TestRuntime>::change_owner(
				Origin::signed(OWNER),
				REQUESTER1,
			).unwrap();

			assert_eq!(
				Owner::<TestRuntime>::get(),
				REQUESTER1,
			);
		});
	}

	#[test]
	fn should_forbid_change_owner_by_non_owner() {
		basic_initialization().execute_with(|| {
			Module::<TestRuntime>::change_owner(
				Origin::signed(REQUESTER1),
				REQUESTER1,
			).unwrap_err();
		});
	}

	#[test]
	fn should_allow_claim_id() {
		basic_initialization().execute_with(|| {
			Module::<TestRuntime>::claim_id(
				Origin::signed(500),
				[255u8; 20].into(),
			).unwrap();
		});
	}

	#[test]
	fn should_forbid_claiming_claimed_id() {
		basic_initialization().execute_with(|| {
			Module::<TestRuntime>::claim_id(
				Origin::signed(500),
				KEY_SERVER1_ID.into(),
			).unwrap_err();
		});
	}

	#[test]
	fn should_forbid_claiming_second_id() {
		basic_initialization().execute_with(|| {
			Module::<TestRuntime>::claim_id(
				Origin::signed(REQUESTER1),
				[255u8; 20].into(),
			).unwrap_err();
		});
	}

	#[test]
	fn should_allow_claim_key() {
		basic_initialization().execute_with(|| {
			Module::<TestRuntime>::claim_key(
				Origin::signed(REQUESTER1),
				[1u8; 32].into(),
			).unwrap();

			assert_eq!(
				KeyOwners::get(ServerKeyId::from([1u8; 32])),
				vec![[REQUESTER1 as u8; 20].into()],
			);
		});
	}

	#[test]
	fn should_forbid_claim_key_to_unknown_entity() {
		basic_initialization().execute_with(|| {
			Module::<TestRuntime>::claim_key(
				Origin::signed(500),
				[1u8; 32].into(),
			).unwrap_err();
		});
	}

	#[test]
	fn should_forbid_claim_existing_key() {
		basic_initialization().execute_with(|| {
			Module::<TestRuntime>::claim_key(
				Origin::signed(REQUESTER1),
				[1u8; 32].into(),
			).unwrap();

			Module::<TestRuntime>::claim_key(
				Origin::signed(REQUESTER2),
				[1u8; 32].into(),
			).unwrap_err();
		});
	}

	#[test]
	fn should_allow_transfer_key_ownership() {
		basic_initialization().execute_with(|| {
			Module::<TestRuntime>::claim_key(
				Origin::signed(REQUESTER1),
				[1u8; 32].into(),
			).unwrap();

			Module::<TestRuntime>::transfer_key(
				Origin::signed(REQUESTER1),
				[1u8; 32].into(),
				[REQUESTER2 as u8; 20].into(),
			).unwrap();

			assert_eq!(
				KeyOwners::get(ServerKeyId::from([1u8; 32])),
				vec![[REQUESTER2 as u8; 20].into()],
			);
		});
	}

	#[test]
	fn should_forbid_transfer_key_ownership_to_non_owner() {
		basic_initialization().execute_with(|| {
			Module::<TestRuntime>::claim_key(
				Origin::signed(REQUESTER1),
				[1u8; 32].into(),
			).unwrap();

			Module::<TestRuntime>::transfer_key(
				Origin::signed(REQUESTER2),
				[1u8; 32].into(),
				REAL_REQUESTER1_ADDRESS.into(),
			).unwrap_err();
		});
	}
}
