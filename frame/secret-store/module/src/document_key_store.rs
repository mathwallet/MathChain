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

//! Contains actual implementation of all public/private module methods
//! for storing document keys.

use codec::{Encode, Decode};
use frame_support::{StorageValue, StorageMap, StorageDoubleMap, ensure};
use primitives::{EntityId, ServerKeyId, KeyServerId};
use frame_system::ensure_signed;
use crate::service::{Responses, ResponseSupport, SecretStoreService};
use super::{
	Config, Module, Event,
	DocumentKeyStoreFee,
	DocumentKeyStoreRequests, DocumentKeyStoreRequestsKeys,
	DocumentKeyStoreResponses,
	resolve_entity_id,
};

/// Maximal number of active requests in the queue.
const MAX_REQUESTS: u64 = 8;

/// Structure that describes document key store request with responses meta.
#[derive(Decode, Encode)]
pub struct DocumentKeyStoreRequest<Number> {
	/// The author of this request. It must be the same author as in the
	/// server key generation request.
	pub author: EntityId,
	/// Common point of the document key.
	pub common_point: sp_core::H512,
	/// Encrypted point of the document key.
	pub encrypted_point: sp_core::H512,
	/// Responses metadata.
	pub responses: Responses<Number>,
}

/// Implementation of document key storing service.
pub struct DocumentKeyStoreService<T>(sp_std::marker::PhantomData<T>);

impl<T: Config> DocumentKeyStoreService<T> {
	/// Request storing of new document key.
	pub fn store(
		origin: T::Origin,
		id: ServerKeyId,
		common_point: sp_core::H512,
		encrypted_point: sp_core::H512,
	) -> Result<(), &'static str> {
		// limit number of requests in the queue
		ensure!(
			(DocumentKeyStoreRequestsKeys::decode_len().unwrap_or(0) as u64) < MAX_REQUESTS,
			"Too many active requests. Try later",
		);

		// check if there are no pending request for the same key
		ensure!(
			!DocumentKeyStoreRequests::<T>::contains_key(id),
			"The same request is already queued",
		);

		// collect service fee
		let origin = ensure_signed(origin)?;
		let fee = DocumentKeyStoreFee::<T>::get();
		SecretStoreService::<T>::collect_service_fee(&origin, fee)?;

		// insert request to the queue
		let author = resolve_entity_id::<T>(&origin)?;
		let request = DocumentKeyStoreRequest {
			author: author.clone(),
			common_point: common_point.clone(),
			encrypted_point: encrypted_point.clone(),
			responses: SecretStoreService::<T>::new_responses(),
		};
		DocumentKeyStoreRequests::<T>::insert(id, request);
		DocumentKeyStoreRequestsKeys::append(&id);

		// emit event
		Module::<T>::deposit_event(Event::DocumentKeyStoreRequested(id, author, common_point, encrypted_point));

		Ok(())
	}

	/// Called when storing is reported by key server.
	pub fn on_stored(
		origin: T::Origin,
		id: ServerKeyId,
	) -> Result<(), &'static str> {
		// check if this request is active (the tx could arrive when request is already inactive)
		let mut request = match DocumentKeyStoreRequests::<T>::get(id) {
			Some(request) => request,
			None => return Ok(()),
		};

		// insert response (we're waiting for responses from all authorities here)
		let key_servers_count = SecretStoreService::<T>::key_servers_count()?;
		let key_server_index = SecretStoreService::<T>::key_server_index_from_origin(origin)?;
		let response_support = SecretStoreService::<T>::insert_response::<_, _, DocumentKeyStoreResponses>(
			key_server_index,
			key_servers_count - 1,
			&mut request.responses,
			&id,
			&(),
		)?;

		// check if response is confirmed
		match response_support {
			ResponseSupport::Unconfirmed => {
				DocumentKeyStoreRequests::<T>::insert(id, request);
			},
			ResponseSupport::Confirmed => {
				// we do not need this request anymore
				delete_request::<T>(&id);

				// emit event
				Module::<T>::deposit_event(Event::DocumentKeyStored(id));
			},
			ResponseSupport::Impossible => unreachable!("we're receiving the same response from all servers; qed"),
		}

		Ok(())
	}

	/// Called when error occurs during document key storing.
	pub fn on_store_error(
		origin: T::Origin,
		id: ServerKeyId,
	) -> Result<(), &'static str> {
		// check that it is reported by the key server
		let _ = SecretStoreService::<T>::key_server_index_from_origin(origin)?;

		// check if this request is active (the tx could arrive when request is already inactive)
		let _request = match DocumentKeyStoreRequests::<T>::get(id) {
			Some(request) => request,
			None => return Ok(()),
		};

		// any error in key generation is fatal, because we need all key servers to participate in generation
		// => delete request and fire event
		delete_request::<T>(&id);

		Module::<T>::deposit_event(Event::DocumentKeyStoreError(id));
		Ok(())
	}

	/// Returns true if response from given key server is required to complete request.
	pub fn is_response_required(
		key_server: KeyServerId,
		id: ServerKeyId,
	) -> bool {
		DocumentKeyStoreRequests::<T>::get(&id)
			.map(|request| SecretStoreService::<T>::is_response_required(
				key_server,
				&request.responses,
			))
			.unwrap_or(false)
	}
}

/// Deletes request and all associated data.
fn delete_request<T: Config>(request: &ServerKeyId) {
	DocumentKeyStoreResponses::remove_prefix(request);
	DocumentKeyStoreRequests::<T>::remove(request);
	DocumentKeyStoreRequestsKeys::mutate(|list| {
		let index = list.iter().position(|lrequest| lrequest == request);
		if let Some(index) = index {
			list.swap_remove(index);
		}
	});
}

#[cfg(test)]
mod tests {
	use crate::mock::*;
	use super::*;

	fn ensure_clean_storage(key: ServerKeyId) {
		assert_eq!(DocumentKeyStoreRequestsKeys::get(), vec![]);
		assert!(!DocumentKeyStoreRequests::<TestRuntime>::contains_key(key));
		assert_eq!(
			DocumentKeyStoreResponses::iter_prefix(key).collect::<Vec<_>>(),
			vec![],
		);
	}

	#[test]
	fn should_accept_document_key_store_request() {
		default_initialization().execute_with(|| {
			// ask to store document key
			DocumentKeyStoreService::<TestRuntime>::store(
				Origin::signed(REQUESTER1),
				[32; 32].into(),
				[21; 64].into(),
				[42; 64].into(),
			).unwrap();

			// check that event has been emitted
			assert!(
				frame_system::Module::<TestRuntime>::events().into_iter()
					.find(|e| e.event == Event::DocumentKeyStoreRequested(
						[32; 32].into(),
						[REQUESTER1 as u8; 20].into(),
						[21; 64].into(),
						[42; 64].into(),
					).into())
					.is_some(),
			);
		});
	}

	#[test]
	fn should_reject_document_key_store_request_when_fee_is_not_paid() {
		default_initialization().execute_with(|| {
			// REQUESTER2 has no enough funds
			DocumentKeyStoreService::<TestRuntime>::store(
				Origin::signed(REQUESTER2),
				[32; 32].into(),
				[21; 64].into(),
				[42; 64].into(),
			).unwrap_err();

			ensure_clean_storage([32; 32].into());
		});
	}

	#[test]
	fn should_reject_document_key_store_request_when_limit_reached() {
		default_initialization().execute_with(|| {
			// make MAX_REQUESTS requests
			for i in 0..MAX_REQUESTS {
				DocumentKeyStoreService::<TestRuntime>::store(
					Origin::signed(REQUESTER1),
					[i as u8; 32].into(),
					[21; 64].into(),
					[42; 64].into(),
				).unwrap();
			}

			// and now try to push new request so that there will be more than a limit requests
			DocumentKeyStoreService::<TestRuntime>::store(
				Origin::signed(REQUESTER1),
				[MAX_REQUESTS as u8; 32].into(),
				[21; 64].into(),
				[42; 64].into(),
			).unwrap_err();
		});
	}

	#[test]
	fn should_reject_duplicated_document_key_store_request() {
		default_initialization().execute_with(|| {
			// ask to store document key
			DocumentKeyStoreService::<TestRuntime>::store(
				Origin::signed(REQUESTER1),
				[32; 32].into(),
				[21; 64].into(),
				[42; 64].into(),
			).unwrap();

			// ask to store document key
			DocumentKeyStoreService::<TestRuntime>::store(
				Origin::signed(REQUESTER1),
				[32; 32].into(),
				[21; 64].into(),
				[42; 64].into(),
			).unwrap_err();
		});
	}

	#[test]
	fn should_publish_document_key_store_confirmation() {
		default_initialization().execute_with(|| {
			// ask to store document key
			DocumentKeyStoreService::<TestRuntime>::store(
				Origin::signed(REQUESTER1),
				[32; 32].into(),
				[21; 64].into(),
				[42; 64].into(),
			).unwrap();
			let events_count = frame_system::Module::<TestRuntime>::events().len();

			// response from key server 1 is received
			DocumentKeyStoreService::<TestRuntime>::on_stored(
				Origin::signed(KEY_SERVER0),
				[32; 32].into(),
			).unwrap();
			// => no new events generated
			assert_eq!(
				events_count,
				frame_system::Module::<TestRuntime>::events().len(),
			);

			// response from key server 2 is received
			DocumentKeyStoreService::<TestRuntime>::on_stored(
				Origin::signed(KEY_SERVER1),
				[32; 32].into(),
			).unwrap();
			// => new event is generated
			assert_eq!(
				events_count + 1,
				frame_system::Module::<TestRuntime>::events().len(),
			);
			assert!(
				frame_system::Module::<TestRuntime>::events().into_iter()
					.find(|e| e.event == Event::DocumentKeyStored([32; 32].into()).into())
					.is_some(),
			);

			// and then another response from key server 2 is received (and ignored without error)
			DocumentKeyStoreService::<TestRuntime>::on_stored(
				Origin::signed(KEY_SERVER1),
				[32; 32].into(),
			).unwrap();

			ensure_clean_storage([32; 32].into());
		});
	}

	#[test]
	fn should_not_accept_store_confirmation_from_non_key_server() {
		default_initialization().execute_with(|| {
			// ask to store document key
			DocumentKeyStoreService::<TestRuntime>::store(
				Origin::signed(REQUESTER1),
				[32; 32].into(),
				[21; 64].into(),
				[42; 64].into(),
			).unwrap();

			// response from key server 3 is received
			DocumentKeyStoreService::<TestRuntime>::on_stored(
				Origin::signed(KEY_SERVER3),
				[32; 32].into(),
			).unwrap_err();
		});
	}

	#[test]
	fn should_not_publish_generated_key_when_receiving_responses_from_same_key_server() {
		default_initialization().execute_with(|| {
			// ask to store document key
			DocumentKeyStoreService::<TestRuntime>::store(
				Origin::signed(REQUESTER1),
				[32; 32].into(),
				[21; 64].into(),
				[42; 64].into(),
			).unwrap();
			let events_count = frame_system::Module::<TestRuntime>::events().len();

			// response from key server 1 is received
			DocumentKeyStoreService::<TestRuntime>::on_stored(
				Origin::signed(KEY_SERVER1),
				[32; 32].into(),
			).unwrap();

			// another response from key server 1 is received
			DocumentKeyStoreService::<TestRuntime>::on_stored(
				Origin::signed(KEY_SERVER1),
				[32; 32].into(),
			).unwrap();

			// check that key is not published
			assert_eq!(
				events_count,
				frame_system::Module::<TestRuntime>::events().len(),
			);
		});
	}

	#[test]
	fn should_raise_store_error_when_at_least_one_server_has_responded_with_error() {
		default_initialization().execute_with(|| {
			// ask to store document key
			DocumentKeyStoreService::<TestRuntime>::store(
				Origin::signed(REQUESTER1),
				[32; 32].into(),
				[21; 64].into(),
				[42; 64].into(),
			).unwrap();
			let events_count = frame_system::Module::<TestRuntime>::events().len();

			// error from key server 1 is received
			DocumentKeyStoreService::<TestRuntime>::on_store_error(
				Origin::signed(KEY_SERVER0),
				[32; 32].into(),
			).unwrap();

			// check that store error is published
			assert_eq!(
				events_count + 1,
				frame_system::Module::<TestRuntime>::events().len(),
			);
			assert!(
				frame_system::Module::<TestRuntime>::events().into_iter()
					.find(|e| e.event == Event::DocumentKeyStoreError([32; 32].into()).into())
					.is_some(),
			);

			ensure_clean_storage([32; 32].into());
		});
	}

	#[test]
	fn should_fail_if_store_error_is_reported_by_non_key_server() {
		default_initialization().execute_with(|| {
			// ask to store document key
			DocumentKeyStoreService::<TestRuntime>::store(
				Origin::signed(REQUESTER1),
				[32; 32].into(),
				[21; 64].into(),
				[42; 64].into(),
			).unwrap();

			// error from REQUESTER1 is received
			DocumentKeyStoreService::<TestRuntime>::on_store_error(
				Origin::signed(REQUESTER1),
				[32; 32].into(),
			).unwrap_err();
		});
	}

	#[test]
	fn should_not_raise_store_error_if_no_active_request() {
		default_initialization().execute_with(|| {
			// error from key server 1 is received
			DocumentKeyStoreService::<TestRuntime>::on_store_error(
				Origin::signed(KEY_SERVER0),
				[32; 32].into(),
			).unwrap();

			assert!(
				!frame_system::Module::<TestRuntime>::events().iter()
					.any(|event| match event.event {
						TestEvent::secret_store(_) => true,
						_ => false,
					}),
			);
		});
	}

	#[test]
	fn should_return_if_store_response_is_required() {
		default_initialization().execute_with(|| {
			// ask to store document key
			DocumentKeyStoreService::<TestRuntime>::store(
				Origin::signed(REQUESTER1),
				[32; 32].into(),
				[21; 64].into(),
				[42; 64].into(),
			).unwrap();

			// response from all key servers is required
			assert!(DocumentKeyStoreService::<TestRuntime>::is_response_required(
				KEY_SERVER0_ID.into(),
				[32; 32].into(),
			));
			assert!(DocumentKeyStoreService::<TestRuntime>::is_response_required(
				KEY_SERVER1_ID.into(),
				[32; 32].into(),
			));

			// response from key server 1 is received
			DocumentKeyStoreService::<TestRuntime>::on_stored(
				Origin::signed(KEY_SERVER0),
				[32; 32].into(),
			).unwrap();

			// response from key server 2 is required
			assert!(!DocumentKeyStoreService::<TestRuntime>::is_response_required(
				KEY_SERVER0_ID.into(),
				[32; 32].into(),
			));
			assert!(DocumentKeyStoreService::<TestRuntime>::is_response_required(
				KEY_SERVER1_ID.into(),
				[32; 32].into(),
			));

			// response from key server 2 is received
			DocumentKeyStoreService::<TestRuntime>::on_stored(
				Origin::signed(KEY_SERVER1),
				[32; 32].into(),
			).unwrap();

			// no responses are required
			assert!(!DocumentKeyStoreService::<TestRuntime>::is_response_required(
				KEY_SERVER0_ID.into(),
				[32; 32].into(),
			));
			assert!(!DocumentKeyStoreService::<TestRuntime>::is_response_required(
				KEY_SERVER1_ID.into(),
				[32; 32].into(),
			));
		});
	}

	#[test]
	fn should_reset_existing_responses_when_key_server_set_changes() {
		default_initialization().execute_with(|| {
			// ask to store document key
			DocumentKeyStoreService::<TestRuntime>::store(
				Origin::signed(REQUESTER1),
				[32; 32].into(),
				[21; 64].into(),
				[42; 64].into(),
			).unwrap();

			// response from key server 1 is received
			DocumentKeyStoreService::<TestRuntime>::on_stored(
				Origin::signed(KEY_SERVER0),
				[32; 32].into(),
			).unwrap();

			// response from key server 1 is not required anymore
			assert!(!DocumentKeyStoreService::<TestRuntime>::is_response_required(
				KEY_SERVER0_ID.into(),
				[32; 32].into(),
			));

			// let's simulate migration
			crate::CurrentSetChangeBlock::<TestRuntime>::put(100);

			// response from key server 2 is received
			DocumentKeyStoreService::<TestRuntime>::on_stored(
				Origin::signed(KEY_SERVER1),
				[32; 32].into(),
			).unwrap();

			// response from key server 1 is required again
			assert!(DocumentKeyStoreService::<TestRuntime>::is_response_required(
				KEY_SERVER0_ID.into(),
				[32; 32].into(),
			));
			assert!(!DocumentKeyStoreService::<TestRuntime>::is_response_required(
				KEY_SERVER1_ID.into(),
				[32; 32].into(),
			));
		});
	}
}
