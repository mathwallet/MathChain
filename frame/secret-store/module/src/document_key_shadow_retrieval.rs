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
//! for retrieving document keys shadows.

use codec::{Encode, Decode};
use frame_support::{StorageValue, StorageMap, StorageDoubleMap, ensure};
use primitives::{EntityId, ServerKeyId, KeyServerId, KeyServersMask};
use sp_std::vec::Vec;
use frame_system::ensure_signed;
use crate::service::{Responses, ResponseSupport, SecretStoreService};
use super::{
	Config, Module, Event,
	DocumentKeyShadowRetrievalFee,
	DocumentKeyShadowRetrievalRequestsKeys, DocumentKeyShadowRetrievalRequests,
	DocumentKeyShadowRetrievalCommonResponses, DocumentKeyShadowRetrievalPersonalResponses,
	resolve_entity_id,
};

/// Maximal number of active requests in the queue.
const MAX_REQUESTS: u64 = 4;

/// Structure that describes document key shadow retrieval request with responses meta.
#[derive(Decode, Encode)]
pub struct DocumentKeyShadowRetrievalRequest<Number> {
	/// The author of this request. It must be the same author as in the
	/// server key generation request.
	pub requester: EntityId,
	/// The public key of author of this request. This must be the public key coresponding
	/// to the claimed author id. Otherwise, request will fail.
	pub requester_public: sp_core::H512,
	/// Common data retrieval responses.
	pub common_responses: Responses<Number>,
	/// Key threshold that key servers have agreed upon in common phase. If it is None,
	/// then common retrieval phase is in-progress.
	pub threshold: Option<u8>,
	/// Personal data: retrieval errors mask.
	pub personal_retrieval_errors_mask: KeyServersMask,
	/// Personal data: retrieval errors count.
	pub personal_retrieval_errors_count: u8,
}

/// Response from single key server from single decryption session.
#[derive(Default, Decode, Encode)]
#[cfg_attr(test, derive(Debug, PartialEq))]
pub struct DocumentKeyShadowRetrievalPersonalData {
	/// Participated key servers mask.
	pub participants: KeyServersMask,
	/// Mask of servers that have reported result of the session.
	pub reported: KeyServersMask,
	/// Number of servers that have reported result of the session.
	pub reported_count: u8,
}

/// Implementation of document key shadow retrieval service.
pub struct DocumentKeyShadowRetrievalService<T>(sp_std::marker::PhantomData<T>);

impl<T: Config> DocumentKeyShadowRetrievalService<T> {
	/// Request new document key shadow retrieval. Retrieved key will be published via
	/// DocumentKeyShadowRetrieved event when available.
	pub fn retrieve(
		origin: T::Origin,
		id: ServerKeyId,
		requester_public: sp_core::H512,
	) -> Result<(), &'static str> {
		// limit number of requests in the queue
		ensure!(
			(DocumentKeyShadowRetrievalRequestsKeys::decode_len().unwrap_or(0) as u64) < MAX_REQUESTS,
			"Too many active requests. Try later",
		);

		// the request ID here is the concat of key id and requester id
		let origin = ensure_signed(origin)?;
		let requester = resolve_entity_id::<T>(&origin)?;
		let retrieval_id = (id, requester);

		// check that requester_public corresponds to requester address (EntityId)
		let requester_public_hash = sp_io::hashing::keccak_256(requester_public.as_fixed_bytes());
		let mut computed_requester_address = EntityId::zero();
		computed_requester_address.as_bytes_mut().copy_from_slice(&requester_public_hash[12..]);
		ensure!(
			requester == computed_requester_address,
			"Invalid public key passed",
		);

		// check if there are no pending request for the same key
		ensure!(
			!DocumentKeyShadowRetrievalRequests::<T>::contains_key(retrieval_id),
			"The same request is already queued",
		);

		// collect service fee
		let fee = DocumentKeyShadowRetrievalFee::<T>::get();
		SecretStoreService::<T>::collect_service_fee(&origin, fee)?;

		// we do not know exact threshold value here && we can not blindly trust the first response
		// => we should agree upon two values: threshold && document key itself
		// => assuming that all authorities will eventually respond with value/error, we will wait for:
		// 1) at least 50% + 1 authorities agreement on the same threshold value
		// 2) after threshold is agreed, we will wait for threshold + 1 values of document key

		// the data required to compute document key is the triple { sp_core::H512, encryptedPoint, shadowPoints[] }
		// this data is computed on threshold + 1 nodes only
		// retrieval consists of two phases:
		// 1) every authority that is seeing retrieval request, publishes { sp_core::H512, encryptedPoint, threshold }
		// 2) master node starts decryption session
		// 2.1) every node participating in decryption session publishes { address[], shadow }
		// 2.2) once there are threshold + 1 confirmations of { address[], shadow } from exactly address[]
		// authorities, we are publishing the key

		let request = DocumentKeyShadowRetrievalRequest {
			requester,
			requester_public: requester_public.clone(),
			common_responses: SecretStoreService::<T>::new_responses(),
			threshold: None,
			personal_retrieval_errors_mask: Default::default(),
			personal_retrieval_errors_count: 0,
		};
		DocumentKeyShadowRetrievalRequests::<T>::insert(retrieval_id, request);
		DocumentKeyShadowRetrievalRequestsKeys::append(&retrieval_id);

		// emit event
		Module::<T>::deposit_event(Event::DocumentKeyShadowRetrievalRequested(id, requester));

		Ok(())
	}

	/// Called when 'common' key data is reported by key server.
	pub fn on_common_retrieved(
		origin: T::Origin,
		id: ServerKeyId,
		requester: EntityId,
		common_point: sp_core::H512,
		threshold: u8,
	) -> Result<(), &'static str> {
		// check if this request is active (the tx could arrive when request is already inactive)
		let retrieval_id = (id, requester);
		let mut request = match DocumentKeyShadowRetrievalRequests::<T>::get(retrieval_id) {
			Some(request) => request,
			None => return Ok(()),
		};

		// do not accept common data once we started receiving personal data
		if request.threshold.is_some() {
			return Ok(());
		}

		// insert common key data response
		let key_servers_count = SecretStoreService::<T>::key_servers_count()?;
		let key_server_index = SecretStoreService::<T>::key_server_index_from_origin(origin)?;
		let common_support = SecretStoreService::<T>
			::insert_response::<_, _, DocumentKeyShadowRetrievalCommonResponses>(
				key_server_index,
				key_servers_count / 2,
				&mut request.common_responses,
				&retrieval_id,
				&(common_point.clone(), threshold),
			)?;

		match common_support {
			ResponseSupport::Unconfirmed => {
				DocumentKeyShadowRetrievalRequests::<T>::insert(retrieval_id, request);
			},
			ResponseSupport::Confirmed => {
				// remember threshold
				let requester_public = request.requester_public.clone();
				request.threshold = Some(threshold);
				DocumentKeyShadowRetrievalRequests::<T>::insert(retrieval_id, request);

				// publish common data
				Module::<T>::deposit_event(Event::DocumentKeyCommonRetrieved(id, requester, common_point, threshold));

				// ...and signal to start decryption
				Module::<T>::deposit_event(Event::DocumentKeyPersonalRetrievalRequested(id, requester_public));
			},
			ResponseSupport::Impossible => {
				// we do not need this request anymore
				delete_request::<T>(&(id, requester));

				// emit event
				Module::<T>::deposit_event(Event::DocumentKeyShadowRetrievalError(id, requester));
			},
		}

		Ok(())
	}

	/// Called when 'personal' key data is reported by key server.
	pub fn on_personal_retrieved(
		origin: T::Origin,
		id: ServerKeyId,
		requester: EntityId,
		participants: KeyServersMask,
		decrypted_secret: sp_core::H512,
		shadow: Vec<u8>,
	) -> Result<(), &'static str> {
		// check if this request is active (the tx could arrive when request is already inactive)
		let retrieval_id = (id, requester);
		let request = match DocumentKeyShadowRetrievalRequests::<T>::get(retrieval_id) {
			Some(request) => request,
			None => return Ok(()),
		};

		// reporting private data when common is not yet reported is an error
		ensure!(
			request.threshold.is_some(),
			"Reporting private data before common is reported",
		);

		// key server must have an entry in participants
		let key_server_index = SecretStoreService::<T>::key_server_index_from_origin(origin)?;
		let key_server_mask = KeyServersMask::from_index(key_server_index);
		let updated_participants = participants.union(key_server_mask);
		ensure!(
			participants == updated_participants,
			"Reporint key server is not a participant",
		);

		// insert new personal data
		let mut personal_data = DocumentKeyShadowRetrievalPersonalResponses::get(
			&retrieval_id,
			&(participants, decrypted_secret.clone()),
		);
		let personal_data_updated_participants = personal_data.participants.union(key_server_mask);
		ensure!(
			personal_data_updated_participants != personal_data.participants,
			"Cannot report personal data twice",
		);
		personal_data.reported_count = personal_data.reported_count + 1;
		personal_data.participants = personal_data_updated_participants;

		// publish personal portion
		Module::<T>::deposit_event(Event::DocumentKeyPersonalRetrieved(
			id,
			requester,
			decrypted_secret,
			shadow,
		));

		// check if we have published enough portions
		if request.threshold != Some(personal_data.reported_count - 1) {
			DocumentKeyShadowRetrievalPersonalResponses::insert(
				&retrieval_id,
				&(participants, decrypted_secret),
				&personal_data,
			);
		} else {
			delete_request::<T>(&retrieval_id);
		}

		Ok(())
	}

	/// Called when retrieval error is reported by key server.
	pub fn on_retrieval_error(
		origin: T::Origin,
		id: ServerKeyId,
		requester: EntityId,
	) -> Result<(), &'static str> {
		// check if this request is active (the tx could arrive when request is already inactive)
		let retrieval_id = (id, requester);
		let mut request = match DocumentKeyShadowRetrievalRequests::<T>::get(retrieval_id) {
			Some(request) => request,
			None => return Ok(()),
		};

		// error on common data retrieval step is treated like a voting for non-existant common data
		let key_servers_count = SecretStoreService::<T>::key_servers_count()?;
		let key_server_index = SecretStoreService::<T>::key_server_index_from_origin(origin)?;
		if request.threshold.is_none() {
			// insert response
			let invalid_response_support = SecretStoreService::<T>
				::insert_response::<_, _, DocumentKeyShadowRetrievalCommonResponses>(
					key_server_index,
					key_servers_count / 2,
					&mut request.common_responses,
					&retrieval_id,
					&(Default::default(), 0xFF),
				)?;

			// ...and check if there are enough confirmations for invalid response
			if invalid_response_support == ResponseSupport::Unconfirmed {
				DocumentKeyShadowRetrievalRequests::<T>::insert(retrieval_id, request);
				return Ok(());
			}

			// delete request and fire event
			delete_request::<T>(&retrieval_id);
			Module::<T>::deposit_event(Event::DocumentKeyShadowRetrievalError(id, requester));
			return Ok(());
		}

		// else error has occured during personal data retrieval
		// this could be:
		// 1) access denied error (because KS is out of sync?)
		// 2) key has became irrecoverable
		// 3) key server is cheating
		// there's currently no strong criteria - when to stop retrying to serve request
		// stopping it after first error isn't good, because this means that any KS can reject request
		// waiting for N errors isn't good, because consensus set in decryption session is constructed
		//   right after t+1 nodes have responded with AGREE => some of nodes (with bad connectivity) might be
		//   'banned' from this session forever
		// waiting for any threshold-related errors count will fail if this count is larger than N
		// => let's wait for N/2+1 errors from different nodes
		let key_server_mask = KeyServersMask::from_index(key_server_index);
		let updated_personal_retrieval_errors_mask = request.personal_retrieval_errors_mask.union(key_server_mask);
		if updated_personal_retrieval_errors_mask == request.personal_retrieval_errors_mask {
			DocumentKeyShadowRetrievalRequests::<T>::insert(retrieval_id, request);
			return Ok(());
		}
		request.personal_retrieval_errors_mask = updated_personal_retrieval_errors_mask;
		request.personal_retrieval_errors_count = request.personal_retrieval_errors_count + 1;

		// check if we have enough errors
		if request.personal_retrieval_errors_count < key_servers_count / 2 + 1 {
			DocumentKeyShadowRetrievalRequests::<T>::insert(retrieval_id, request);
			return Ok(());
		}

		delete_request::<T>(&retrieval_id);
		Module::<T>::deposit_event(Event::DocumentKeyShadowRetrievalError(id, requester));
		Ok(())
	}

	/// Returs true if response from given keyServer is required.
	pub fn is_response_required(
		key_server: KeyServerId,
		id: ServerKeyId,
		requester: EntityId,
	) -> bool {
		let retrieval_id = (id, requester);
		DocumentKeyShadowRetrievalRequests::<T>::get(&retrieval_id)
			.map(|request| request.threshold.is_some() || SecretStoreService::<T>::is_response_required(
				key_server,
				&request.common_responses,
			))
			.unwrap_or(false)
	}
}

/// Deletes request and all associated data.
fn delete_request<T: Config>(request: &(ServerKeyId, EntityId)) {
	DocumentKeyShadowRetrievalCommonResponses::remove_prefix(request);
	DocumentKeyShadowRetrievalPersonalResponses::remove_prefix(request);
	DocumentKeyShadowRetrievalRequests::<T>::remove(request);
	DocumentKeyShadowRetrievalRequestsKeys::mutate(|list| {
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

	fn ensure_clean_storage(key: ServerKeyId, requester: EntityId) {
		assert_eq!(DocumentKeyShadowRetrievalRequestsKeys::get(), vec![]);
		assert!(!DocumentKeyShadowRetrievalRequests::<TestRuntime>::contains_key((key, requester)));
		assert_eq!(
			DocumentKeyShadowRetrievalCommonResponses::iter_prefix((key, requester))
				.collect::<Vec<_>>(),
			vec![],
		);
		assert_eq!(
			DocumentKeyShadowRetrievalPersonalResponses::iter_prefix((key, requester))
				.collect::<Vec<_>>(),
			vec![],
		);
	}

	#[test]
	fn should_accept_document_key_shadow_retrieval_request() {
		default_initialization_with_five_servers().execute_with(|| {
			// ask to retrieve document key shadow
			DocumentKeyShadowRetrievalService::<TestRuntime>::retrieve(
				Origin::signed(REAL_REQUESTER1),
				[32; 32].into(),
				REAL_REQUESTER1_PUBLIC.into(),
			).unwrap();

			// check that event has been emitted
			assert!(
				frame_system::Module::<TestRuntime>::events().into_iter()
					.find(|e| e.event == Event::DocumentKeyShadowRetrievalRequested(
						[32; 32].into(),
						REAL_REQUESTER1_ADDRESS.into(),
					).into())
					.is_some(),
			);
		});
	}

	#[test]
	fn should_reject_document_key_shadow_retrieval_request_from_invalid_public() {
		default_initialization_with_five_servers().execute_with(|| {
			// ask to retrieve document key shadow
			DocumentKeyShadowRetrievalService::<TestRuntime>::retrieve(
				Origin::signed(REAL_REQUESTER2),
				[32; 32].into(),
				REAL_REQUESTER1_PUBLIC.into(),
			).unwrap_err();

			ensure_clean_storage([32; 32].into(), REAL_REQUESTER1_ADDRESS.into());
		});
	}

	#[test]
	fn should_reject_document_key_shadow_retrieval_request_when_fee_is_not_paid() {
		default_initialization_with_five_servers().execute_with(|| {
			// ask to retrieve document key shadow
			DocumentKeyShadowRetrievalService::<TestRuntime>::retrieve(
				Origin::signed(REAL_REQUESTER2),
				[32; 32].into(),
				REAL_REQUESTER2_PUBLIC.into(),
			).unwrap_err();

			ensure_clean_storage([32; 32].into(), REAL_REQUESTER2_ADDRESS.into());
		});
	}

	#[test]
	fn should_reject_document_key_shadow_retrieval_request_when_limit_reached() {
		default_initialization_with_five_servers().execute_with(|| {
			// make MAX_REQUESTS requests
			for i in 0..MAX_REQUESTS {
				DocumentKeyShadowRetrievalService::<TestRuntime>::retrieve(
					Origin::signed(REAL_REQUESTER1),
					[i as u8; 32].into(),
					REAL_REQUESTER1_PUBLIC.into(),
				).unwrap();
			}

			// and now try to push new request so that there will be more than a limit requests
			DocumentKeyShadowRetrievalService::<TestRuntime>::retrieve(
				Origin::signed(REAL_REQUESTER1),
				[MAX_REQUESTS as u8; 32].into(),
				REAL_REQUESTER1_PUBLIC.into(),
			).unwrap_err();
		});
	}

	#[test]
	fn should_reject_duplicated_document_key_shadow_retrieval_request() {
		default_initialization_with_five_servers().execute_with(|| {
			// ask to retrieve document key shadow
			DocumentKeyShadowRetrievalService::<TestRuntime>::retrieve(
				Origin::signed(REAL_REQUESTER1),
				[32; 32].into(),
				REAL_REQUESTER1_PUBLIC.into(),
			).unwrap();

			// ask to retrieve document key shadow
			DocumentKeyShadowRetrievalService::<TestRuntime>::retrieve(
				Origin::signed(REAL_REQUESTER1),
				[32; 32].into(),
				REAL_REQUESTER1_PUBLIC.into(),
			).unwrap_err();
		});
	}

	#[test]
	fn should_publish_common_data_when_all_servers_respond_with_the_same_value() {
		default_initialization_with_five_servers().execute_with(|| {
			// ask to retrieve document key shadow
			DocumentKeyShadowRetrievalService::<TestRuntime>::retrieve(
				Origin::signed(REAL_REQUESTER1),
				[32; 32].into(),
				REAL_REQUESTER1_PUBLIC.into(),
			).unwrap();

			// receive same response from 50%+1 servers
			let events_count = frame_system::Module::<TestRuntime>::events().len();
			DocumentKeyShadowRetrievalService::<TestRuntime>::on_common_retrieved(
				Origin::signed(KEY_SERVER0),
				[32; 32].into(),
				REAL_REQUESTER1_ADDRESS.into(),
				[21; 64].into(),
				4,
			).unwrap();
			DocumentKeyShadowRetrievalService::<TestRuntime>::on_common_retrieved(
				Origin::signed(KEY_SERVER1),
				[32; 32].into(),
				REAL_REQUESTER1_ADDRESS.into(),
				[21; 64].into(),
				4,
			).unwrap();
			assert_eq!(
				events_count,
				frame_system::Module::<TestRuntime>::events().len(),
			);
			DocumentKeyShadowRetrievalService::<TestRuntime>::on_common_retrieved(
				Origin::signed(KEY_SERVER2),
				[32; 32].into(),
				REAL_REQUESTER1_ADDRESS.into(),
				[21; 64].into(),
				4,
			).unwrap();

			// check that common data is published and personal data retrieval is requested
			assert_eq!(
				events_count + 2,
				frame_system::Module::<TestRuntime>::events().len(),
			);
			assert!(
				frame_system::Module::<TestRuntime>::events().into_iter()
					.find(|e| e.event == Event::DocumentKeyCommonRetrieved(
						[32; 32].into(),
						REAL_REQUESTER1_ADDRESS.into(),
						[21; 64].into(),
						4,
					).into())
					.is_some(),
			);
			assert!(
				frame_system::Module::<TestRuntime>::events().into_iter()
					.find(|e| e.event == Event::DocumentKeyPersonalRetrievalRequested(
						[32; 32].into(),
						REAL_REQUESTER1_PUBLIC.into(),
					).into())
					.is_some(),
			);

			// and now next key server responds with the same data
			DocumentKeyShadowRetrievalService::<TestRuntime>::on_common_retrieved(
				Origin::signed(KEY_SERVER3),
				[32; 32].into(),
				REAL_REQUESTER1_ADDRESS.into(),
				[21; 64].into(),
				4,
			).unwrap();

			// check that no new events appear
			assert_eq!(
				events_count + 2,
				frame_system::Module::<TestRuntime>::events().len(),
			);
		});
	}

	#[test]
	fn should_publish_common_data_even_if_some_servers_respond_with_different_common_values() {
		default_initialization_with_five_servers().execute_with(|| {
			// ask to retrieve document key shadow
			DocumentKeyShadowRetrievalService::<TestRuntime>::retrieve(
				Origin::signed(REAL_REQUESTER1),
				[32; 32].into(),
				REAL_REQUESTER1_PUBLIC.into(),
			).unwrap();

			// receive same response1 from 2 servers, then response2 from 1 sever, then response1 from 1 server
			let events_count = frame_system::Module::<TestRuntime>::events().len();
			DocumentKeyShadowRetrievalService::<TestRuntime>::on_common_retrieved(
				Origin::signed(KEY_SERVER0),
				[32; 32].into(),
				REAL_REQUESTER1_ADDRESS.into(),
				[21; 64].into(),
				4,
			).unwrap();
			DocumentKeyShadowRetrievalService::<TestRuntime>::on_common_retrieved(
				Origin::signed(KEY_SERVER1),
				[32; 32].into(),
				REAL_REQUESTER1_ADDRESS.into(),
				[84; 64].into(),
				1,
			).unwrap();
			DocumentKeyShadowRetrievalService::<TestRuntime>::on_common_retrieved(
				Origin::signed(KEY_SERVER2),
				[32; 32].into(),
				REAL_REQUESTER1_ADDRESS.into(),
				[21; 64].into(),
				4,
			).unwrap();
			assert_eq!(
				events_count,
				frame_system::Module::<TestRuntime>::events().len(),
			);
			DocumentKeyShadowRetrievalService::<TestRuntime>::on_common_retrieved(
				Origin::signed(KEY_SERVER3),
				[32; 32].into(),
				REAL_REQUESTER1_ADDRESS.into(),
				[21; 64].into(),
				4,
			).unwrap();

			// check that common data is published and personal data retrieval is requested
			assert_eq!(
				events_count + 2,
				frame_system::Module::<TestRuntime>::events().len(),
			);
			assert!(
				frame_system::Module::<TestRuntime>::events().into_iter()
					.find(|e| e.event == Event::DocumentKeyCommonRetrieved(
						[32; 32].into(),
						REAL_REQUESTER1_ADDRESS.into(),
						[21; 64].into(),
						4,
					).into())
					.is_some(),
			);
			assert!(
				frame_system::Module::<TestRuntime>::events().into_iter()
					.find(|e| e.event == Event::DocumentKeyPersonalRetrievalRequested(
						[32; 32].into(),
						REAL_REQUESTER1_PUBLIC.into(),
					).into())
					.is_some(),
			);
		});
	}

	#[test]
	fn should_report_failure_if_common_data_consensus_unreachable() {
		default_initialization_with_five_servers().execute_with(|| {
			// ask to retrieve document key shadow
			DocumentKeyShadowRetrievalService::<TestRuntime>::retrieve(
				Origin::signed(REAL_REQUESTER1),
				[32; 32].into(),
				REAL_REQUESTER1_PUBLIC.into(),
			).unwrap();

			// receive responses from key servers so that consensus is unreachable
			let events_count = frame_system::Module::<TestRuntime>::events().len();
			DocumentKeyShadowRetrievalService::<TestRuntime>::on_common_retrieved(
				Origin::signed(KEY_SERVER0),
				[32; 32].into(),
				REAL_REQUESTER1_ADDRESS.into(),
				[21; 64].into(),
				4,
			).unwrap();
			DocumentKeyShadowRetrievalService::<TestRuntime>::on_common_retrieved(
				Origin::signed(KEY_SERVER1),
				[32; 32].into(),
				REAL_REQUESTER1_ADDRESS.into(),
				[21; 64].into(),
				1,
			).unwrap();
			DocumentKeyShadowRetrievalService::<TestRuntime>::on_common_retrieved(
				Origin::signed(KEY_SERVER2),
				[32; 32].into(),
				REAL_REQUESTER1_ADDRESS.into(),
				[42; 64].into(),
				4,
			).unwrap();
			assert_eq!(
				events_count,
				frame_system::Module::<TestRuntime>::events().len(),
			);
			DocumentKeyShadowRetrievalService::<TestRuntime>::on_common_retrieved(
				Origin::signed(KEY_SERVER3),
				[32; 32].into(),
				REAL_REQUESTER1_ADDRESS.into(),
				[42; 64].into(),
				3,
			).unwrap();

			// check that retrieval error is published
			assert_eq!(
				events_count + 1,
				frame_system::Module::<TestRuntime>::events().len(),
			);
			assert!(
				frame_system::Module::<TestRuntime>::events().into_iter()
					.find(|e| e.event == Event::DocumentKeyShadowRetrievalError(
						[32; 32].into(),
						REAL_REQUESTER1_ADDRESS.into(),
					).into())
					.is_some(),
			);
		});
	}

	#[test]
	fn should_ignore_common_data_if_no_active_request() {
		default_initialization_with_five_servers().execute_with(|| {
			// receive common response before/after request
			DocumentKeyShadowRetrievalService::<TestRuntime>::on_common_retrieved(
				Origin::signed(KEY_SERVER0),
				[32; 32].into(),
				[REQUESTER1 as u8; 20].into(),
				[21; 64].into(),
				4,
			).unwrap();
		});
	}

	#[test]
	fn should_ignore_personal_data_if_no_active_request() {
		default_initialization_with_five_servers().execute_with(|| {
			// receive personal response before/after request
			DocumentKeyShadowRetrievalService::<TestRuntime>::on_personal_retrieved(
				Origin::signed(KEY_SERVER0),
				[32; 32].into(),
				[REQUESTER1 as u8; 20].into(),
				KeyServersMask::from_index(0),
				[100; 64].into(),
				vec![101],
			).unwrap();
		});
	}

	#[test]
	fn should_fail_if_personal_data_is_received_before_common() {
		default_initialization_with_five_servers().execute_with(|| {
			// ask to retrieve document key shadow
			DocumentKeyShadowRetrievalService::<TestRuntime>::retrieve(
				Origin::signed(REAL_REQUESTER1),
				[32; 32].into(),
				REAL_REQUESTER1_PUBLIC.into(),
			).unwrap();

			// receive personal response before common
			DocumentKeyShadowRetrievalService::<TestRuntime>::on_personal_retrieved(
				Origin::signed(KEY_SERVER0),
				[32; 32].into(),
				REAL_REQUESTER1_ADDRESS.into(),
				KeyServersMask::from_index(0),
				[100; 64].into(),
				vec![101].into(),
			).unwrap_err();
		});
	}

	#[test]
	fn should_fail_if_second_personal_data_is_retrieved() {
		default_initialization_with_five_servers().execute_with(|| {
			// ask to retrieve document key shadow
			DocumentKeyShadowRetrievalService::<TestRuntime>::retrieve(
				Origin::signed(REAL_REQUESTER1),
				[32; 32].into(),
				REAL_REQUESTER1_PUBLIC.into(),
			).unwrap();

			// receive common responses
			DocumentKeyShadowRetrievalService::<TestRuntime>::on_common_retrieved(
				Origin::signed(KEY_SERVER0),
				[32; 32].into(),
				REAL_REQUESTER1_ADDRESS.into(),
				[42; 64].into(),
				1,
			).unwrap();
			DocumentKeyShadowRetrievalService::<TestRuntime>::on_common_retrieved(
				Origin::signed(KEY_SERVER1),
				[32; 32].into(),
				REAL_REQUESTER1_ADDRESS.into(),
				[42; 64].into(),
				1,
			).unwrap();
			DocumentKeyShadowRetrievalService::<TestRuntime>::on_common_retrieved(
				Origin::signed(KEY_SERVER2),
				[32; 32].into(),
				REAL_REQUESTER1_ADDRESS.into(),
				[42; 64].into(),
				1,
			).unwrap();

			// receive shadow-different responses from the same KS - the second should fail
			DocumentKeyShadowRetrievalService::<TestRuntime>::on_personal_retrieved(
				Origin::signed(KEY_SERVER0),
				[32; 32].into(),
				REAL_REQUESTER1_ADDRESS.into(),
				KeyServersMask::from_index(0),
				[100; 64].into(),
				vec![101],
			).unwrap();
			DocumentKeyShadowRetrievalService::<TestRuntime>::on_personal_retrieved(
				Origin::signed(KEY_SERVER0),
				[32; 32].into(),
				REAL_REQUESTER1_ADDRESS.into(),
				KeyServersMask::from_index(0),
				[100; 64].into(),
				vec![102],
			).unwrap_err();
		});
	}

	#[test]
	fn should_fail_if_common_data_is_reported_by_non_key_server() {
		default_initialization_with_five_servers().execute_with(|| {
			// ask to retrieve document key shadow
			DocumentKeyShadowRetrievalService::<TestRuntime>::retrieve(
				Origin::signed(REAL_REQUESTER1),
				[32; 32].into(),
				REAL_REQUESTER1_PUBLIC.into(),
			).unwrap();

			// receive common response from usual entity
			DocumentKeyShadowRetrievalService::<TestRuntime>::on_common_retrieved(
				Origin::signed(REAL_REQUESTER2),
				[32; 32].into(),
				REAL_REQUESTER1_ADDRESS.into(),
				[42; 64].into(),
				1,
			).unwrap_err();
		});
	}

	#[test]
	fn should_fail_if_personal_data_is_reported_by_non_key_server() {
		default_initialization_with_five_servers().execute_with(|| {
			// ask to retrieve document key shadow
			DocumentKeyShadowRetrievalService::<TestRuntime>::retrieve(
				Origin::signed(REAL_REQUESTER1),
				[32; 32].into(),
				REAL_REQUESTER1_PUBLIC.into(),
			).unwrap();

			// receive common responses
			DocumentKeyShadowRetrievalService::<TestRuntime>::on_common_retrieved(
				Origin::signed(KEY_SERVER0),
				[32; 32].into(),
				REAL_REQUESTER1_ADDRESS.into(),
				[42; 64].into(),
				1,
			).unwrap();
			DocumentKeyShadowRetrievalService::<TestRuntime>::on_common_retrieved(
				Origin::signed(KEY_SERVER1),
				[32; 32].into(),
				REAL_REQUESTER1_ADDRESS.into(),
				[42; 64].into(),
				1,
			).unwrap();
			DocumentKeyShadowRetrievalService::<TestRuntime>::on_common_retrieved(
				Origin::signed(KEY_SERVER2),
				[32; 32].into(),
				REAL_REQUESTER1_ADDRESS.into(),
				[42; 64].into(),
				1,
			).unwrap();

			// receive personal response from usual requester
			DocumentKeyShadowRetrievalService::<TestRuntime>::on_personal_retrieved(
				Origin::signed(REQUESTER2),
				[32; 32].into(),
				REAL_REQUESTER1_ADDRESS.into(),
				KeyServersMask::from_index(0),
				[100; 64].into(),
				vec![101],
			).unwrap_err();
		});
	}

	#[test]
	fn should_fail_if_personal_data_is_reported_by_wrong_server() {
		default_initialization_with_five_servers().execute_with(|| {
			// ask to retrieve document key shadow
			DocumentKeyShadowRetrievalService::<TestRuntime>::retrieve(
				Origin::signed(REAL_REQUESTER1),
				[32; 32].into(),
				REAL_REQUESTER1_PUBLIC.into(),
			).unwrap();

			// receive common responses
			DocumentKeyShadowRetrievalService::<TestRuntime>::on_common_retrieved(
				Origin::signed(KEY_SERVER0),
				[32; 32].into(),
				REAL_REQUESTER1_ADDRESS.into(),
				[42; 64].into(),
				1,
			).unwrap();
			DocumentKeyShadowRetrievalService::<TestRuntime>::on_common_retrieved(
				Origin::signed(KEY_SERVER1),
				[32; 32].into(),
				REAL_REQUESTER1_ADDRESS.into(),
				[42; 64].into(),
				1,
			).unwrap();
			DocumentKeyShadowRetrievalService::<TestRuntime>::on_common_retrieved(
				Origin::signed(KEY_SERVER2),
				[32; 32].into(),
				REAL_REQUESTER1_ADDRESS.into(),
				[42; 64].into(),
				1,
			).unwrap();

			// receive error from non-KS
			DocumentKeyShadowRetrievalService::<TestRuntime>::on_personal_retrieved(
				Origin::signed(REQUESTER2),
				[32; 32].into(),
				REAL_REQUESTER1_ADDRESS.into(),
				KeyServersMask::from_index(1),
				[100; 64].into(),
				vec![101],
			).unwrap_err();
		});
	}

	#[test]
	fn should_ignore_retrieval_error_if_no_active_request() {
		default_initialization_with_five_servers().execute_with(|| {
			// receive common response from usual entity
			DocumentKeyShadowRetrievalService::<TestRuntime>::on_retrieval_error(
				Origin::signed(KEY_SERVER0),
				[32; 32].into(),
				[REQUESTER1 as u8; 20].into(),
			).unwrap();
		});
	}

	#[test]
	fn should_fail_if_retrieval_error_is_reported_by_non_key_server() {
		default_initialization_with_five_servers().execute_with(|| {
			// ask to retrieve document key shadow
			DocumentKeyShadowRetrievalService::<TestRuntime>::retrieve(
				Origin::signed(REAL_REQUESTER1),
				[32; 32].into(),
				REAL_REQUESTER1_PUBLIC.into(),
			).unwrap();

			// receive common response from usual entity
			DocumentKeyShadowRetrievalService::<TestRuntime>::on_retrieval_error(
				Origin::signed(REAL_REQUESTER1),
				[32; 32].into(),
				REAL_REQUESTER1_ADDRESS.into(),
			).unwrap_err();
		});
	}

	#[test]
	fn should_report_failure_if_common_retrieval_error_is_confirmed_by_more_than_a_half_servers() {
		default_initialization_with_five_servers().execute_with(|| {
			// ask to retrieve document key shadow
			DocumentKeyShadowRetrievalService::<TestRuntime>::retrieve(
				Origin::signed(REAL_REQUESTER1),
				[32; 32].into(),
				REAL_REQUESTER1_PUBLIC.into(),
			).unwrap();
			let events_count = frame_system::Module::<TestRuntime>::events().len();

			// receive common response from usual entity
			DocumentKeyShadowRetrievalService::<TestRuntime>::on_retrieval_error(
				Origin::signed(KEY_SERVER0),
				[32; 32].into(),
				REAL_REQUESTER1_ADDRESS.into(),
			).unwrap();
			DocumentKeyShadowRetrievalService::<TestRuntime>::on_retrieval_error(
				Origin::signed(KEY_SERVER1),
				[32; 32].into(),
				REAL_REQUESTER1_ADDRESS.into(),
			).unwrap();
			assert_eq!(
				events_count,
				frame_system::Module::<TestRuntime>::events().len(),
			);
			DocumentKeyShadowRetrievalService::<TestRuntime>::on_retrieval_error(
				Origin::signed(KEY_SERVER2),
				[32; 32].into(),
				REAL_REQUESTER1_ADDRESS.into(),
			).unwrap();

			// check that retrieval error is published
			assert_eq!(
				events_count + 1,
				frame_system::Module::<TestRuntime>::events().len(),
			);
			assert!(
				frame_system::Module::<TestRuntime>::events().into_iter()
					.find(|e| e.event == Event::DocumentKeyShadowRetrievalError(
						[32; 32].into(),
						REAL_REQUESTER1_ADDRESS.into(),
					).into())
					.is_some(),
			);
		});
	}

	#[test]
	fn should_ignore_personal_retrieval_error_if_reported_twice() {
		default_initialization_with_five_servers().execute_with(|| {
			// ask to retrieve document key shadow
			DocumentKeyShadowRetrievalService::<TestRuntime>::retrieve(
				Origin::signed(REAL_REQUESTER1),
				[32; 32].into(),
				REAL_REQUESTER1_PUBLIC.into(),
			).unwrap();

			// receive common responses
			DocumentKeyShadowRetrievalService::<TestRuntime>::on_common_retrieved(
				Origin::signed(KEY_SERVER0),
				[32; 32].into(),
				REAL_REQUESTER1_ADDRESS.into(),
				[42; 64].into(),
				1,
			).unwrap();
			DocumentKeyShadowRetrievalService::<TestRuntime>::on_common_retrieved(
				Origin::signed(KEY_SERVER1),
				[32; 32].into(),
				REAL_REQUESTER1_ADDRESS.into(),
				[42; 64].into(),
				1,
			).unwrap();
			DocumentKeyShadowRetrievalService::<TestRuntime>::on_common_retrieved(
				Origin::signed(KEY_SERVER2),
				[32; 32].into(),
				REAL_REQUESTER1_ADDRESS.into(),
				[42; 64].into(),
				1,
			).unwrap();
			let events_count = frame_system::Module::<TestRuntime>::events().len();

			// N is 5 => we are waiting for 3 (5/2 + 1) errors before reporting an error
			DocumentKeyShadowRetrievalService::<TestRuntime>::on_retrieval_error(
				Origin::signed(KEY_SERVER0),
				[32; 32].into(),
				REAL_REQUESTER1_ADDRESS.into(),
			).unwrap();
			DocumentKeyShadowRetrievalService::<TestRuntime>::on_retrieval_error(
				Origin::signed(KEY_SERVER1),
				[32; 32].into(),
				REAL_REQUESTER1_ADDRESS.into(),
			).unwrap();
			DocumentKeyShadowRetrievalService::<TestRuntime>::on_retrieval_error(
				Origin::signed(KEY_SERVER0),
				[32; 32].into(),
				REAL_REQUESTER1_ADDRESS.into(),
			).unwrap();

			// check that error isn't published
			assert_eq!(
				events_count,
				frame_system::Module::<TestRuntime>::events().len(),
			);
		});
	}

	#[test]
	fn should_report_failure_if_personal_retrieval_error_is_confirmed_by_more_than_required_servers() {
		default_initialization_with_five_servers().execute_with(|| {
			// ask to retrieve document key shadow
			DocumentKeyShadowRetrievalService::<TestRuntime>::retrieve(
				Origin::signed(REAL_REQUESTER1),
				[32; 32].into(),
				REAL_REQUESTER1_PUBLIC.into(),
			).unwrap();

			// receive common responses
			DocumentKeyShadowRetrievalService::<TestRuntime>::on_common_retrieved(
				Origin::signed(KEY_SERVER0),
				[32; 32].into(),
				REAL_REQUESTER1_ADDRESS.into(),
				[42; 64].into(),
				1,
			).unwrap();
			DocumentKeyShadowRetrievalService::<TestRuntime>::on_common_retrieved(
				Origin::signed(KEY_SERVER1),
				[32; 32].into(),
				REAL_REQUESTER1_ADDRESS.into(),
				[42; 64].into(),
				1,
			).unwrap();
			DocumentKeyShadowRetrievalService::<TestRuntime>::on_common_retrieved(
				Origin::signed(KEY_SERVER2),
				[32; 32].into(),
				REAL_REQUESTER1_ADDRESS.into(),
				[42; 64].into(),
				1,
			).unwrap();
			let events_count = frame_system::Module::<TestRuntime>::events().len();

			// N is 5 => we are waiting for 3 (5/2 + 1) errors before reporting an error
			DocumentKeyShadowRetrievalService::<TestRuntime>::on_retrieval_error(
				Origin::signed(KEY_SERVER0),
				[32; 32].into(),
				REAL_REQUESTER1_ADDRESS.into(),
			).unwrap();
			DocumentKeyShadowRetrievalService::<TestRuntime>::on_retrieval_error(
				Origin::signed(KEY_SERVER1),
				[32; 32].into(),
				REAL_REQUESTER1_ADDRESS.into(),
			).unwrap();
			DocumentKeyShadowRetrievalService::<TestRuntime>::on_retrieval_error(
				Origin::signed(KEY_SERVER2),
				[32; 32].into(),
				REAL_REQUESTER1_ADDRESS.into(),
			).unwrap();

			// check that retrieval error is published
			assert_eq!(
				events_count + 1,
				frame_system::Module::<TestRuntime>::events().len(),
			);
			assert!(
				frame_system::Module::<TestRuntime>::events().into_iter()
					.find(|e| e.event == Event::DocumentKeyShadowRetrievalError(
						[32; 32].into(),
						REAL_REQUESTER1_ADDRESS.into(),
					).into())
					.is_some(),
			);
		});
	}

	#[test]
	fn should_return_if_response_is_required() {
		default_initialization_with_five_servers().execute_with(|| {
			// ask to retrieve document key shadow
			DocumentKeyShadowRetrievalService::<TestRuntime>::retrieve(
				Origin::signed(REAL_REQUESTER1),
				[32; 32].into(),
				REAL_REQUESTER1_PUBLIC.into(),
			).unwrap();

			// initially responses from KS0 && KS1 are required
			assert!(
				DocumentKeyShadowRetrievalService::<TestRuntime>::is_response_required(
					KEY_SERVER0_ID.into(),
					[32; 32].into(),
					REAL_REQUESTER1_ADDRESS.into(),
				)
				&& DocumentKeyShadowRetrievalService::<TestRuntime>::is_response_required(
					KEY_SERVER1_ID.into(),
					[32; 32].into(),
					REAL_REQUESTER1_ADDRESS.into(),
				)
			);

			// receive response from KS0
			DocumentKeyShadowRetrievalService::<TestRuntime>::on_common_retrieved(
				Origin::signed(KEY_SERVER0),
				[32; 32].into(),
				REAL_REQUESTER1_ADDRESS.into(),
				[42; 64].into(),
				1,
			).unwrap();

			// response from KS1 is required
			assert!(
				!DocumentKeyShadowRetrievalService::<TestRuntime>::is_response_required(
					KEY_SERVER0_ID.into(),
					[32; 32].into(),
					REAL_REQUESTER1_ADDRESS.into(),
				)
				&& DocumentKeyShadowRetrievalService::<TestRuntime>::is_response_required(
					KEY_SERVER1_ID.into(),
					[32; 32].into(),
					REAL_REQUESTER1_ADDRESS.into(),
				)
			);

			// receive response from KS1
			DocumentKeyShadowRetrievalService::<TestRuntime>::on_common_retrieved(
				Origin::signed(KEY_SERVER1),
				[32; 32].into(),
				REAL_REQUESTER1_ADDRESS.into(),
				[42; 64].into(),
				1,
			).unwrap();

			// response from other KS are required
			assert!(
				!DocumentKeyShadowRetrievalService::<TestRuntime>::is_response_required(
					KEY_SERVER0_ID.into(),
					[32; 32].into(),
					REAL_REQUESTER1_ADDRESS.into(),
				)
				&& !DocumentKeyShadowRetrievalService::<TestRuntime>::is_response_required(
					KEY_SERVER1_ID.into(),
					[32; 32].into(),
					REAL_REQUESTER1_ADDRESS.into(),
				)
			);

			// complete common retrieval step
			DocumentKeyShadowRetrievalService::<TestRuntime>::on_common_retrieved(
				Origin::signed(KEY_SERVER2),
				[32; 32].into(),
				REAL_REQUESTER1_ADDRESS.into(),
				[42; 64].into(),
				1,
			).unwrap();

			// response from both KS is required again
			assert!(
				DocumentKeyShadowRetrievalService::<TestRuntime>::is_response_required(
					KEY_SERVER0_ID.into(),
					[32; 32].into(),
					REAL_REQUESTER1_ADDRESS.into(),
				)
				&& DocumentKeyShadowRetrievalService::<TestRuntime>::is_response_required(
					KEY_SERVER1_ID.into(),
					[32; 32].into(),
					REAL_REQUESTER1_ADDRESS.into(),
				)
			);

			// now KS0 responds with personal data and still we're waiting for personal response (since it one-time
			// only and if some node fail to respond we need to restart)
			DocumentKeyShadowRetrievalService::<TestRuntime>::on_personal_retrieved(
				Origin::signed(KEY_SERVER0),
				[32; 32].into(),
				REAL_REQUESTER1_ADDRESS.into(),
				KeyServersMask::from_index(1),
				[100; 64].into(),
				vec![101],
			).unwrap_err();

			// response from both KS is required again
			assert!(
				DocumentKeyShadowRetrievalService::<TestRuntime>::is_response_required(
					KEY_SERVER0_ID.into(),
					[32; 32].into(),
					REAL_REQUESTER1_ADDRESS.into(),
				)
				&& DocumentKeyShadowRetrievalService::<TestRuntime>::is_response_required(
					KEY_SERVER1_ID.into(),
					[32; 32].into(),
					REAL_REQUESTER1_ADDRESS.into(),
				)
			);
		});
	}

	#[test]
	fn should_reset_existing_responses_when_server_set_changes() {
		default_initialization_with_five_servers().execute_with(|| {
			// request is created and single key server responds
			DocumentKeyShadowRetrievalService::<TestRuntime>::retrieve(
				Origin::signed(REAL_REQUESTER1),
				[32; 32].into(),
				REAL_REQUESTER1_PUBLIC.into(),
			).unwrap();

			DocumentKeyShadowRetrievalService::<TestRuntime>::on_common_retrieved(
				Origin::signed(KEY_SERVER0),
				[32; 32].into(),
				REAL_REQUESTER1_ADDRESS.into(),
				[42; 64].into(),
				1,
			).unwrap();

			assert!(!DocumentKeyShadowRetrievalService::<TestRuntime>::is_response_required(
				KEY_SERVER0_ID.into(),
				[32; 32].into(),
				REAL_REQUESTER1_ADDRESS.into(),
			));

			// then we're starting && completing the migration
			crate::CurrentSetChangeBlock::<TestRuntime>::put(100);

			// check that response from KS0 is now required
			assert!(DocumentKeyShadowRetrievalService::<TestRuntime>::is_response_required(
				KEY_SERVER0_ID.into(),
				[32; 32].into(),
				REAL_REQUESTER1_ADDRESS.into(),
			));

			// now we're receiving common response from KS2 && KS4 and still response from KS1 is required
			DocumentKeyShadowRetrievalService::<TestRuntime>::on_common_retrieved(
				Origin::signed(KEY_SERVER2),
				[32; 32].into(),
				REAL_REQUESTER1_ADDRESS.into(),
				[42; 64].into(),
				1,
			).unwrap();
			DocumentKeyShadowRetrievalService::<TestRuntime>::on_common_retrieved(
				Origin::signed(KEY_SERVER4),
				[32; 32].into(),
				REAL_REQUESTER1_ADDRESS.into(),
				[42; 64].into(),
				1,
			).unwrap();
			assert!(DocumentKeyShadowRetrievalService::<TestRuntime>::is_response_required(
				KEY_SERVER0_ID.into(),
				[32; 32].into(),
				REAL_REQUESTER1_ADDRESS.into(),
			));

			// now we're receiving response from KS0
			DocumentKeyShadowRetrievalService::<TestRuntime>::on_common_retrieved(
				Origin::signed(KEY_SERVER0),
				[32; 32].into(),
				REAL_REQUESTER1_ADDRESS.into(),
				[42; 64].into(),
				1,
			).unwrap();

			// and still response from KS0 is required (because we always personal responses)
			assert!(DocumentKeyShadowRetrievalService::<TestRuntime>::is_response_required(
				KEY_SERVER0_ID.into(),
				[32; 32].into(),
				REAL_REQUESTER1_ADDRESS.into(),
			));
		});
	}

	#[test]
	fn should_publish_common_and_personal_data() {
		default_initialization_with_five_servers().execute_with(|| {
			// ask to retrieve document key shadow
			DocumentKeyShadowRetrievalService::<TestRuntime>::retrieve(
				Origin::signed(REAL_REQUESTER1),
				[32; 32].into(),
				REAL_REQUESTER1_PUBLIC.into(),
			).unwrap();

			// receive same response from 50%+1 servers
			let events_count = frame_system::Module::<TestRuntime>::events().len();
			DocumentKeyShadowRetrievalService::<TestRuntime>::on_common_retrieved(
				Origin::signed(KEY_SERVER0),
				[32; 32].into(),
				REAL_REQUESTER1_ADDRESS.into(),
				[21; 64].into(),
				2,
			).unwrap();
			DocumentKeyShadowRetrievalService::<TestRuntime>::on_common_retrieved(
				Origin::signed(KEY_SERVER1),
				[32; 32].into(),
				REAL_REQUESTER1_ADDRESS.into(),
				[21; 64].into(),
				2,
			).unwrap();
			assert_eq!(
				events_count,
				frame_system::Module::<TestRuntime>::events().len(),
			);
			DocumentKeyShadowRetrievalService::<TestRuntime>::on_common_retrieved(
				Origin::signed(KEY_SERVER2),
				[32; 32].into(),
				REAL_REQUESTER1_ADDRESS.into(),
				[21; 64].into(),
				2,
			).unwrap();

			// check that common data is published and personal data retrieval is requested
			assert_eq!(
				events_count + 2,
				frame_system::Module::<TestRuntime>::events().len(),
			);
			assert!(
				frame_system::Module::<TestRuntime>::events().into_iter()
					.find(|e| e.event == Event::DocumentKeyCommonRetrieved(
						[32; 32].into(),
						REAL_REQUESTER1_ADDRESS.into(),
						[21; 64].into(),
						2,
					).into())
					.is_some(),
			);
			assert!(
				frame_system::Module::<TestRuntime>::events().into_iter()
					.find(|e| e.event == Event::DocumentKeyPersonalRetrievalRequested(
						[32; 32].into(),
						REAL_REQUESTER1_PUBLIC.into(),
					).into())
					.is_some(),
			);

			// now respond with personal data (we need 2+1 responses)
			let events_count = frame_system::Module::<TestRuntime>::events().len();
			DocumentKeyShadowRetrievalService::<TestRuntime>::on_personal_retrieved(
				Origin::signed(KEY_SERVER0),
				[32; 32].into(),
				REAL_REQUESTER1_ADDRESS.into(),
				KeyServersMask::from_index(0)
					.union(KeyServersMask::from_index(1))
					.union(KeyServersMask::from_index(2)),
				[63; 64].into(),
				vec![10],
			).unwrap();
			DocumentKeyShadowRetrievalService::<TestRuntime>::on_personal_retrieved(
				Origin::signed(KEY_SERVER1),
				[32; 32].into(),
				REAL_REQUESTER1_ADDRESS.into(),
				KeyServersMask::from_index(0)
					.union(KeyServersMask::from_index(1))
					.union(KeyServersMask::from_index(2)),
				[63; 64].into(),
				vec![11],
			).unwrap();
			DocumentKeyShadowRetrievalService::<TestRuntime>::on_personal_retrieved(
				Origin::signed(KEY_SERVER2),
				[32; 32].into(),
				REAL_REQUESTER1_ADDRESS.into(),
				KeyServersMask::from_index(0)
					.union(KeyServersMask::from_index(1))
					.union(KeyServersMask::from_index(2)),
				[63; 64].into(),
				vec![12],
			).unwrap();

			// ensure that everything required has been published
			assert_eq!(
				events_count + 3,
				frame_system::Module::<TestRuntime>::events().len(),
			);
			assert!(
				frame_system::Module::<TestRuntime>::events().into_iter()
					.find(|e| e.event == Event::DocumentKeyPersonalRetrieved(
						[32; 32].into(),
						REAL_REQUESTER1_ADDRESS.into(),
						[63; 64].into(),
						vec![10],
					).into())
					.is_some(),
			);
			assert!(
				frame_system::Module::<TestRuntime>::events().into_iter()
					.find(|e| e.event == Event::DocumentKeyPersonalRetrieved(
						[32; 32].into(),
						REAL_REQUESTER1_ADDRESS.into(),
						[63; 64].into(),
						vec![11],
					).into())
					.is_some(),
			);
			assert!(
				frame_system::Module::<TestRuntime>::events().into_iter()
					.find(|e| e.event == Event::DocumentKeyPersonalRetrieved(
						[32; 32].into(),
						REAL_REQUESTER1_ADDRESS.into(),
						[63; 64].into(),
						vec![12],
					).into())
					.is_some(),
			);

			// ensure that everything is purged from the storage
			ensure_clean_storage([32; 32].into(), REAL_REQUESTER1_ADDRESS.into());
		});
	}
}
