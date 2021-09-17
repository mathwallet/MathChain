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
//! for server key retrieval.

use codec::{Encode, Decode};
use frame_support::{StorageValue, StorageMap, StorageDoubleMap, ensure};
use primitives::{KeyServerId, ServerKeyId};
use frame_system::ensure_signed;
use crate::service::{Responses, ResponseSupport, SecretStoreService};
use super::{
	Config, Module, Event,
	ServerKeyRetrievalFee,
	ServerKeyRetrievalRequests, ServerKeyRetrievalRequestsKeys,
	ServerKeyRetrievalResponses, ServerKeyRetrievalThresholdResponses,
};

/// Maximal number of active requests in the queue.
const MAX_REQUESTS: u64 = 8;

/// Invalid threshold.
const INVALID_THRESHOLD: u8 = 0xFF;

/// Structure that describes server key retrieval request with responses meta.
#[derive(Decode, Encode)]
pub struct ServerKeyRetrievalRequest<Number> {
	/// Threshold responses metadata.
	pub threshold_responses: Responses<Number>,
	/// Responses metadata.
	pub responses: Responses<Number>,
	/// Retrieved server key public with max support.
	pub server_key_with_max_threshold: sp_core::H512,
}

/// Implementation of server key retrieval service.
pub struct ServerKeyRetrievalService<T>(sp_std::marker::PhantomData<T>);

impl<T: Config> ServerKeyRetrievalService<T> {
	/// Request new server key retrieval. Retrieved key will be published via ServerKeyRetrieved event when available.
	pub fn retrieve(
		origin: T::Origin,
		id: ServerKeyId,
	) -> Result<(), &'static str> {
		// limit number of requests in the queue
		ensure!(
			(ServerKeyRetrievalRequestsKeys::decode_len().unwrap_or(0) as u64) < MAX_REQUESTS,
			"Too many active requests. Try later",
		);

		// check if there are no pending request for the same key
		ensure!(
			!ServerKeyRetrievalRequests::<T>::contains_key(id),
			"The same request is already queued",
		);

		// collect service fee
		let origin = ensure_signed(origin)?;
		let fee = ServerKeyRetrievalFee::<T>::get();
		SecretStoreService::<T>::collect_service_fee(&origin, fee)?;

		// we do not know exact threshold value here && we can not blindly trust the first response
		// => we should agree upon two values: threshold && server key itself
		// => assuming that all authorities will eventually respond with value/error, we will wait for:
		// 1) at least 50% + 1 authorities agreement on the same threshold value
		// 2) after threshold is agreed, we will wait for threshold + 1 values of server key

		let request = ServerKeyRetrievalRequest {
			threshold_responses: SecretStoreService::<T>::new_responses(),
			responses: SecretStoreService::<T>::new_responses(),
			server_key_with_max_threshold: Default::default(),
		};
		ServerKeyRetrievalRequests::<T>::insert(id, request);
		ServerKeyRetrievalRequestsKeys::append(&id);

		// emit event
		Module::<T>::deposit_event(Event::ServerKeyRetrievalRequested(id));

		Ok(())
	}

	/// Called when retrieval is reported by key server.
	pub fn on_retrieved(
		origin: T::Origin,
		id: ServerKeyId,
		server_key_public: sp_core::H512,
		threshold: u8,
	) -> Result<(), &'static str> {
		// check if this request is active (the tx could arrive when request is already inactive)
		let request = match ServerKeyRetrievalRequests::<T>::get(id) {
			Some(request) => request,
			None => return Ok(()),
		};

		// insert response
		let (request, response_support, final_server_key_public) = Self::insert_response(
			origin,
			id,
			request,
			server_key_public,
			threshold,
		)?;

		// check if response is confirmed
		match response_support {
			ResponseSupport::Unconfirmed => {
				ServerKeyRetrievalRequests::<T>::insert(id, request);
			},
			ResponseSupport::Confirmed => {
				// we do not need this request anymore
				delete_request::<T>(&id);

				// emit event
				Module::<T>::deposit_event(Event::ServerKeyRetrieved(id, final_server_key_public));
			},
			ResponseSupport::Impossible => {
				// we do not need this request anymore
				delete_request::<T>(&id);

				// emit event
				Module::<T>::deposit_event(Event::ServerKeyRetrievalError(id));
			},
		}

		Ok(())
	}

	/// Called when error occurs during server key retrieval.
	pub fn on_retrieval_error(
		origin: T::Origin,
		id: ServerKeyId,
	) -> Result<(), &'static str> {
		// check if this request is active (the tx could arrive when request is already inactive)
		let request = match ServerKeyRetrievalRequests::<T>::get(id) {
			Some(request) => request,
			None => return Ok(()),
		};

		// all key servers in SS with auto-migration enabled should have a share for every key
		// => we could make an error fatal, but let's tolerate such issues
		// => insert invalid response and check if there are enough confirmations
		let (request, response_support, _) = Self::insert_response(
			origin,
			id,
			request,
			Default::default(),
			0xFF,
		)?;

		// check if response is confirmed
		match response_support {
			ResponseSupport::Unconfirmed => {
				ServerKeyRetrievalRequests::<T>::insert(id, request);
			},
			ResponseSupport::Confirmed | ResponseSupport::Impossible => {
				// we do not need this request anymore
				delete_request::<T>(&id);

				// emit event
				Module::<T>::deposit_event(Event::ServerKeyRetrievalError(id));
			},
		}

		Ok(())
	}

	/// Returns true if response from given key server is required to complete request.
	pub fn is_response_required(
		key_server: KeyServerId,
		id: ServerKeyId,
	) -> bool {
		ServerKeyRetrievalRequests::<T>::get(&id)
			.map(|request| SecretStoreService::<T>::is_response_required(
				key_server,
				&request.threshold_responses,
			))
			.unwrap_or(false)
	}

	/// Insert server key retrieval response (either successful or not).
	fn insert_response(
		origin: T::Origin,
		id: ServerKeyId,
		mut request: ServerKeyRetrievalRequest<<T as frame_system::Config>::BlockNumber>,
		server_key_public: sp_core::H512,
		threshold: u8,
	) -> Result<(
		ServerKeyRetrievalRequest<<T as frame_system::Config>::BlockNumber>,
		ResponseSupport,
		sp_core::H512
	), &'static str> {
		// insert threshold response
		let key_servers_count = SecretStoreService::<T>::key_servers_count()?;
		let key_server_index = SecretStoreService::<T>::key_server_index_from_origin(origin)?;
		let threshold_support = SecretStoreService::<T>::insert_response::<_, _, ServerKeyRetrievalThresholdResponses>(
			key_server_index,
			key_servers_count / 2,
			&mut request.threshold_responses,
			&id,
			&threshold,
		)?;
		if threshold_support == ResponseSupport::Impossible {
			return Ok((request, threshold_support, server_key_public));
		}

		// insert server key public response
		let key_support = SecretStoreService::<T>::insert_response::<_, _, ServerKeyRetrievalResponses>(
			key_server_index,
			threshold,
			&mut request.responses,
			&id,
			&server_key_public,
		)?;
		if threshold_support == ResponseSupport::Unconfirmed {
			// even though threshold is not yet confirmed, we might want to remember public
			// to return it in future
			if threshold != INVALID_THRESHOLD &&
				request.responses.max_response_support == ServerKeyRetrievalResponses::get(&id, &server_key_public) {
				request.server_key_with_max_threshold = server_key_public.clone();
			}

			return Ok((request, ResponseSupport::Unconfirmed, server_key_public));
		}
		if key_support == ResponseSupport::Unconfirmed {
			// threshold is confirmed and response is unconfirmed
			// => we might want to check if some other public has enough confirmations already
			if request.responses.max_response_support >= threshold + 1 {
				let final_server_key_public = request.server_key_with_max_threshold.clone();
				return Ok((request, ResponseSupport::Confirmed, final_server_key_public));
			}
		}

		Ok((request, key_support, server_key_public))
	}
}

/// Deletes request and all associated data.
fn delete_request<T: Config>(request: &ServerKeyId) {
	ServerKeyRetrievalResponses::remove_prefix(request, None);
	ServerKeyRetrievalThresholdResponses::remove_prefix(request, None);
	ServerKeyRetrievalRequests::<T>::remove(request);
	ServerKeyRetrievalRequestsKeys::mutate(|list| {
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
		assert_eq!(ServerKeyRetrievalRequestsKeys::get(), vec![]);
		assert!(!ServerKeyRetrievalRequests::<TestRuntime>::contains_key(key));
		assert_eq!(
			ServerKeyRetrievalResponses::iter_prefix(key).collect::<Vec<_>>(),
			vec![],
		);
		assert_eq!(
			ServerKeyRetrievalThresholdResponses::iter_prefix(key).collect::<Vec<_>>(),
			vec![],
		);
	}

	#[test]
	fn should_accept_server_key_retrieval_request() {
		default_initialization_with_five_servers().execute_with(|| {
			// ask to retrieve server key
			ServerKeyRetrievalService::<TestRuntime>::retrieve(
				Origin::signed(REQUESTER1),
				[32; 32].into(),
			).unwrap();

			// check that event has been emitted
			assert!(
				frame_system::Module::<TestRuntime>::events().into_iter()
					.find(|e| e.event == Event::ServerKeyRetrievalRequested([32; 32].into()).into())
					.is_some(),
			);
		});
	}

	#[test]
	fn should_reject_server_key_retrieval_request_when_fee_is_not_paid() {
		default_initialization_with_five_servers().execute_with(|| {
			// ask to retrieve server key
			ServerKeyRetrievalService::<TestRuntime>::retrieve(
				Origin::signed(REQUESTER2),
				[32; 32].into(),
			).unwrap_err();

			ensure_clean_storage([32; 32].into());
		});
	}

	#[test]
	fn should_reject_server_key_retrieval_request_when_limit_reached() {
		default_initialization_with_five_servers().execute_with(|| {
			// make MAX_REQUESTS requests
			for i in 0..MAX_REQUESTS {
				ServerKeyRetrievalService::<TestRuntime>::retrieve(
					Origin::signed(REQUESTER1),
					[i as u8; 32].into(),
				).unwrap();
			}

			// and now try to push new request so that there will be more than a limit requests
			ServerKeyRetrievalService::<TestRuntime>::retrieve(
				Origin::signed(REQUESTER1),
				[MAX_REQUESTS as u8; 32].into(),
			).unwrap_err();
		});
	}

	#[test]
	fn should_reject_duplicated_server_key_retrieval_request() {
		default_initialization_with_five_servers().execute_with(|| {
			// ask to retrieve server key
			ServerKeyRetrievalService::<TestRuntime>::retrieve(
				Origin::signed(REQUESTER1),
				[32; 32].into(),
			).unwrap();

			// ask to retrieve server key
			ServerKeyRetrievalService::<TestRuntime>::retrieve(
				Origin::signed(REQUESTER1),
				[32; 32].into(),
			).unwrap_err();
		});
	}

	#[test]
	fn should_publish_server_key_when_all_servers_respond_with_the_same_value() {
		default_initialization_with_five_servers().execute_with(|| {
			// ask to retrieve server key
			ServerKeyRetrievalService::<TestRuntime>::retrieve(
				Origin::signed(REQUESTER1),
				[32; 32].into(),
			).unwrap();

			// 3-of-5 servers are required to respond with the same threshold value:
			// 1) 3-of-5 servers are responding with the same threshold value
			// 2) by that time last response already have support of 3 (when only 2 is required) => retrieved
			let events_count = frame_system::Module::<TestRuntime>::events().len();
			ServerKeyRetrievalService::<TestRuntime>::on_retrieved(
				Origin::signed(KEY_SERVER0),
				[32; 32].into(),
				[42; 64].into(),
				1,
			).unwrap();
			ServerKeyRetrievalService::<TestRuntime>::on_retrieved(
				Origin::signed(KEY_SERVER1),
				[32; 32].into(),
				[42; 64].into(),
				1,
			).unwrap();
			assert_eq!(
				events_count,
				frame_system::Module::<TestRuntime>::events().len(),
			);
			ServerKeyRetrievalService::<TestRuntime>::on_retrieved(
				Origin::signed(KEY_SERVER2),
				[32; 32].into(),
				[42; 64].into(),
				1,
			).unwrap();

			// check that event has been emitted
			assert_eq!(
				events_count + 1,
				frame_system::Module::<TestRuntime>::events().len(),
			);
			assert!(
				frame_system::Module::<TestRuntime>::events().into_iter()
					.find(|e| e.event == Event::ServerKeyRetrieved([32; 32].into(), [42; 64].into()).into())
					.is_some(),
			);

			ensure_clean_storage([32; 32].into());
		});
	}

	#[test]
	fn should_publish_server_key_when_some_servers_respond_with_different_key_value() {
		default_initialization_with_five_servers().execute_with(|| {
			// ask to retrieve server key
			ServerKeyRetrievalService::<TestRuntime>::retrieve(
				Origin::signed(REQUESTER1),
				[32; 32].into(),
			).unwrap();

			// 3-of-5 servers are required to respond with the same threshold value:
			// 1) KS1 responds with (P1, 3). 3-threshold support is 1
			// 2) KS2 responds with (P2, 3). 3-threshold support is 2
			// 3) KS3 responds with (P1, 3). 3-threshold support is 3 => threshold is 3. (P1, 3) support is 2
			// 4) KS4 responds with (P1, 3). (P1, 3) support is 3
			// 5) KS5 responds with (P1, 3). (P1, 3) support is 4
			let events_count = frame_system::Module::<TestRuntime>::events().len();
			ServerKeyRetrievalService::<TestRuntime>::on_retrieved(
				Origin::signed(KEY_SERVER0),
				[32; 32].into(),
				[42; 64].into(),
				3,
			).unwrap();
			ServerKeyRetrievalService::<TestRuntime>::on_retrieved(
				Origin::signed(KEY_SERVER1),
				[32; 32].into(),
				[43; 64].into(), // 'wrong' value
				3,
			).unwrap();
			ServerKeyRetrievalService::<TestRuntime>::on_retrieved(
				Origin::signed(KEY_SERVER2),
				[32; 32].into(),
				[42; 64].into(),
				3,
			).unwrap();
			ServerKeyRetrievalService::<TestRuntime>::on_retrieved(
				Origin::signed(KEY_SERVER3),
				[32; 32].into(),
				[42; 64].into(),
				3,
			).unwrap();
			assert_eq!(
				events_count,
				frame_system::Module::<TestRuntime>::events().len(),
			);
			ServerKeyRetrievalService::<TestRuntime>::on_retrieved(
				Origin::signed(KEY_SERVER4),
				[32; 32].into(),
				[42; 64].into(),
				3,
			).unwrap();

			// check that event has been emitted
			assert_eq!(
				events_count + 1,
				frame_system::Module::<TestRuntime>::events().len(),
			);
			assert!(
				frame_system::Module::<TestRuntime>::events().into_iter()
					.find(|e| e.event == Event::ServerKeyRetrieved([32; 32].into(), [42; 64].into()).into())
					.is_some(),
			);

			ensure_clean_storage([32; 32].into());
		});
	}

	#[test]
	fn should_publish_server_key_when_some_servers_respond_with_different_threshold_value() {
		default_initialization_with_five_servers().execute_with(|| {
			// ask to retrieve server key
			ServerKeyRetrievalService::<TestRuntime>::retrieve(
				Origin::signed(REQUESTER1),
				[32; 32].into(),
			).unwrap();

			// 3-of-5 servers are required to respond with the same threshold value:
			// 1) KS1 responds with (P1, 3). 3-threshold support is 1
			// 2) KS2 responds with (P1, 10). 3-threshold support is 1
			// 3) KS3 responds with (P1, 3). 3-threshold support is 2
			// 4) KS4 responds with (P1, 3). (P1, 3) support is 3 => threshold is 3. (P1, 3) support is 3
			// 5) KS5 responds with (P1, 3). (P1, 3) support is 4
			let events_count = frame_system::Module::<TestRuntime>::events().len();
			ServerKeyRetrievalService::<TestRuntime>::on_retrieved(
				Origin::signed(KEY_SERVER0),
				[32; 32].into(),
				[42; 64].into(),
				3,
			).unwrap();
			ServerKeyRetrievalService::<TestRuntime>::on_retrieved(
				Origin::signed(KEY_SERVER1),
				[32; 32].into(),
				[42; 64].into(),
				10, // 'wrong' threshold
			).unwrap();
			ServerKeyRetrievalService::<TestRuntime>::on_retrieved(
				Origin::signed(KEY_SERVER2),
				[32; 32].into(),
				[42; 64].into(),
				3,
			).unwrap();
			assert_eq!(
				events_count,
				frame_system::Module::<TestRuntime>::events().len(),
			);
			ServerKeyRetrievalService::<TestRuntime>::on_retrieved(
				Origin::signed(KEY_SERVER3),
				[32; 32].into(),
				[42; 64].into(),
				3,
			).unwrap();

			// check that event has been emitted
			assert_eq!(
				events_count + 1,
				frame_system::Module::<TestRuntime>::events().len(),
			);
			assert!(
				frame_system::Module::<TestRuntime>::events().into_iter()
					.find(|e| e.event == Event::ServerKeyRetrieved([32; 32].into(), [42; 64].into()).into())
					.is_some(),
			);

			ensure_clean_storage([32; 32].into());
		});
	}

	#[test]
	fn should_publish_server_key_if_key_stabilized_before_threshold() {
		default_initialization_with_five_servers().execute_with(|| {
			// ask to retrieve server key
			ServerKeyRetrievalService::<TestRuntime>::retrieve(
				Origin::signed(REQUESTER1),
				[32; 32].into(),
			).unwrap();

			// 3-of-5 servers are required to respond with the same threshold value:
			// 1) KS1 responds with (P1, 1). 1-threshold support is 1
			// 2) KS2 responds with (P1, 1). 1-threshold support is 2. (P1, 1) support is 2, enough for 1-threshold
			// 3) KS3 responds with (P2, 1). 1-threshold support is 3 => threshold is 1. P1 already has enough
			//    support && we publish it
			//  even though KS3 has responded with P2 && at the end P2 could end having more confirmations than P1
			let events_count = frame_system::Module::<TestRuntime>::events().len();
			ServerKeyRetrievalService::<TestRuntime>::on_retrieved(
				Origin::signed(KEY_SERVER0),
				[32; 32].into(),
				[42; 64].into(),
				1,
			).unwrap();
			ServerKeyRetrievalService::<TestRuntime>::on_retrieved(
				Origin::signed(KEY_SERVER1),
				[32; 32].into(),
				[42; 64].into(),
				1,
			).unwrap();
			assert_eq!(
				events_count,
				frame_system::Module::<TestRuntime>::events().len(),
			);
			ServerKeyRetrievalService::<TestRuntime>::on_retrieved(
				Origin::signed(KEY_SERVER2),
				[32; 32].into(),
				[43; 64].into(), // 'wrong' value
				1,
			).unwrap();

			// check that event has been emitted
			assert_eq!(
				events_count + 1,
				frame_system::Module::<TestRuntime>::events().len(),
			);
			assert!(
				frame_system::Module::<TestRuntime>::events().into_iter()
					.find(|e| e.event == Event::ServerKeyRetrieved([32; 32].into(), [42; 64].into()).into())
					.is_some(),
			);

			ensure_clean_storage([32; 32].into());
		});
	}

	#[test]
	fn should_ignore_response_if_sent_twice() {
		default_initialization_with_five_servers().execute_with(|| {
			// ask to retrieve server key
			ServerKeyRetrievalService::<TestRuntime>::retrieve(
				Origin::signed(REQUESTER1),
				[32; 32].into(),
			).unwrap();

			// 3-of-5 servers are required to respond with the same threshold value
			// => let's check if 3 responses from single server won't work
			let events_count = frame_system::Module::<TestRuntime>::events().len();
			ServerKeyRetrievalService::<TestRuntime>::on_retrieved(
				Origin::signed(KEY_SERVER0),
				[32; 32].into(),
				[42; 64].into(),
				1,
			).unwrap();
			ServerKeyRetrievalService::<TestRuntime>::on_retrieved(
				Origin::signed(KEY_SERVER0),
				[32; 32].into(),
				[42; 64].into(),
				1,
			).unwrap();
			ServerKeyRetrievalService::<TestRuntime>::on_retrieved(
				Origin::signed(KEY_SERVER0),
				[32; 32].into(),
				[42; 64].into(),
				1,
			).unwrap();

			// check that no events have been emitted
			assert_eq!(
				events_count,
				frame_system::Module::<TestRuntime>::events().len(),
			);
		});
	}

	#[test]
	fn should_raise_retrieval_error_if_many_servers_responded_with_different_key_before_threshold_stabilization() {
		default_initialization_with_five_servers().execute_with(|| {
			// ask to retrieve server key
			ServerKeyRetrievalService::<TestRuntime>::retrieve(
				Origin::signed(REQUESTER1),
				[32; 32].into(),
			).unwrap();

			// 3-of-5 servers are required to respond with the same threshold value:
			// 1) KS1 responds with (P1, 3). 3-threshold support is 1
			// 2) KS2 responds with (P2, 3). 3-threshold support is 2
			// 3) KS3 responds with (P3, 3). 3-threshold support is 3 => threshold is 3
			//    => we need 4 nodes to agree upon same public value
			//   => max public support is 1 and there are only 2 nodes left to vote => agreement is impossible
			let events_count = frame_system::Module::<TestRuntime>::events().len();
			ServerKeyRetrievalService::<TestRuntime>::on_retrieved(
				Origin::signed(KEY_SERVER0),
				[32; 32].into(),
				[42; 64].into(),
				3,
			).unwrap();
			ServerKeyRetrievalService::<TestRuntime>::on_retrieved(
				Origin::signed(KEY_SERVER1),
				[32; 32].into(),
				[43; 64].into(),
				3,
			).unwrap();
			assert_eq!(
				events_count,
				frame_system::Module::<TestRuntime>::events().len(),
			);
			ServerKeyRetrievalService::<TestRuntime>::on_retrieved(
				Origin::signed(KEY_SERVER2),
				[32; 32].into(),
				[44; 64].into(),
				3,
			).unwrap();

			// check that event has been emitted
			assert_eq!(
				events_count + 1,
				frame_system::Module::<TestRuntime>::events().len(),
			);
			assert!(
				frame_system::Module::<TestRuntime>::events().into_iter()
					.find(|e| e.event == Event::ServerKeyRetrievalError([32; 32].into()).into())
					.is_some(),
			);

			ensure_clean_storage([32; 32].into());
		});
	}

	#[test]
	fn should_raise_retrieval_error_if_many_servers_responded_with_different_key_after_threshold_stabilization() {
		default_initialization_with_five_servers().execute_with(|| {
			// ask to retrieve server key
			ServerKeyRetrievalService::<TestRuntime>::retrieve(
				Origin::signed(REQUESTER1),
				[32; 32].into(),
			).unwrap();

			// 3-of-5 servers are required to respond with the same threshold value:
			// 1) KS1 responds with (P1, 2). 2-threshold support is 1
			// 2) KS2 responds with (P2, 2). 2-threshold support is 2
			// 3) KS3 responds with (P3, 2). 2-threshold support is 3 => threshold is 2
			//    => we need 3 nodes to agree upon same public value
			// 4) KS4 responds with (P4, 2). max public support is 1 and there are only 1 node left to vote\
			//    => agreement is impossible
			let events_count = frame_system::Module::<TestRuntime>::events().len();
			ServerKeyRetrievalService::<TestRuntime>::on_retrieved(
				Origin::signed(KEY_SERVER0),
				[32; 32].into(),
				[42; 64].into(),
				2,
			).unwrap();
			ServerKeyRetrievalService::<TestRuntime>::on_retrieved(
				Origin::signed(KEY_SERVER1),
				[32; 32].into(),
				[43; 64].into(),
				2,
			).unwrap();
			ServerKeyRetrievalService::<TestRuntime>::on_retrieved(
				Origin::signed(KEY_SERVER2),
				[32; 32].into(),
				[44; 64].into(),
				2,
			).unwrap();
			assert_eq!(
				events_count,
				frame_system::Module::<TestRuntime>::events().len(),
			);
			ServerKeyRetrievalService::<TestRuntime>::on_retrieved(
				Origin::signed(KEY_SERVER3),
				[32; 32].into(),
				[45; 64].into(),
				2,
			).unwrap();

			// check that event has been emitted
			assert_eq!(
				events_count + 1,
				frame_system::Module::<TestRuntime>::events().len(),
			);
			assert!(
				frame_system::Module::<TestRuntime>::events().into_iter()
					.find(|e| e.event == Event::ServerKeyRetrievalError([32; 32].into()).into())
					.is_some(),
			);

			ensure_clean_storage([32; 32].into());
		});
	}

	#[test]
	fn should_raise_retrieval_error_if_many_servers_responded_with_different_threshold_values() {
		default_initialization_with_five_servers().execute_with(|| {
			// ask to retrieve server key
			ServerKeyRetrievalService::<TestRuntime>::retrieve(
				Origin::signed(REQUESTER1),
				[32; 32].into(),
			).unwrap();

			// 3-of-5 servers are required to respond with the same threshold value:
			// 1) KS1 responds with (P1, 1). 2-threshold support is 1
			// 2) KS2 responds with (P1, 2). 2-threshold support is 2
			// 3) KS3 responds with (P1, 3). 2-threshold support is 3 => threshold is 2
			//    => we need 3 nodes to agree upon same public value
			// 4) KS4 responds with (P1, 4). max threshold support is 1 and there is only 1 node left to vote
			//    => threshold agreement is impossible
			let events_count = frame_system::Module::<TestRuntime>::events().len();
			ServerKeyRetrievalService::<TestRuntime>::on_retrieved(
				Origin::signed(KEY_SERVER0),
				[32; 32].into(),
				[42; 64].into(),
				1,
			).unwrap();
			ServerKeyRetrievalService::<TestRuntime>::on_retrieved(
				Origin::signed(KEY_SERVER1),
				[32; 32].into(),
				[42; 64].into(),
				2,
			).unwrap();
			ServerKeyRetrievalService::<TestRuntime>::on_retrieved(
				Origin::signed(KEY_SERVER2),
				[32; 32].into(),
				[42; 64].into(),
				3,
			).unwrap();
			assert_eq!(
				events_count,
				frame_system::Module::<TestRuntime>::events().len(),
			);
			ServerKeyRetrievalService::<TestRuntime>::on_retrieved(
				Origin::signed(KEY_SERVER3),
				[32; 32].into(),
				[42; 64].into(),
				4,
			).unwrap();

			// check that event has been emitted
			assert_eq!(
				events_count + 1,
				frame_system::Module::<TestRuntime>::events().len(),
			);
			assert!(
				frame_system::Module::<TestRuntime>::events().into_iter()
					.find(|e| e.event == Event::ServerKeyRetrievalError([32; 32].into()).into())
					.is_some(),
			);

			ensure_clean_storage([32; 32].into());
		});
	}

	#[test]
	fn should_ignore_response_if_there_are_no_active_request() {
		default_initialization_with_five_servers().execute_with(|| {
			ServerKeyRetrievalService::<TestRuntime>::on_retrieved(
				Origin::signed(KEY_SERVER0),
				[32; 32].into(),
				[42; 64].into(),
				1,
			).unwrap();
		});
	}

	#[test]
	fn should_ignore_error_if_there_are_no_active_request() {
		default_initialization_with_five_servers().execute_with(|| {
			ServerKeyRetrievalService::<TestRuntime>::on_retrieval_error(
				Origin::signed(KEY_SERVER0),
				[32; 32].into(),
			).unwrap();
		});
	}

	#[test]
	fn fail_if_response_is_not_from_a_key_server() {
		default_initialization_with_five_servers().execute_with(|| {
			// ask to retrieve server key
			ServerKeyRetrievalService::<TestRuntime>::retrieve(
				Origin::signed(REQUESTER1),
				[32; 32].into(),
			).unwrap();

			ServerKeyRetrievalService::<TestRuntime>::on_retrieved(
				Origin::signed(REQUESTER1),
				[32; 32].into(),
				[42; 64].into(),
				1,
			).unwrap_err();
		});
	}

	#[test]
	fn fail_if_error_is_not_from_a_key_server() {
		default_initialization_with_five_servers().execute_with(|| {
			// ask to retrieve server key
			ServerKeyRetrievalService::<TestRuntime>::retrieve(
				Origin::signed(REQUESTER1),
				[32; 32].into(),
			).unwrap();

			ServerKeyRetrievalService::<TestRuntime>::on_retrieval_error(
				Origin::signed(REQUESTER1),
				[32; 32].into(),
			).unwrap_err();
		});
	}

	#[test]
	fn should_raise_retrieval_error_if_many_servers_repoted_error() {
		default_initialization_with_five_servers().execute_with(|| {
			// ask to retrieve server key
			ServerKeyRetrievalService::<TestRuntime>::retrieve(
				Origin::signed(REQUESTER1),
				[32; 32].into(),
			).unwrap();

			// receive errors from 3-of-5 servers (> 50%)
			let events_count = frame_system::Module::<TestRuntime>::events().len();
			ServerKeyRetrievalService::<TestRuntime>::on_retrieval_error(
				Origin::signed(KEY_SERVER0),
				[32; 32].into(),
			).unwrap();
			ServerKeyRetrievalService::<TestRuntime>::on_retrieval_error(
				Origin::signed(KEY_SERVER1),
				[32; 32].into(),
			).unwrap();
			assert_eq!(
				events_count,
				frame_system::Module::<TestRuntime>::events().len(),
			);
			ServerKeyRetrievalService::<TestRuntime>::on_retrieval_error(
				Origin::signed(KEY_SERVER2),
				[32; 32].into(),
			).unwrap();

			// check that event has been emitted
			assert_eq!(
				events_count + 1,
				frame_system::Module::<TestRuntime>::events().len(),
			);
			assert!(
				frame_system::Module::<TestRuntime>::events().into_iter()
					.find(|e| e.event == Event::ServerKeyRetrievalError([32; 32].into()).into())
					.is_some(),
			);

			ensure_clean_storage([32; 32].into());
		});
	}

	#[test]
	fn should_publish_server_key_if_some_servers_responded_with_error() {
		default_initialization_with_five_servers().execute_with(|| {
			// ask to retrieve server key
			ServerKeyRetrievalService::<TestRuntime>::retrieve(
				Origin::signed(REQUESTER1),
				[32; 32].into(),
			).unwrap();

			let events_count = frame_system::Module::<TestRuntime>::events().len();
			ServerKeyRetrievalService::<TestRuntime>::on_retrieved(
				Origin::signed(KEY_SERVER0),
				[32; 32].into(),
				[42; 64].into(),
				1,
			).unwrap();
			ServerKeyRetrievalService::<TestRuntime>::on_retrieval_error(
				Origin::signed(KEY_SERVER1),
				[32; 32].into(),
			).unwrap();
			ServerKeyRetrievalService::<TestRuntime>::on_retrieved(
				Origin::signed(KEY_SERVER2),
				[32; 32].into(),
				[42; 64].into(),
				1,
			).unwrap();
			ServerKeyRetrievalService::<TestRuntime>::on_retrieval_error(
				Origin::signed(KEY_SERVER3),
				[32; 32].into(),
			).unwrap();
			assert_eq!(
				events_count,
				frame_system::Module::<TestRuntime>::events().len(),
			);
			ServerKeyRetrievalService::<TestRuntime>::on_retrieved(
				Origin::signed(KEY_SERVER4),
				[32; 32].into(),
				[43; 64].into(),
				1,
			).unwrap();

			// check that event has been emitted
			assert_eq!(
				events_count + 1,
				frame_system::Module::<TestRuntime>::events().len(),
			);
			assert!(
				frame_system::Module::<TestRuntime>::events().into_iter()
					.find(|e| e.event == Event::ServerKeyRetrieved([32; 32].into(), [42; 64].into()).into())
					.is_some(),
			);

			ensure_clean_storage([32; 32].into());
		});
	}

	#[test]
	fn should_raise_retrieval_error_even_if_some_servers_responded() {
		default_initialization_with_five_servers().execute_with(|| {
			// ask to retrieve server key
			ServerKeyRetrievalService::<TestRuntime>::retrieve(
				Origin::signed(REQUESTER1),
				[32; 32].into(),
			).unwrap();

			let events_count = frame_system::Module::<TestRuntime>::events().len();
			ServerKeyRetrievalService::<TestRuntime>::on_retrieved(
				Origin::signed(KEY_SERVER0),
				[32; 32].into(),
				[42; 64].into(),
				4,
			).unwrap();
			ServerKeyRetrievalService::<TestRuntime>::on_retrieved(
				Origin::signed(KEY_SERVER1),
				[32; 32].into(),
				[42; 64].into(),
				4,
			).unwrap();
			ServerKeyRetrievalService::<TestRuntime>::on_retrieval_error(
				Origin::signed(KEY_SERVER2),
				[32; 32].into(),
			).unwrap();
			// possible optimization:
			// at this moment we already have (4-threshold support of 2) and (256-threshold support of 1)
			// => even though the rest of KS will resppnd with 4-threshold, we won't be able to agree
			// upon public because 1 node has failed to agree
			ServerKeyRetrievalService::<TestRuntime>::on_retrieval_error(
				Origin::signed(KEY_SERVER3),
				[32; 32].into(),
			).unwrap();
			assert_eq!(
				events_count,
				frame_system::Module::<TestRuntime>::events().len(),
			);
			ServerKeyRetrievalService::<TestRuntime>::on_retrieval_error(
				Origin::signed(KEY_SERVER4),
				[32; 32].into(),
			).unwrap();

			// check that event has been emitted
			assert_eq!(
				events_count + 1,
				frame_system::Module::<TestRuntime>::events().len(),
			);
			assert!(
				frame_system::Module::<TestRuntime>::events().into_iter()
					.find(|e| e.event == Event::ServerKeyRetrievalError([32; 32].into()).into())
					.is_some(),
			);

			ensure_clean_storage([32; 32].into());
		});
	}
}