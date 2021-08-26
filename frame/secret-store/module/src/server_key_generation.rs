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
//! for server key generation.

use codec::{Encode, Decode};
use frame_support::{StorageValue, StorageMap, StorageDoubleMap, ensure};
use primitives::{EntityId, ServerKeyId, KeyServerId};
use frame_system::ensure_signed;
use crate::service::{Responses, ResponseSupport, SecretStoreService};
use super::{
	Config, Module, Event,
	ServerKeyGenerationFee,
	ServerKeyGenerationRequests, ServerKeyGenerationRequestsKeys,
	ServerKeyGenerationResponses,
	resolve_entity_id,
};

/// Maximal number of active requests in the queue.
const MAX_REQUESTS: u64 = 4;

/// Structure that describes server key generation request with responses meta.
#[derive(Decode, Encode)]
pub struct ServerKeyGenerationRequest<Number> {
	/// The author of this request.
	pub author: EntityId,
	/// The threshold of the key we're generating.
	pub threshold: u8,
	/// Responses metadata.
	pub responses: Responses<Number>,
}

/// Implementation of server key generation service.
pub struct ServerKeyGenerationService<T>(sp_std::marker::PhantomData<T>);

impl<T: Config> ServerKeyGenerationService<T> {
	/// Request new server key generation. Generated key will be published via
	/// ServerKeyGenerated event when available.
	pub fn generate(
		origin: T::Origin,
		id: ServerKeyId,
		threshold: u8,
	) -> Result<(), &'static str> {
		// we can't process requests with invalid threshold
		let key_servers_count = SecretStoreService::<T>::key_servers_count()?;
		ensure!(
			threshold + 1 <= key_servers_count,
			"Invalid threshold has been passed",
		);

		// limit number of requests in the queue
		ensure!(
			(ServerKeyGenerationRequestsKeys::decode_len().unwrap_or(0) as u64) < MAX_REQUESTS,
			"Too many active requests. Try later",
		);

		// check if there are no pending request for the same key
		ensure!(
			!ServerKeyGenerationRequests::<T>::contains_key(id),
			"The same request is already queued",
		);

		// collect service fee
		let origin = ensure_signed(origin)?;
		let fee = ServerKeyGenerationFee::<T>::get();
		SecretStoreService::<T>::collect_service_fee(&origin, fee)?;

		// insert request to the queue
		let author = resolve_entity_id::<T>(&origin)?;
		let request = ServerKeyGenerationRequest {
			author,
			threshold,
			responses: SecretStoreService::<T>::new_responses(),
		};
		ServerKeyGenerationRequests::<T>::insert(id, request);
		ServerKeyGenerationRequestsKeys::append(&id);

		// emit event
		Module::<T>::deposit_event(Event::ServerKeyGenerationRequested(id, author, threshold));

		Ok(())
	}

	/// Called when generation is reported by key server.
	pub fn on_generated(
		origin: T::Origin,
		id: ServerKeyId,
		server_key_public: sp_core::H512,
	) -> Result<(), &'static str> {
		// check if this request is active (the tx could arrive when request is already inactive)
		let mut request = match ServerKeyGenerationRequests::<T>::get(id) {
			Some(request) => request,
			None => return Ok(()),
		};

		// insert response
		let key_servers_count = SecretStoreService::<T>::key_servers_count()?;
		let key_server_index = SecretStoreService::<T>::key_server_index_from_origin(origin)?;
		let response_support = SecretStoreService::<T>::insert_response::<_, _, ServerKeyGenerationResponses>(
			key_server_index,
			key_servers_count - 1,
			&mut request.responses,
			&id,
			&server_key_public,
		)?;

		// check if response is confirmed
		match response_support {
			ResponseSupport::Unconfirmed => {
				ServerKeyGenerationRequests::<T>::insert(id, request);
			},
			ResponseSupport::Confirmed => {
				// we do not need this request anymore
				delete_request::<T>(&id);

				// emit event
				Module::<T>::deposit_event(Event::ServerKeyGenerated(id, server_key_public));
			},
			ResponseSupport::Impossible => {
				// we do not need this request anymore
				delete_request::<T>(&id);

				// emit event
				Module::<T>::deposit_event(Event::ServerKeyGenerationError(id));
			},
		}

		Ok(())
	}

	/// Called when error occurs during server key generation.
	pub fn on_generation_error(
		origin: T::Origin,
		id: ServerKeyId,
	) -> Result<(), &'static str> {
		// check that it is reported by the key server
		let _ = SecretStoreService::<T>::key_server_index_from_origin(origin)?;

		// check if this request is active (the tx could arrive when request is already inactive)
		let _request = match ServerKeyGenerationRequests::<T>::get(id) {
			Some(request) => request,
			None => return Ok(()),
		};

		// any error in key generation is fatal, because we need all key servers to participate in generation
		// => delete request and fire event
		delete_request::<T>(&id);

		Module::<T>::deposit_event(Event::ServerKeyGenerationError(id));
		Ok(())
	}

	/// Returns true if response from given key server is required to complete request.
	pub fn is_response_required(
		key_server: KeyServerId,
		id: ServerKeyId,
	) -> bool {
		ServerKeyGenerationRequests::<T>::get(&id)
			.map(|request| SecretStoreService::<T>::is_response_required(
				key_server,
				&request.responses,
			))
			.unwrap_or(false)
	}
}

/// Deletes request and all associated data.
fn delete_request<T: Config>(request: &ServerKeyId) {
	ServerKeyGenerationResponses::remove_prefix(request);
	ServerKeyGenerationRequests::<T>::remove(request);
	ServerKeyGenerationRequestsKeys::mutate(|list| {
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
		assert_eq!(ServerKeyGenerationRequestsKeys::get(), vec![]);
		assert!(!ServerKeyGenerationRequests::<TestRuntime>::contains_key(key));
		assert_eq!(
			ServerKeyGenerationResponses::iter_prefix(key).collect::<Vec<_>>(),
			vec![],
		);
	}

	#[test]
	fn should_accept_server_key_generation_request() {
		default_initialization().execute_with(|| {
			// ask to generate server key
			ServerKeyGenerationService::<TestRuntime>::generate(
				Origin::signed(REQUESTER1),
				[32; 32].into(),
				1,
			).unwrap();

			// check that event has been emitted
			assert!(
				frame_system::Module::<TestRuntime>::events().into_iter()
					.find(|e| e.event == Event::ServerKeyGenerationRequested(
						[32; 32].into(),
						[REQUESTER1 as u8; 20].into(),
						1,
					).into())
					.is_some(),
			);
		});
	}

	#[test]
	fn should_reject_server_key_generation_request_when_fee_is_not_paid() {
		default_initialization().execute_with(|| {
			// REQUESTER2 has no enough funds
			ServerKeyGenerationService::<TestRuntime>::generate(
				Origin::signed(REQUESTER2),
				[32; 32].into(),
				1,
			).unwrap_err();

			ensure_clean_storage([32; 32].into());
		});
	}

	#[test]
	fn should_reject_server_key_generation_request_when_threshold_is_too_large() {
		default_initialization().execute_with(|| {
			// there are only two key servers => max threshold is 1
			ServerKeyGenerationService::<TestRuntime>::generate(
				Origin::signed(REQUESTER1),
				[32; 32].into(),
				2,
			).unwrap_err();
		});
	}

	#[test]
	fn should_reject_server_key_generation_request_when_limit_reached() {
		default_initialization().execute_with(|| {
			// make MAX_REQUESTS requests
			for i in 0..MAX_REQUESTS {
				ServerKeyGenerationService::<TestRuntime>::generate(
					Origin::signed(REQUESTER1),
					[i as u8; 32].into(),
					1,
				).unwrap();
			}

			// and now try to push new request so that there will be more than a limit requests
			ServerKeyGenerationService::<TestRuntime>::generate(
				Origin::signed(REQUESTER1),
				[MAX_REQUESTS as u8; 32].into(),
				1,
			).unwrap_err();
		});
	}

	#[test]
	fn should_reject_duplicated_server_key_generation_request() {
		default_initialization().execute_with(|| {
			// ask to generate server key
			ServerKeyGenerationService::<TestRuntime>::generate(
				Origin::signed(REQUESTER1),
				[32; 32].into(),
				1,
			).unwrap();

			// ask to generate server key
			ServerKeyGenerationService::<TestRuntime>::generate(
				Origin::signed(REQUESTER1),
				[32; 32].into(),
				1,
			).unwrap_err();
		});
	}

	#[test]
	fn should_publish_generated_server_key() {
		default_initialization().execute_with(|| {
			// ask to generate server key
			ServerKeyGenerationService::<TestRuntime>::generate(
				Origin::signed(REQUESTER1),
				[32; 32].into(),
				1,
			).unwrap();
			let events_count = frame_system::Module::<TestRuntime>::events().len();

			// response from key server 1 is received
			ServerKeyGenerationService::<TestRuntime>::on_generated(
				Origin::signed(KEY_SERVER0),
				[32; 32].into(),
				[42; 64].into(),
			).unwrap();
			// => no new events generated
			assert_eq!(
				events_count,
				frame_system::Module::<TestRuntime>::events().len(),
			);

			// response from key server 2 is received
			ServerKeyGenerationService::<TestRuntime>::on_generated(
				Origin::signed(KEY_SERVER1),
				[32; 32].into(),
				[42; 64].into(),
			).unwrap();
			// => new event is generated
			assert_eq!(
				events_count + 1,
				frame_system::Module::<TestRuntime>::events().len(),
			);
			assert!(
				frame_system::Module::<TestRuntime>::events().into_iter()
					.find(|e| e.event == Event::ServerKeyGenerated([32; 32].into(), [42; 64].into()).into())
					.is_some(),
			);

			// and then another response from key server 2 is received (and ignored without error)
			ServerKeyGenerationService::<TestRuntime>::on_generated(
				Origin::signed(KEY_SERVER1),
				[32; 32].into(),
				[42; 64].into(),
			).unwrap();

			ensure_clean_storage([32; 32].into());
		});
	}

	#[test]
	fn should_not_accept_generated_key_from_non_key_server() {
		default_initialization().execute_with(|| {
			// ask to generate server key
			ServerKeyGenerationService::<TestRuntime>::generate(
				Origin::signed(REQUESTER1),
				[32; 32].into(),
				0,
			).unwrap();

			// response from key server 1 is received
			ServerKeyGenerationService::<TestRuntime>::on_generated(
				Origin::signed(KEY_SERVER3),
				[32; 32].into(),
				[42; 64].into(),
			).unwrap_err();
		});
	}

	#[test]
	fn should_not_publish_generated_key_when_receiving_responses_from_same_key_server() {
		default_initialization().execute_with(|| {
			// ask to generate server key
			ServerKeyGenerationService::<TestRuntime>::generate(
				Origin::signed(REQUESTER1),
				[32; 32].into(),
				1,
			).unwrap();
			let events_count = frame_system::Module::<TestRuntime>::events().len();

			// response from key server 1 is received
			ServerKeyGenerationService::<TestRuntime>::on_generated(
				Origin::signed(KEY_SERVER1),
				[32; 32].into(),
				[42; 64].into(),
			).unwrap();

			// another response from key server 1 is received
			ServerKeyGenerationService::<TestRuntime>::on_generated(
				Origin::signed(KEY_SERVER1),
				[32; 32].into(),
				[42; 64].into(),
			).unwrap();

			// check that key is not published
			assert_eq!(
				events_count,
				frame_system::Module::<TestRuntime>::events().len(),
			);
		});
	}

	#[test]
	fn should_raise_generation_error_when_two_servers_report_different_key() {
		default_initialization().execute_with(|| {
			// ask to generate server key
			ServerKeyGenerationService::<TestRuntime>::generate(
				Origin::signed(REQUESTER1),
				[32; 32].into(),
				1,
			).unwrap();
			let events_count = frame_system::Module::<TestRuntime>::events().len();

			// response from key server 1 is received
			ServerKeyGenerationService::<TestRuntime>::on_generated(
				Origin::signed(KEY_SERVER0),
				[32; 32].into(),
				[42; 64].into(),
			).unwrap();

			// response from key server 2 is received
			ServerKeyGenerationService::<TestRuntime>::on_generated(
				Origin::signed(KEY_SERVER1),
				[32; 32].into(),
				[43; 64].into(),
			).unwrap();

			// check that generation error is published
			assert_eq!(
				events_count + 1,
				frame_system::Module::<TestRuntime>::events().len(),
			);
			assert!(
				frame_system::Module::<TestRuntime>::events().into_iter()
					.find(|e| e.event == Event::ServerKeyGenerationError([32; 32].into()).into())
					.is_some(),
			);

			ensure_clean_storage([32; 32].into());
		});
	}

	#[test]
	fn should_raise_generation_error_when_one_of_three_servers_report_different_key() {
		default_initialization_with_three_servers().execute_with(|| {
			// ask to generate server key
			ServerKeyGenerationService::<TestRuntime>::generate(
				Origin::signed(REQUESTER1),
				[32; 32].into(),
				1,
			).unwrap();
			let events_count = frame_system::Module::<TestRuntime>::events().len();

			// response from key server 1 is received
			ServerKeyGenerationService::<TestRuntime>::on_generated(
				Origin::signed(KEY_SERVER0),
				[32; 32].into(),
				[42; 64].into(),
			).unwrap();

			// response from key server 2 is received
			ServerKeyGenerationService::<TestRuntime>::on_generated(
				Origin::signed(KEY_SERVER1),
				[32; 32].into(),
				[42; 64].into(),
			).unwrap();

			// and wron response from key server 3 is received
			ServerKeyGenerationService::<TestRuntime>::on_generated(
				Origin::signed(KEY_SERVER2),
				[32; 32].into(),
				[43; 64].into(),
			).unwrap();

			// check that generation error is published
			assert_eq!(
				events_count + 1,
				frame_system::Module::<TestRuntime>::events().len(),
			);
			assert!(
				frame_system::Module::<TestRuntime>::events().into_iter()
					.find(|e| e.event == Event::ServerKeyGenerationError([32; 32].into()).into())
					.is_some(),
			);

			ensure_clean_storage([32; 32].into());
		});
	}

	#[test]
	fn should_raise_generation_error_when_at_least_one_key_server_reports_error() {
		default_initialization().execute_with(|| {
			// ask to generate server key
			ServerKeyGenerationService::<TestRuntime>::generate(
				Origin::signed(REQUESTER1),
				[32; 32].into(),
				1,
			).unwrap();

			// response from key server 1 is received
			ServerKeyGenerationService::<TestRuntime>::on_generation_error(
				Origin::signed(KEY_SERVER0),
				[32; 32].into(),
			).unwrap();

			// check that generation error is published
			assert!(
				frame_system::Module::<TestRuntime>::events().into_iter()
					.find(|e| e.event == Event::ServerKeyGenerationError([32; 32].into()).into())
					.is_some(),
			);

			ensure_clean_storage([32; 32].into());
		});
	}

	#[test]
	fn should_raise_generation_error_when_at_least_one_key_server_reports_error_wth_zero_threshold() {
		default_initialization().execute_with(|| {
			// ask to generate server key
			ServerKeyGenerationService::<TestRuntime>::generate(
				Origin::signed(REQUESTER1),
				[32; 32].into(),
				0,
			).unwrap();

			// response from key server 1 is received
			ServerKeyGenerationService::<TestRuntime>::on_generation_error(
				Origin::signed(KEY_SERVER0),
				[32; 32].into(),
			).unwrap();

			// check that generation error is published
			assert!(
				frame_system::Module::<TestRuntime>::events().into_iter()
					.find(|e| e.event == Event::ServerKeyGenerationError([32; 32].into()).into())
					.is_some(),
			);

			ensure_clean_storage([32; 32].into());
		});
	}
}
