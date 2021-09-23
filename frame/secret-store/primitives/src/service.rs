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
use sp_std::vec::Vec;
use crate::{
	KeyServerId, ServerKeyId, EntityId,
};

/// Service contract task.
#[derive(Debug, Clone, PartialEq, Encode, Decode)]
pub enum ServiceTask {
	/// Generate server key (server_key_id, author, threshold).
	GenerateServerKey(ServerKeyId, EntityId, u8),
	/// Retrieve server key (server_key_id).
	RetrieveServerKey(ServerKeyId),
	/// Store document key (server_key_id, author, common_point, encrypted_point).
	StoreDocumentKey(ServerKeyId, EntityId, sp_core::H512, sp_core::H512),
	/// Retrieve common data of document key (server_key_id, requester).
	RetrieveShadowDocumentKeyCommon(ServerKeyId, EntityId),
	/// Retrieve personal data of document key (server_key_id, requester).
	RetrieveShadowDocumentKeyPersonal(ServerKeyId, sp_core::H512),
}

sp_api::decl_runtime_apis! {
	/// Service runtime API.
	pub trait SecretStoreServiceApi {
		///
		fn server_key_generation_tasks(begin: u32, end: u32) -> Vec<ServiceTask>;
		/// Check if server key generation response is required from given key server.
		fn is_server_key_generation_response_required(key_server: KeyServerId, key: ServerKeyId) -> bool;

		///
		fn server_key_retrieval_tasks(begin: u32, end: u32) -> Vec<ServiceTask>;
		/// Check if server key retrieval response is required from given key server.
		fn is_server_key_retrieval_response_required(key_server: KeyServerId, key: ServerKeyId) -> bool;

		///
		fn document_key_store_tasks(begin: u32, end: u32) -> Vec<ServiceTask>;
		/// Check if server key retrieval response is required from given key server.
		fn is_document_key_store_response_required(key_server: KeyServerId, key: ServerKeyId) -> bool;

		///
		fn document_key_shadow_retrieval_tasks(begin: u32, end: u32) -> Vec<ServiceTask>;
		///
		fn is_document_key_shadow_retrieval_response_required(key_server: KeyServerId, key: ServerKeyId, requester: EntityId) -> bool;
	}
}
