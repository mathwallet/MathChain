// This file is part of Mathchain.

// Copyright (C) 2017-2020 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

mod aux_schema;

pub use crate::aux_schema::{load_block_hash, load_transaction_metadata};

use async_trait::async_trait;
use std::sync::Arc;
use std::collections::HashMap;
use std::marker::PhantomData;
use mathchain_consensus_primitives::{MATHCHAIN_ENGINE_ID, ConsensusLog};
use sc_client_api::{BlockOf, backend::AuxStore};
use sp_blockchain::{HeaderBackend, ProvideCache, well_known_cache_keys::Id as CacheKeyId};
use sp_block_builder::BlockBuilder as BlockBuilderApi;
use sp_runtime::generic::OpaqueDigestItemId;
use sp_runtime::traits::{Block as BlockT, Header as HeaderT};
use sp_api::ProvideRuntimeApi;
use sp_consensus::{
	BlockImportParams, Error as ConsensusError, BlockImport,
	BlockCheckParams, ImportResult,
};
use log::*;
use sc_client_api;

#[derive(derive_more::Display, Debug)]
pub enum Error {
	#[display(fmt = "Multiple post-runtime Ethereum blocks, rejecting!")]
	MultiplePostRuntimeLogs,
	#[display(fmt = "Post-runtime Ethereum block not found, rejecting!")]
	NoPostRuntimeLog,
}

impl From<Error> for String {
	fn from(error: Error) -> String {
		error.to_string()
	}
}

impl std::convert::From<Error> for ConsensusError {
	fn from(error: Error) -> ConsensusError {
		ConsensusError::ClientImport(error.to_string())
	}
}

pub struct MathchainBlockImport<B: BlockT, I, C> {
	inner: I,
	client: Arc<C>,
	is_galois: bool,
	_marker: PhantomData<B>,
}

impl<Block: BlockT, I: Clone + BlockImport<Block>, C> Clone for MathchainBlockImport<Block, I, C> {
	fn clone(&self) -> Self {
		MathchainBlockImport {
			inner: self.inner.clone(),
			client: self.client.clone(),
			is_galois: self.is_galois,
			_marker: PhantomData,
		}
	}
}

impl<B, I, C> MathchainBlockImport<B, I, C> where
	B: BlockT,
	I: BlockImport<B, Transaction = sp_api::TransactionFor<C, B>> + Send + Sync,
	I::Error: Into<ConsensusError>,
	C: ProvideRuntimeApi<B> + Send + Sync + HeaderBackend<B> + AuxStore + ProvideCache<B> + BlockOf,
	C::Api: BlockBuilderApi<B>,
{
	pub fn new(
		inner: I,
		client: Arc<C>,
		is_galois: bool,
	) -> Self {
		Self {
			inner,
			client,
			is_galois,
			_marker: PhantomData,
		}
	}
}

#[async_trait]
impl<B, I, C> BlockImport<B> for MathchainBlockImport<B, I, C> where
	B: BlockT,
	I: BlockImport<B, Transaction = sp_api::TransactionFor<C, B>> + Send + Sync,
	I::Error: Into<ConsensusError>,
	C: ProvideRuntimeApi<B> + Send + Sync + HeaderBackend<B> + AuxStore + ProvideCache<B> + BlockOf,
	C::Api: BlockBuilderApi<B>,
{
	type Error = ConsensusError;
	type Transaction = sp_api::TransactionFor<C, B>;

	async fn check_block(
		&mut self,
		block: BlockCheckParams<B>,
	) -> Result<ImportResult, Self::Error> {
		self.inner.check_block(block).await.map_err(Into::into)
	}

	async fn import_block(
		&mut self,
		mut block: BlockImportParams<B, Self::Transaction>,
		new_cache: HashMap<CacheKeyId, Vec<u8>>,
	) -> Result<ImportResult, Self::Error> {
		macro_rules! insert_closure {
			() => (
				|insert| block.auxiliary.extend(
					insert.iter().map(|(k, v)| (k.to_vec(), Some(v.to_vec())))
				)
			)
		}

		let client = self.client.clone();

		// support testnet aura block import
		// if !!!(self.is_galois && block.header.number().clone().saturated_into::<u64>() < 1_252_435) {
		let log = find_mathchain_log::<B>(&block.header)?;
		let hash = block.post_hash();

		match log {
			ConsensusLog::EndBlock {
				block_hash, transaction_hashes,
			} => {
				aux_schema::write_block_hash(client.as_ref(), block_hash, hash, insert_closure!());

				for (index, transaction_hash) in transaction_hashes.into_iter().enumerate() {
					aux_schema::write_transaction_metadata(
						transaction_hash,
						(block_hash, index as u32),
						insert_closure!(),
					);
				}
			},
		}
		// }

		self.inner.import_block(block, new_cache).await.map_err(Into::into)
	}
}

fn find_mathchain_log<B: BlockT>(
	header: &B::Header,
) -> Result<ConsensusLog, Error> {
	let mut mathchain_log: Option<_> = None;
	for log in header.digest().logs() {
		trace!(target: "mathchain-consensus", "Checking log {:?}, looking for ethereum block.", log);
		let log = log.try_to::<ConsensusLog>(OpaqueDigestItemId::Consensus(&MATHCHAIN_ENGINE_ID));
		match (log, mathchain_log.is_some()) {
			(Some(_), true) =>
				return Err(Error::MultiplePostRuntimeLogs),
			(Some(log), false) => mathchain_log = Some(log),
			_ => trace!(target: "mathchain-consensus", "Ignoring digest not meant for us"),
		}
	}

	Ok(mathchain_log.ok_or(Error::NoPostRuntimeLog)?)
}
