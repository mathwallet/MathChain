// This file is part of Substrate.

// Copyright (C) 2017-2020 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: Apache-2.0

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use crate::{
	chain_spec,
	cli::{Cli, Subcommand},
	service::{self, frontier_database_dir},
};
use mathchain_runtime::Block;
use sc_cli::{ChainSpec, Role, RuntimeVersion, SubstrateCli};

use sc_service::PartialComponents;
use sp_core::crypto::Ss58AddressFormat;

use galois_runtime_config::CHAIN_ID as GaoloisChainId;
use mathchain_runtime_config::CHAIN_ID as MathchainChainId;
use service::IdentifyVariant;

impl SubstrateCli for Cli {
	fn impl_name() -> String {
		"MathChain Node".into()
	}

	fn impl_version() -> String {
		env!("SUBSTRATE_CLI_IMPL_VERSION").into()
	}

	fn description() -> String {
		env!("CARGO_PKG_DESCRIPTION").into()
	}

	fn author() -> String {
		env!("CARGO_PKG_AUTHORS").into()
	}

	fn support_url() -> String {
		"support.anonymous.an".into()
	}

	fn copyright_start_year() -> i32 {
		2020
	}

	fn load_spec(&self, id: &str) -> Result<Box<dyn sc_service::ChainSpec>, String> {
		Ok(match id {
			"dev" => Box::new(chain_spec::development_config()?),
			// "galois_genesis" => Box::new(chain_spec::galois_build_spec_genesis()?),
			"" | "local" => Box::new(chain_spec::local_testnet_config()?),
			"galois" => Box::new(chain_spec::galois_config()?),
			"galois_for_genesis" => Box::new(chain_spec::galois_for_genesis()?),
			path => Box::new(chain_spec::ChainSpec::from_json_file(
				std::path::PathBuf::from(path),
			)?),
		})
	}

	fn native_runtime_version(_: &Box<dyn ChainSpec>) -> &'static RuntimeVersion {
		&mathchain_runtime::VERSION
	}
}

fn set_default_ss58_version(spec: &Box<dyn sc_cli::ChainSpec>) {
	let ss58_version = if spec.is_galois() {
		Ss58AddressFormat::Custom(GaoloisChainId)
	} else if spec.is_math() {
		Ss58AddressFormat::Custom(MathchainChainId)
	} else {
		Ss58AddressFormat::Custom(GaoloisChainId)
	};

	sp_core::crypto::set_default_ss58_version(ss58_version);
}

/// Parse and run command line arguments
pub fn run() -> sc_cli::Result<()> {
	let cli = Cli::from_args();

	match &cli.subcommand {
		Some(Subcommand::Key(cmd)) => cmd.run(&cli),
		Some(Subcommand::BuildSpec(cmd)) => {
			let runner = cli.create_runner(cmd)?;
			runner.sync_run(|config| cmd.run(config.chain_spec, config.network))
		}
		Some(Subcommand::CheckBlock(cmd)) => {
			let runner = cli.create_runner(cmd)?;
			runner.async_run(|config| {
				let PartialComponents {
					client,
					task_manager,
					import_queue,
					..
				} = service::new_partial(&config, &cli)?;
				Ok((cmd.run(client, import_queue), task_manager))
			})
		}
		Some(Subcommand::ExportBlocks(cmd)) => {
			let runner = cli.create_runner(cmd)?;
			runner.async_run(|config| {
				let PartialComponents {
					client,
					task_manager,
					..
				} = service::new_partial(&config, &cli)?;
				Ok((cmd.run(client, config.database), task_manager))
			})
		}
		Some(Subcommand::ExportState(cmd)) => {
			let runner = cli.create_runner(cmd)?;
			runner.async_run(|config| {
				let PartialComponents {
					client,
					task_manager,
					..
				} = service::new_partial(&config, &cli)?;
				Ok((cmd.run(client, config.chain_spec), task_manager))
			})
		}
		Some(Subcommand::ImportBlocks(cmd)) => {
			let runner = cli.create_runner(cmd)?;
			runner.async_run(|config| {
				let PartialComponents {
					client,
					task_manager,
					import_queue,
					..
				} = service::new_partial(&config, &cli)?;
				Ok((cmd.run(client, import_queue), task_manager))
			})
		}
		Some(Subcommand::PurgeChain(cmd)) => {
			let runner = cli.create_runner(cmd)?;
			runner.sync_run(|config| {
				// Remove Frontier offchain db
				let frontier_database_config = sc_service::DatabaseSource::RocksDb {
					path: frontier_database_dir(&config),
					cache_size: 0,
				};
				cmd.run(frontier_database_config)?;
				cmd.run(config.database)
			})
		}
		Some(Subcommand::Revert(cmd)) => {
			let runner = cli.create_runner(cmd)?;
			runner.async_run(|config| {
				let PartialComponents {
					client,
					task_manager,
					backend,
					..
				} = service::new_partial(&config, &cli)?;
				Ok((cmd.run(client, backend), task_manager))
			})
		}
		Some(Subcommand::Benchmark(cmd)) => {
			if cfg!(feature = "runtime-benchmarks") {
				let runner = cli.create_runner(cmd)?;

				runner.sync_run(|config| cmd.run::<Block, service::ExecutorDispatch>(config))
			} else {
				Err(
					"Benchmarking wasn't enabled when building the node. You can enable it with `--features runtime-benchmarks`."
						.into(),
				)
			}
		}
		None => {
			let runner = cli.create_runner(&cli.run.base)?;
			set_default_ss58_version(&runner.config().chain_spec);

			runner.run_node_until_exit(|config| async move {
				match config.role {
					Role::Light => service::new_light(config),
					_ => service::new_full(config, &cli),
				}
				.map_err(sc_cli::Error::Service)
			})
		}
	}
}
