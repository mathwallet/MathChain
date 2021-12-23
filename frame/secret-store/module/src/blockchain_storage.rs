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

use crate::{Event, Module, Config};
use sp_std::marker::PhantomData;

/// Blockchain related data storage.
pub(crate) trait Storage {
	/// Block number type.
	type BlockNumber;

	/// Returns current block number.
	fn current_block_number(&self) -> Self::BlockNumber;
	/// Deposit event.
	fn deposit_event(&mut self, event: Event);
}

/// The storage of single key server set.
pub(crate) struct RuntimeStorage<T>(PhantomData<T>);

impl<T: Config> Storage for RuntimeStorage<T> {
	type BlockNumber = <T as frame_system::Config>::BlockNumber;

	fn current_block_number(&self) -> Self::BlockNumber {
		<frame_system::Module<T>>::block_number()
	}

	fn deposit_event(&mut self, event: Event) {
		Module::<T>::deposit_event(event);
	}
}

impl<T> Default for RuntimeStorage<T> {
	fn default() -> Self {
		RuntimeStorage(Default::default())
	}
}
