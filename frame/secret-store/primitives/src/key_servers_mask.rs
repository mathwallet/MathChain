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

use codec::{Decode, Encode};

/// The mask of key servers. We only support up to 256 key servers.
#[derive(Debug, Default, Decode, Encode, PartialEq, Clone, Copy)]
pub struct KeyServersMask {
	low: u128,
	high: u128,
}

impl KeyServersMask {
	/// Create mask from key server index.
	pub fn from_index(index: u8) -> Self {
		match index.overflowing_sub(128) {
			(_, true) => KeyServersMask { low: 1 << index, high: 0 },
			(high_index, false) => KeyServersMask { low: 0, high: 1 << high_index },
		}
	}

	/// Returns true if bit with given index is set.
	pub fn is_set(&self, index: u8) -> bool {
		match index.overflowing_sub(128) {
			(_, true) => (self.low & (1u128 << index)) != 0,
			(high_index, false) => (self.high & (1u128 << high_index)) != 0,
		}
	}

	/// Returns union of two masks.
	pub fn union(&self, other: KeyServersMask) -> Self {
		KeyServersMask { low: self.low | other.low, high: self.high | other.high }
	}

	pub fn lowest_unoccupied_index(&self) -> Option<u8> {
		let low_index = (0..128).find(|idx| self.low & (1u128 << idx) == 0);
		match low_index {
			Some(low_index) => Some(low_index),
			None => (0..128).find(|idx| self.high & (1u128 << idx) == 0).map(|idx| 128 + idx)
		}
	}

	pub fn set(&mut self, index: u8) {
		match index.overflowing_sub(128) {
			(_, true) => self.low |= 1u128 << index,
			(high_index, false) => self.high |= 1u128 << high_index,
		}
	}
}
