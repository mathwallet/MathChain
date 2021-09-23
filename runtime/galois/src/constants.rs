pub mod currency {
	type Balance = u128;
	pub const MATHS: Balance = 1_000_000_000_000_000_000;
	pub const DOLLARS: Balance = MATHS / 100;               // 10_000_000_000_000_000
	pub const CENTS: Balance = DOLLARS / 100;               // 100_000_000_000_000
	pub const MILLICENTS: Balance = CENTS / 1_000;          // 100_000_000_000
}