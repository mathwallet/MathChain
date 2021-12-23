pub mod galois;
pub use galois_runtime;

pub mod mathchain;
pub use mathchain_runtime;

/// Can be called for a `Configuration` to check if it is a configuration for the `Crab` network.
pub trait IdentifyVariant {
	/// Returns if this is a configuration for the `Galois` network.
	fn is_galois(&self) -> bool;

	/// Returns if this is a configuration for the `MathChain` network.
	fn is_mathchain(&self) -> bool;
}

impl IdentifyVariant for Box<dyn sc_service::ChainSpec> {
	fn is_galois(&self) -> bool {
		self.id().starts_with("Galois") || self.id().starts_with("dev")
	}

	fn is_mathchain(&self) -> bool {
		self.id().starts_with("MathChain")
	}
}
