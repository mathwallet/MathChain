// pub mod client;

// pub mod chain_spec;
// pub use chain_spec::{
// 	galois as galois_chain_spec, mathchain as mathchain_chain_spec, GaloisChainSpec, MathChainSpec,
// };

pub mod service;
pub use service::{
	galois as galois_service, galois_runtime,
    mathchain as mathchain_service, mathchain_runtime,
	IdentifyVariant,
};