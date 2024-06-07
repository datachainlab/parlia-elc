#![no_std]

#[cfg_attr(not(test), macro_use)]
extern crate alloc;
#[cfg(test)]
#[macro_use]
extern crate std;

pub mod client;
pub mod client_state;
pub mod commitment;
pub mod consensus_state;
pub mod errors;
pub mod header;
pub mod message;
pub mod misbehaviour;
pub mod misc;
#[cfg(test)]
mod fixture;

pub fn register_implementations(registry: &mut dyn light_client::LightClientRegistry) {
    registry
        .put_light_client(
            alloc::string::String::from(client_state::PARLIA_CLIENT_STATE_TYPE_URL),
            alloc::boxed::Box::new(client::ParliaLightClient),
        )
        .unwrap()
}
