use alloc::vec::Vec;

use crate::misc::{keccak_256_vec, Hash, Validators};

#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct ValidatorSet {
    pub validators: Validators,
    pub hash: Hash,
}

impl ValidatorSet {
    pub fn checkpoint(&self, turn_length: u8) -> u64 {
        let validator_size = self.validators.len() as u64;
        (validator_size / 2 + 1) * turn_length as u64
        // https://github.com/bnb-chain/BEPs/pull/341
        // The validator set switch occurs only when the block height reaches Bswitch to prevent epoch block forging.
        // Bswitch%epochSlots + 1 = checkpoint
    }
}

impl From<Vec<Vec<u8>>> for ValidatorSet {
    fn from(value: Vec<Vec<u8>>) -> Self {
        let hash = keccak_256_vec(&value);
        Self {
            validators: value as Validators,
            hash,
        }
    }
}
