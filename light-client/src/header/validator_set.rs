use crate::errors::Error;
use alloc::vec::Vec;

use crate::misc::{ceil_div, keccak_256_vec, Hash, Validators};

#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct ValidatorSet {
    pub validators: Validators,
    pub hash: Hash,
}

impl ValidatorSet {
    /// https://github.com/NathanBSC/bsc/blob/a910033bc52013d96ecefd8d5224d70d288c1309/consensus/parlia/snapshot.go#L226
    pub fn checkpoint(&self, turn_term: u8) -> u64 {
        let validator_size = self.validators.len() as u64;
        return (validator_size / 2) * turn_term as u64 + 1;
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
