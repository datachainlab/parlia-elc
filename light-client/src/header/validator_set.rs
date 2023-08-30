use crate::errors::Error;
use alloc::vec::Vec;

use crate::misc::{keccak_256_vec, Hash, Validators};

#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct ValidatorSet {
    pub validators: Validators,
    pub hash: Hash,
}

impl TryFrom<Vec<Vec<u8>>> for ValidatorSet {
    type Error = Error;
    fn try_from(value: Vec<Vec<u8>>) -> Result<Self, Self::Error> {
        let hash = keccak_256_vec(&value);
        Ok(Self {
            validators: value as Validators,
            hash,
        })
    }
}
