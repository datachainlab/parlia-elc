use crate::errors::Error;
use alloc::vec::Vec;

use crate::misc::{keccak_256_vec, Hash, Validators};

#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct ValidatorSet {
    validators: Validators,
    pub hash: Hash,
    pub trusted: bool,
}

impl ValidatorSet {
    pub fn validators(&self) -> Result<&Validators, Error> {
        if !self.trusted {
            return Err(Error::ValidatorNotTrusted(self.hash));
        }
        Ok(&self.validators)
    }
}

impl From<Vec<Vec<u8>>> for ValidatorSet {
    fn from(value: Vec<Vec<u8>>) -> Self {
        let hash = keccak_256_vec(&value);
        Self {
            validators: value as Validators,
            hash,
            trusted: false,
        }
    }
}
