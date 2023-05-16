use crate::misc::{keccak_256_vec, Hash, Validators};

#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct ValidatorSet {
    validators: Validators,
    hash: Hash,
}

impl ValidatorSet {
    pub fn validators(&self) -> &Validators {
        &self.validators
    }

    pub fn hash(&self) -> &Hash {
        &self.hash
    }
}

impl From<Validators> for ValidatorSet {

    fn from(value: Validators) -> Self{
        let hash = keccak_256_vec(&value);
        Self {
            validators: value,
            hash,
        }
    }
}
