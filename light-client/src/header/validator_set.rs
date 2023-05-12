use crate::errors::Error;
use crate::misc::{keccak_256_vec, new_height, Hash, Validators};
use alloc::vec::Vec;
use lcp_types::Height;
use parlia_ibc_proto::ibc::lightclients::parlia::v1::ValidatorSet as RawValidatorSet;
use patricia_merkle_trie::keccak::keccak_256;

#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct ValidatorSet {
    epoch_height: Height,
    validators: Validators,
    hash: Hash,
}

impl ValidatorSet {
    pub fn validators(&self) -> &Validators {
        &self.validators
    }
}

impl TryFrom<RawValidatorSet> for ValidatorSet {
    type Error = Error;

    fn try_from(value: RawValidatorSet) -> Result<Self, Self::Error> {
        let height = value
            .epoch_height
            .ok_or(Error::MissingTrustedValidatorsHeight)?;
        let validators = value.validators;
        let hash = keccak_256_vec(&validators);
        Ok(Self {
            epoch_height: new_height(height.revision_number, height.revision_height),
            validators,
            hash,
        })
    }
}
