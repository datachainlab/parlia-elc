use alloc::vec::Vec;

use lcp_types::{Height, Time};
use rlp::{Decodable, Rlp};

use crate::errors::Error;

pub type Validator = Vec<u8>;
pub type Validators = Vec<Validator>;
pub type Address = [u8; 20];
pub type BlockNumber = u64;
pub type Hash = [u8; 32];
pub type StorageKey = [u8; 32];

#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct ChainId {
    id: u64,
    version: u64,
}

impl ChainId {
    pub fn id(&self) -> u64 {
        self.id
    }

    pub fn new(id: u64) -> Self {
        //TODO support upgrade. currently follow the ethereum-elc-
        ChainId { id, version: 0 }
    }

    pub fn version(&self) -> u64 {
        self.version
    }
}

pub trait ValidatorReader {
    fn read(&self, height: Height) -> Result<Validators, Error>;
}

#[derive(Debug, PartialEq)]
pub struct Account {
    // nonce,
    // balance
    /// storage root hash
    pub storage_root: Vec<u8>,
    // code_hash
}

impl<'a> TryFrom<Rlp<'a>> for Account {
    type Error = Error;

    fn try_from(value: Rlp<'a>) -> Result<Self, Self::Error> {
        let storage_root = value
            .at(2)
            .map_err(Error::RLPDecodeError)?
            .as_val::<Vec<u8>>()
            .map_err(Error::RLPDecodeError)?;
        Ok(Self { storage_root })
    }
}

/// RlpIterator returns an error instead of None on next() unlike the rlp::RlpIterator.
pub(crate) struct RlpIterator<'a> {
    rlp: Rlp<'a>,
    index: usize,
}

impl<'a> RlpIterator<'a> {
    pub fn new(rlp: Rlp<'a>) -> Self {
        Self { rlp, index: 0 }
    }

    pub fn try_next(&mut self) -> Result<Rlp<'a>, Error> {
        let index = self.index;
        let result = self.rlp.at(index).map_err(Error::RLPDecodeError)?;
        self.index += 1;
        Ok(result)
    }

    pub fn try_next_as_val<T: Decodable>(&mut self) -> Result<T, Error> {
        let next = self.try_next()?;
        next.as_val().map_err(Error::RLPDecodeError)
    }
}

pub(crate) fn required_block_count_to_finalize(validators: &Validators) -> usize {
    let validator_size = validators.len();
    validator_size / 2 + 1
}

pub fn new_height(revision_number: u64, height: BlockNumber) -> Height {
    Height::new(revision_number, height)
}

pub fn new_timestamp(second: u64) -> Result<Time, Error> {
    Time::from_unix_timestamp_secs(second).map_err(Error::TimeError)
}

pub fn decode_proof(proofs: &[u8]) -> Result<Vec<Vec<u8>>, Error> {
    let mut proof_encoded: Vec<Vec<u8>> = Vec::with_capacity(proofs.len());
    let proofs = Rlp::new(proofs);
    for proof in proofs.iter() {
        let proof: Vec<Vec<u8>> = proof.as_list().map_err(Error::ProofRLPError)?;
        let proof = rlp::encode_list::<Vec<u8>, Vec<u8>>(&proof).into();
        proof_encoded.push(proof)
    }
    Ok(proof_encoded)
}
