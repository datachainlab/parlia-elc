use alloc::vec::Vec;

use light_client::types::{Height, Time};
use patricia_merkle_trie::keccak::keccak_256;
use rlp::{Decodable, Rlp};

use crate::errors::Error;

pub type Validator = Vec<u8>;
pub type Validators = Vec<Validator>;
pub type Address = [u8; 20];
pub type BlockNumber = u64;
pub type Hash = [u8; 32];

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

pub fn rlp_as_val<T: Decodable>(rlp: &Rlp, index: usize) -> Result<T, Error> {
    rlp.at(index)
        .map_err(Error::RLPDecodeError)?
        .as_val()
        .map_err(Error::RLPDecodeError)
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

pub fn new_height(revision_number: u64, height: BlockNumber) -> Height {
    Height::new(revision_number, height)
}

pub fn new_timestamp(msec: u64) -> Result<Time, Error> {
    let msec = msec as u128;
    let nanos = msec
        .checked_mul(1_000_000)
        .ok_or_else(|| Error::TimestampOverflowError(msec))?;
    Time::from_unix_timestamp_nanos(nanos).map_err(Error::TimeError)
}

pub fn keccak_256_vec(targets: &[Vec<u8>]) -> Hash {
    let flatten: Vec<u8> = targets.iter().flat_map(|x| x.clone()).collect();
    keccak_256(flatten.as_slice())
}

pub fn ceil_div(x: usize, y: usize) -> usize {
    if y == 0 {
        return 0;
    }
    (x + y - 1) / y
}

#[cfg(test)]
mod test {
    use crate::misc::ceil_div;

    #[test]
    fn ceil_div_test() {
        assert_eq!(ceil_div(0, 0), 0);

        // 1/2
        assert_eq!(ceil_div(1, 2), 1);
        assert_eq!(ceil_div(7, 2), 4);
        assert_eq!(ceil_div(8, 2), 4);
        assert_eq!(ceil_div(21, 2), 11);

        // 1/3
        assert_eq!(ceil_div(1, 3), 1);
        assert_eq!(ceil_div(7, 3), 3);
        assert_eq!(ceil_div(8, 3), 3);
        assert_eq!(ceil_div(21, 3), 7);

        // 2/3
        assert_eq!(ceil_div(2, 3), 1);
        assert_eq!(ceil_div(7 * 2, 3), 5);
        assert_eq!(ceil_div(8 * 2, 3), 6);
        assert_eq!(ceil_div(21 * 2, 3), 14);
    }
}
