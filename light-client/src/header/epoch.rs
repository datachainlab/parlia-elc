use patricia_merkle_trie::keccak::keccak_256;
use crate::header::validator_set::ValidatorSet;
use crate::misc::{Hash};

struct Epoch {
    validator_set: ValidatorSet,
    turn_term: u8,
    hash: Hash
}

impl Epoch {
    pub fn new(validator_set: ValidatorSet, turn_term: u8) -> Self {
        let seed = [[turn_term].as_slice(), validator_set.hash.as_slice()].concat();
        Self {
            validator_set,
            turn_term,
            hash: keccak_256(&seed)
        }
    }
    pub fn checkpoint(&self) -> u64 {
       self.validator_set.checkpoint(self.turn_term)
    }

    pub fn hash(&self) -> Hash {
        self.hash
    }
}