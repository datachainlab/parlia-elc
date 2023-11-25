use crate::errors::Error;
use crate::header::constant::BLOCKS_PER_EPOCH;
use crate::header::eth_header::ETHHeader;
use alloc::vec::Vec;

use crate::misc::{ceil_div, keccak_256_vec, BlockNumber, Hash, Validators};

#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct ValidatorSet {
    validators: Validators,
    pub hash: Hash,
    pub trusted: bool,
}

impl ValidatorSet {
    /// for example when the validator count is 21 the checkpoint is 211, 411, 611 ...
    /// https://github.com/bnb-chain/bsc/blob/48aaee69e9cb50fc2cedf1398ae4b98b099697db/consensus/parlia/parlia.go#L607
    /// https://github.com/bnb-chain/bsc/blob/48aaee69e9cb50fc2cedf1398ae4b98b099697db/consensus/parlia/snapshot.go#L191
    pub fn checkpoint(&self) -> u64 {
        let validator_size = self.validators.len() as u64;
        validator_size / 2 + 1
    }

    pub fn validators(&self) -> Result<&Validators, Error> {
        if !self.trusted {
            return Err(Error::ValidatorNotTrusted(self.hash));
        }
        Ok(&self.validators)
    }

    pub fn trust(&mut self, trusted_validators: &Validators) {
        if self.trusted {
            return;
        }
        let (trusted, _, _) = self.trustable(trusted_validators);
        self.trusted = trusted
    }

    fn trustable(&self, trusted_validators: &Validators) -> (bool, usize, usize) {
        let mut trusted_validator_count = 0;
        for x1 in &self.validators {
            if trusted_validators.contains(x1) {
                trusted_validator_count += 1;
            }
        }
        let required = ceil_div(trusted_validators.len(), 3);
        (
            trusted_validator_count >= required,
            trusted_validator_count,
            required,
        )
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

#[derive(Clone, Debug)]
struct ValidatorSetRange {
    min_number_to_verify_seal: BlockNumber,
    min_number_to_verify_vote: BlockNumber,
    validators: ValidatorSet,
}

impl ValidatorSetRange {
    fn new(
        min_number_to_verify_seal: BlockNumber,
        min_number_to_verify_vote: BlockNumber,
        validators: ValidatorSet,
    ) -> Self {
        Self {
            min_number_to_verify_seal,
            min_number_to_verify_vote,
            validators,
        }
    }
}

#[derive(Clone, Debug)]
pub struct ValidatorSets {
    validators: Vec<ValidatorSetRange>,
}

impl ValidatorSets {
    pub fn new(
        hs: &[ETHHeader],
        p_val: &ValidatorSet,
        c_val: &ValidatorSet,
    ) -> Result<ValidatorSets, Error> {
        let first = &hs[0];
        let mut validators = vec![];
        let mut p_val = p_val.clone();
        let mut c_val = c_val.clone();
        let mut epoch = first.number / BLOCKS_PER_EPOCH;
        let mut checkpoint = epoch * BLOCKS_PER_EPOCH + p_val.checkpoint();
        if first.number < checkpoint {
            validators.push(ValidatorSetRange::new(
                first.number,
                first.number,
                p_val.clone(),
            ));
        }
        let mut current_saved = false;
        for h in hs {
            if h.number >= checkpoint {
                if !current_saved {
                    c_val.trust(p_val.validators()?);
                    validators.push(ValidatorSetRange::new(
                        checkpoint,
                        // At the just checkpoint BLS signature uses previous validator set.
                        checkpoint + 1,
                        c_val.clone(),
                    ));
                    current_saved = true;
                }

                let next_epoch = (epoch + 1) * BLOCKS_PER_EPOCH;
                if h.number == next_epoch {
                    let next_checkpoint = epoch + c_val.checkpoint();
                    let mut n_val: ValidatorSet = h
                        .get_validator_bytes()
                        .ok_or(Error::MissingValidatorInEpochBlock(h.number))?
                        .into();
                    n_val.trust(c_val.validators()?);
                    p_val = c_val;
                    c_val = n_val;
                    epoch = next_epoch;
                    checkpoint = next_checkpoint;
                    current_saved = false;
                }
            }
        }
        validators.reverse();
        // ex) validators range. when target = 201
        // 201, 201, p_val
        // 211, 212, c_val
        // 411, 412, n_val
        // 611, 612, nn_val
        // ex) validators range. when target = 215
        // 211, 212, c_val
        // 411, 412, n_val
        // 611, 612, nn_val
        Ok(ValidatorSets { validators })
    }

    pub fn get_for_verify_seal(&self, number: BlockNumber) -> Option<&ValidatorSet> {
        for range in &self.validators {
            if number >= range.min_number_to_verify_seal {
                return Some(&range.validators);
            }
        }
        None
    }

    pub fn get_for_verify_vote(&self, number: BlockNumber) -> Option<&ValidatorSet> {
        for range in &self.validators {
            if number >= range.min_number_to_verify_vote {
                return Some(&range.validators);
            }
        }
        None
    }
}

#[cfg(test)]
mod test {
    use crate::header::validator_set::ValidatorSet;

    #[test]
    pub fn test_trustable() {
        let mut _assert_trusted = |x, y, _trusted| {
            let trusted_validators = vec![
                vec![1],
                vec![2],
                vec![3],
                vec![4],
                vec![5],
                vec![6],
                vec![7],
            ];
            let mut untrusted_validators = ValidatorSet {
                validators: x,
                hash: [0; 32],
                trusted: false,
            };
            let (trusted, count, required) = untrusted_validators.trustable(&trusted_validators);
            assert_eq!(trusted, trusted);
            assert_eq!(count, y);
            assert_eq!(required, 3);
            untrusted_validators.trust(&trusted_validators);
            assert_eq!(untrusted_validators.trusted, trusted);
        };

        let assert_trusted = |x, y| _assert_trusted(x, y, true);
        assert_trusted(
            vec![
                vec![1],
                vec![2],
                vec![3],
                vec![4],
                vec![5],
                vec![6],
                vec![7],
            ],
            7,
        );
        assert_trusted(
            vec![
                vec![1],
                vec![2],
                vec![3],
                vec![4],
                vec![15],
                vec![16],
                vec![17],
            ],
            4,
        );
        assert_trusted(
            vec![
                vec![11],
                vec![12],
                vec![13],
                vec![4],
                vec![5],
                vec![6],
                vec![7],
            ],
            4,
        );
        assert_trusted(
            vec![
                vec![1],
                vec![12],
                vec![3],
                vec![14],
                vec![5],
                vec![16],
                vec![7],
            ],
            4,
        );
        assert_trusted(vec![vec![1], vec![2], vec![3], vec![4]], 4);
        assert_trusted(
            vec![
                vec![1],
                vec![2],
                vec![3],
                vec![14],
                vec![15],
                vec![16],
                vec![17],
            ],
            3,
        );
        assert_trusted(
            vec![
                vec![11],
                vec![12],
                vec![13],
                vec![14],
                vec![5],
                vec![6],
                vec![7],
            ],
            3,
        );
        assert_trusted(
            vec![
                vec![1],
                vec![12],
                vec![3],
                vec![14],
                vec![5],
                vec![16],
                vec![17],
            ],
            3,
        );
        assert_trusted(vec![vec![1], vec![2], vec![3]], 3);

        let assert_untrusted = |x, y| _assert_trusted(x, y, false);
        assert_untrusted(
            vec![
                vec![1],
                vec![2],
                vec![13],
                vec![14],
                vec![15],
                vec![16],
                vec![17],
            ],
            2,
        );
        assert_untrusted(
            vec![
                vec![11],
                vec![12],
                vec![13],
                vec![14],
                vec![15],
                vec![6],
                vec![7],
            ],
            2,
        );
        assert_untrusted(
            vec![
                vec![1],
                vec![12],
                vec![3],
                vec![14],
                vec![15],
                vec![16],
                vec![17],
            ],
            2,
        );
        assert_untrusted(vec![vec![1], vec![2]], 2);
    }
}
