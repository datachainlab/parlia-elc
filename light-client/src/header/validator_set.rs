use crate::errors::Error;
use alloc::vec::Vec;

use crate::misc::{ceil_div, keccak_256_vec, Hash, Validators};

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
