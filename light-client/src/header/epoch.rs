use crate::errors::Error;
use crate::header::validator_set::ValidatorSet;
use crate::misc::{ceil_div, Hash, Validators};
use patricia_merkle_trie::keccak::keccak_256;

#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct Epoch {
    validator_set: ValidatorSet,
    turn_length: u8,
    hash: Hash,
}

impl Epoch {
    pub fn new(validator_set: ValidatorSet, turn_length: u8) -> Self {
        let seed = [[turn_length].as_slice(), validator_set.hash.as_slice()].concat();
        Self {
            validator_set,
            turn_length,
            hash: keccak_256(&seed),
        }
    }
    pub fn checkpoint(&self) -> u64 {
        self.validator_set.checkpoint(self.turn_length)
    }

    pub fn hash(&self) -> Hash {
        self.hash
    }

    pub fn validators(&self) -> &Validators {
        &self.validator_set.validators
    }

    pub fn turn_length(&self) -> u8 {
        self.turn_length
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct TrustedEpoch<'a> {
    inner: &'a Epoch,
}

impl<'a> TrustedEpoch<'a> {
    pub fn validators(&self) -> &Validators {
        self.inner.validators()
    }

    pub fn checkpoint(&self) -> u64 {
        self.inner.checkpoint()
    }

    pub fn epoch(&self) -> &'a Epoch {
        self.inner
    }

    pub fn new(inner: &'a Epoch) -> Self {
        Self { inner }
    }

    pub fn verify_untrusted_voters(&self, untrusted_voter: &Validators) -> Result<(), Error> {
        let (result, found, required) =
            self.contains_at_least_one_honest_validator(untrusted_voter);
        if result {
            return Ok(());
        }
        Err(Error::InsufficientHonestValidator(
            self.inner.hash,
            found,
            required,
        ))
    }

    pub fn contains_at_least_one_honest_validator(
        &self,
        untrusted_voters: &Validators,
    ) -> (bool, usize, usize) {
        let mut trusted_validator_count = 0;
        for x1 in untrusted_voters {
            if self.validators().contains(x1) {
                trusted_validator_count += 1;
            }
        }
        let required = Self::threshold(self.validators().len());
        (
            trusted_validator_count >= required,
            trusted_validator_count,
            required,
        )
    }
    fn threshold(validators_len: usize) -> usize {
        validators_len - ceil_div(validators_len * 2, 3) + 1
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct UntrustedEpoch<'a> {
    inner: &'a Epoch,
}

impl<'a> UntrustedEpoch<'a> {
    pub fn new(inner: &'a Epoch) -> Self {
        Self { inner }
    }
    pub fn checkpoint(&self) -> u64 {
        self.inner.checkpoint()
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum EitherEpoch<'a> {
    Trusted(TrustedEpoch<'a>),
    Untrusted(UntrustedEpoch<'a>),
}

impl<'a> EitherEpoch<'a> {
    pub fn checkpoint(&self) -> u64 {
        match self {
            EitherEpoch::Trusted(v) => v.checkpoint(),
            EitherEpoch::Untrusted(v) => v.checkpoint(),
        }
    }

    pub fn epoch(&self) -> &'a Epoch {
        match self {
            EitherEpoch::Trusted(v) => v.inner,
            EitherEpoch::Untrusted(v) => v.inner,
        }
    }
}

#[cfg(test)]
mod test {
    use crate::errors::Error;
    use crate::header::epoch::{Epoch, TrustedEpoch, ValidatorSet};

    #[test]
    pub fn test_verify_voter() {
        let mut _assert_trusted = |x, y, success: bool| {
            let trusted_validators: ValidatorSet = vec![
                vec![1],
                vec![2],
                vec![3],
                vec![4],
                vec![5],
                vec![6],
                vec![7],
            ]
            .into();
            let trusted_epoch = Epoch::new(trusted_validators, 1);
            let trusted_epoch = TrustedEpoch::new(&trusted_epoch);
            let (result, count, required) =
                trusted_epoch.contains_at_least_one_honest_validator(&x);
            assert_eq!(result, success);
            assert_eq!(count, y);
            assert_eq!(required, 3);
            match trusted_epoch.verify_untrusted_voters(&x) {
                Ok(_) => assert!(success),
                Err(e) => {
                    assert!(!success);
                    match e {
                        Error::InsufficientHonestValidator(_, _, _) => {}
                        e => unreachable!("unexpected error type {:?}", e),
                    }
                }
            }
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

    #[test]
    pub fn test_trust_threshold() {
        assert_eq!(1, TrustedEpoch::threshold(1));
        assert_eq!(1, TrustedEpoch::threshold(2));
        assert_eq!(2, TrustedEpoch::threshold(3));
        assert_eq!(2, TrustedEpoch::threshold(4));
        assert_eq!(2, TrustedEpoch::threshold(5));
        assert_eq!(3, TrustedEpoch::threshold(6));
        assert_eq!(3, TrustedEpoch::threshold(7));
        assert_eq!(3, TrustedEpoch::threshold(8));
        assert_eq!(4, TrustedEpoch::threshold(9));
        assert_eq!(8, TrustedEpoch::threshold(21));
    }
}
