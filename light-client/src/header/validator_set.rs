use crate::errors::Error;
use alloc::vec::Vec;

use crate::misc::{ceil_div, keccak_256_vec, Hash, Validators};

#[derive(Clone, Debug, PartialEq)]
pub struct TrustedValidatorSet<'a> {
    inner: &'a ValidatorSet,
}

impl<'a> TrustedValidatorSet<'a> {
    pub fn validators(&self) -> &Validators {
        &self.inner.validators
    }

    pub fn checkpoint(&self) -> u64 {
        self.inner.checkpoint()
    }

    pub fn new(inner: &'a ValidatorSet) -> Self {
        Self { inner }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct UntrustedValidatorSet<'a> {
    inner: &'a ValidatorSet,
}

impl<'a> UntrustedValidatorSet<'a> {
    pub fn new(inner: &'a ValidatorSet) -> Self {
        Self { inner }
    }
    pub fn checkpoint(&self) -> u64 {
        self.inner.checkpoint()
    }
    pub fn try_borrow(
        &'a self,
        trusted_validators: &TrustedValidatorSet,
    ) -> Result<&'a Validators, Error> {
        let (result, found, required) = self.contains(trusted_validators);
        if result {
            return Ok(&self.inner.validators);
        }
        Err(Error::InsufficientTrustedValidatorsInUntrustedValidators(
            self.inner.hash,
            found,
            required,
        ))
    }

    fn contains(&self, trusted_validators: &TrustedValidatorSet) -> (bool, usize, usize) {
        let trusted_validators = trusted_validators.validators();
        let mut trusted_validator_count = 0;
        for x1 in &self.inner.validators {
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

#[derive(Clone, Debug, PartialEq)]
pub enum EitherValidatorSet<'a> {
    Trusted(TrustedValidatorSet<'a>),
    Untrusted(UntrustedValidatorSet<'a>),
}

impl<'a> EitherValidatorSet<'a> {
    pub fn checkpoint(&self) -> u64 {
        match self {
            EitherValidatorSet::Trusted(v) => v.checkpoint(),
            EitherValidatorSet::Untrusted(v) => v.checkpoint(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct ValidatorSet {
    pub validators: Validators,
    pub hash: Hash,
}

impl ValidatorSet {
    /// for example when the validator count is 21 the checkpoint is 211, 411, 611 ...
    /// https://github.com/bnb-chain/bsc/blob/48aaee69e9cb50fc2cedf1398ae4b98b099697db/consensus/parlia/parlia.go#L607
    /// https://github.com/bnb-chain/bsc/blob/48aaee69e9cb50fc2cedf1398ae4b98b099697db/consensus/parlia/snapshot.go#L191
    pub fn checkpoint(&self) -> u64 {
        let validator_size = self.validators.len() as u64;
        validator_size / 2 + 1
    }
}

impl From<Vec<Vec<u8>>> for ValidatorSet {
    fn from(value: Vec<Vec<u8>>) -> Self {
        let hash = keccak_256_vec(&value);
        Self {
            validators: value as Validators,
            hash,
        }
    }
}

#[cfg(test)]
mod test {
    use crate::errors::Error;
    use crate::header::validator_set::{TrustedValidatorSet, UntrustedValidatorSet, ValidatorSet};

    #[test]
    pub fn test_untrusted_validator_set_try_borrow() {
        let mut _assert_trusted = |x, y, c_val_borrowable| {
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
            let trusted_validators = TrustedValidatorSet::new(&trusted_validators);
            let untrusted_validators = ValidatorSet {
                validators: x,
                hash: [0; 32],
            };
            let untrusted_validators = UntrustedValidatorSet::new(&untrusted_validators);
            let (result, count, required) = untrusted_validators.contains(&trusted_validators);
            assert_eq!(result, c_val_borrowable);
            assert_eq!(count, y);
            assert_eq!(required, 3);
            match untrusted_validators.try_borrow(&trusted_validators) {
                Ok(borrowed) => {
                    if c_val_borrowable {
                        assert_eq!(*borrowed, untrusted_validators.inner.validators);
                    } else {
                        unreachable!("unexpected borrowed")
                    }
                }
                Err(e) => {
                    if c_val_borrowable {
                        unreachable!("unexpected error {:?}", e);
                    } else {
                        match e {
                            Error::InsufficientTrustedValidatorsInUntrustedValidators(_, _, _) => {}
                            e => unreachable!("unexpected error type {:?}", e),
                        }
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
}
