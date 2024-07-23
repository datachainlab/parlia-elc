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

    pub fn new(inner: &'a Epoch) -> Self {
        Self { inner }
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
    pub fn try_borrow(&'a self, trusted_epoch: &TrustedEpoch) -> Result<&'a Validators, Error> {
        let (result, found, required) = self.contains(trusted_epoch);
        if result {
            return Ok(self.inner.validators());
        }
        Err(Error::InsufficientTrustedValidatorsInUntrustedValidators(
            self.inner.hash,
            found,
            required,
        ))
    }

    fn contains(&self, trusted_epoch: &TrustedEpoch) -> (bool, usize, usize) {
        let trusted_validators = trusted_epoch.validators();
        let mut trusted_validator_count = 0;
        for x1 in self.inner.validators() {
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
}

#[cfg(test)]
mod test {
    use crate::errors::Error;
    use crate::header::epoch::{Epoch, TrustedEpoch, UntrustedEpoch, ValidatorSet};

    #[test]
    pub fn test_untrusted_epoch_try_borrow() {
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
            let trusted_epoch = Epoch::new(trusted_validators, 1);
            let trusted_epoch = TrustedEpoch::new(&trusted_epoch);
            let untrusted_epoch = Epoch::new(
                ValidatorSet {
                    validators: x,
                    hash: [0; 32],
                },
                1,
            );
            let untrusted_epoch = UntrustedEpoch::new(&untrusted_epoch);
            let (result, count, required) = untrusted_epoch.contains(&trusted_epoch);
            assert_eq!(result, c_val_borrowable);
            assert_eq!(count, y);
            assert_eq!(required, 3);
            match untrusted_epoch.try_borrow(&trusted_epoch) {
                Ok(borrowed) => {
                    if c_val_borrowable {
                        assert_eq!(borrowed, untrusted_epoch.inner.validators());
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
