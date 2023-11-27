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
        let (trusted, _, _) = self.is_trustable(trusted_validators);
        self.trusted = trusted
    }

    fn is_trustable(&self, trusted_validators: &Validators) -> (bool, usize, usize) {
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
struct ValidatorRange {
    min_number_to_verify_seal: BlockNumber,
    min_number_to_verify_vote: BlockNumber,
    validators: Validators,
}

impl ValidatorRange {
    fn new(
        min_number_to_verify_seal: BlockNumber,
        min_number_to_verify_vote: BlockNumber,
        validators: Validators,
    ) -> Self {
        Self {
            min_number_to_verify_seal,
            min_number_to_verify_vote,
            validators,
        }
    }
}

#[derive(Clone, Debug)]
pub struct ValidatorRanges {
    inner: Vec<ValidatorRange>,
}

impl ValidatorRanges {
    pub fn new(
        hs: &[ETHHeader],
        p_val: &ValidatorSet,
        c_val: &ValidatorSet,
    ) -> Result<Self, Error> {
        let first = &hs[0];
        let mut validators = vec![];
        let mut p_val = p_val.clone();
        let mut c_val = c_val.clone();
        let mut epoch = (first.number / BLOCKS_PER_EPOCH) * BLOCKS_PER_EPOCH;
        let mut checkpoint = epoch + p_val.checkpoint();
        if first.number < checkpoint {
            // Default validators before checkpoint
            validators.push(ValidatorRange::new(
                first.number,
                first.number,
                p_val.validators()?.clone(),
            ));
        }
        let mut is_first_header_in_checkpoint = true;
        for h in hs {
            if h.number >= checkpoint {
                if is_first_header_in_checkpoint {
                    c_val.trust(p_val.validators()?);
                    validators.push(ValidatorRange::new(
                        checkpoint,
                        // At the just checkpoint BLS signature uses previous validator set.
                        checkpoint + 1,
                        c_val.validators()?.clone(),
                    ));
                    is_first_header_in_checkpoint = false;
                }

                let next_epoch = epoch + BLOCKS_PER_EPOCH;
                if h.number == next_epoch {
                    let n_val: ValidatorSet = h
                        .get_validator_bytes()
                        .ok_or_else(|| Error::MissingValidatorInEpochBlock(h.number))?
                        .into();
                    epoch = next_epoch;
                    checkpoint = next_epoch + c_val.checkpoint();
                    is_first_header_in_checkpoint = true;
                    p_val = c_val;
                    c_val = n_val;
                }
            }
        }
        validators.reverse();
        // ex) when target = 201 then
        // 611, 612, nn_val
        // 411, 412, n_val
        // 211, 212, c_val
        // 201, 201, p_val
        // ex) when target = 215
        // 611, 612, nn_val
        // 411, 412, n_val
        // 211, 212, c_val
        Ok(Self { inner: validators })
    }

    pub fn get_to_verify_seal(&self, number: BlockNumber) -> Result<&Validators, Error> {
        for range in &self.inner {
            if number >= range.min_number_to_verify_seal {
                return Ok(&range.validators);
            }
        }
        Err(Error::MissingValidatorToVerifySeal(number))
    }

    pub fn get_to_verify_vote(&self, number: BlockNumber) -> Result<&Validators, Error> {
        for range in &self.inner {
            if number >= range.min_number_to_verify_vote {
                return Ok(&range.validators);
            }
        }
        Err(Error::MissingValidatorToVerifyVote(number))
    }
}

#[cfg(test)]
mod test {
    use crate::errors::Error;
    use crate::header::constant::BLOCKS_PER_EPOCH;
    use crate::header::eth_header::{ETHHeader, EXTRA_SEAL, EXTRA_VANITY, VALIDATOR_BYTES_LENGTH};
    use crate::header::testdata::header_31297200;
    use crate::header::validator_set::{ValidatorRange, ValidatorRanges, ValidatorSet};
    use crate::misc::{ceil_div, Validators};
    use alloc::vec::Vec;

    #[test]
    pub fn test_get_to_verify_seal() {
        let v1 = vec![vec![1]];
        let r1 = ValidatorRange::new(2, 2, v1.clone());
        let ranges = ValidatorRanges { inner: vec![r1] };

        // success
        let result = ranges.get_to_verify_seal(2).unwrap();
        assert_eq!(*result, v1);

        // error
        match ranges.get_to_verify_seal(1).unwrap_err() {
            Error::MissingValidatorToVerifySeal(n) => {
                assert_eq!(n, 1);
            }
            err => unreachable!("err {:?}", err),
        }
    }

    #[test]
    pub fn test_get_to_verify_vote() {
        let v1 = vec![vec![1]];
        let r1 = ValidatorRange::new(2, 2, v1.clone());
        let ranges = ValidatorRanges { inner: vec![r1] };

        // success
        let result = ranges.get_to_verify_vote(2).unwrap();
        assert_eq!(*result, v1);

        // error
        match ranges.get_to_verify_vote(1).unwrap_err() {
            Error::MissingValidatorToVerifyVote(n) => {
                assert_eq!(n, 1);
            }
            err => unreachable!("err {:?}", err),
        }
    }

    #[test]
    pub fn test_success_new_validator_sets() {
        let base = header_31297200();
        let verify = |start, mut p_val: ValidatorSet, c_val| {
            p_val.trusted = true;
            let hs = create_headers(start, base.clone(), &p_val);
            let mut verify_result = ValidatorRanges::new(&hs, &p_val, &c_val).unwrap();
            verify_result.inner.reverse();
            verify_result
        };

        let assert_before_checkpoint =
            |result: ValidatorRanges, start: u64, p_val: ValidatorSet, c_val: ValidatorSet| {
                let first = base.number + start;
                let epoch = (first / BLOCKS_PER_EPOCH) * BLOCKS_PER_EPOCH;
                assert_eq!(6, result.inner.len());
                assert_eq!(result.inner[0].min_number_to_verify_seal, first, "0-min");
                assert_eq!(result.inner[0].validators, p_val.validators, "0-val");
                assert_eq!(
                    result.inner[1].min_number_to_verify_seal,
                    epoch + p_val.checkpoint()
                );
                assert_eq!(result.inner[1].validators, c_val.validators, "1-val");
                assert_eq!(
                    result.inner[2].min_number_to_verify_seal,
                    epoch + BLOCKS_PER_EPOCH + c_val.checkpoint()
                );
                assert_eq!(result.inner[2].validators, p_val.validators, "2-val");
                assert_eq!(
                    result.inner[3].min_number_to_verify_seal,
                    epoch + 2 * BLOCKS_PER_EPOCH + p_val.checkpoint()
                );
                assert_eq!(result.inner[3].validators, p_val.validators, "3-val");
                assert_eq!(
                    result.inner[4].min_number_to_verify_seal,
                    epoch + 3 * BLOCKS_PER_EPOCH + p_val.checkpoint()
                );
                assert_eq!(result.inner[4].validators, p_val.validators, "4-val");
                assert_eq!(
                    result.inner[5].min_number_to_verify_seal,
                    epoch + 4 * BLOCKS_PER_EPOCH + p_val.checkpoint()
                );
                assert_eq!(result.inner[5].validators, p_val.validators, "5-val");
            };

        let assert_eq_checkpoint =
            |result: ValidatorRanges, start: u64, p_val: ValidatorSet, c_val: ValidatorSet| {
                let first = base.number + start;
                let epoch = (first / BLOCKS_PER_EPOCH) * BLOCKS_PER_EPOCH;
                assert_eq!(5, result.inner.len());
                assert_eq!(
                    result.inner[0].min_number_to_verify_seal,
                    epoch + p_val.checkpoint(),
                    "0-min"
                );
                assert_eq!(result.inner[0].validators, c_val.validators, "0-val");
                assert_eq!(
                    result.inner[1].min_number_to_verify_seal,
                    epoch + BLOCKS_PER_EPOCH + c_val.checkpoint()
                );
                assert_eq!(result.inner[1].validators, p_val.validators, "1-val");
                assert_eq!(
                    result.inner[2].min_number_to_verify_seal,
                    epoch + 2 * BLOCKS_PER_EPOCH + p_val.checkpoint()
                );
                assert_eq!(result.inner[2].validators, p_val.validators, "2-val");
                assert_eq!(
                    result.inner[3].min_number_to_verify_seal,
                    epoch + 3 * BLOCKS_PER_EPOCH + p_val.checkpoint()
                );
                assert_eq!(result.inner[3].validators, p_val.validators, "3-val");
                assert_eq!(
                    result.inner[4].min_number_to_verify_seal,
                    epoch + 4 * BLOCKS_PER_EPOCH + p_val.checkpoint()
                );
                assert_eq!(result.inner[4].validators, p_val.validators, "4-val");
            };

        let assert_after_checkpoint =
            |result: ValidatorRanges, start: u64, p_val: ValidatorSet, c_val: ValidatorSet| {
                let first = base.number + start;
                let epoch = (first / BLOCKS_PER_EPOCH) * BLOCKS_PER_EPOCH;
                assert_eq!(6, result.inner.len(), "block={}", first);
                assert_eq!(
                    result.inner[0].min_number_to_verify_seal,
                    epoch + p_val.checkpoint(),
                    "0-min"
                );
                assert_eq!(result.inner[0].validators, c_val.validators, "0-val");
                assert_eq!(
                    result.inner[1].min_number_to_verify_seal,
                    epoch + BLOCKS_PER_EPOCH + c_val.checkpoint()
                );
                assert_eq!(result.inner[1].validators, p_val.validators, "1-val");
                assert_eq!(
                    result.inner[2].min_number_to_verify_seal,
                    epoch + 2 * BLOCKS_PER_EPOCH + p_val.checkpoint()
                );
                assert_eq!(result.inner[2].validators, p_val.validators, "2-val");
                assert_eq!(
                    result.inner[3].min_number_to_verify_seal,
                    epoch + 3 * BLOCKS_PER_EPOCH + p_val.checkpoint()
                );
                assert_eq!(result.inner[3].validators, p_val.validators, "3-val");
                assert_eq!(
                    result.inner[4].min_number_to_verify_seal,
                    epoch + 4 * BLOCKS_PER_EPOCH + p_val.checkpoint()
                );
                assert_eq!(result.inner[4].validators, p_val.validators, "4-val");
                assert_eq!(
                    result.inner[5].min_number_to_verify_seal,
                    epoch + 5 * BLOCKS_PER_EPOCH + p_val.checkpoint()
                );
                assert_eq!(result.inner[5].validators, p_val.validators, "5-val");
            };

        let gen = |p, c| {
            let mut p_val: Validators = vec![];
            for i in 0..p {
                p_val.push([i + 1_u8; VALIDATOR_BYTES_LENGTH].to_vec())
            }
            let mut c_val: Validators = vec![];
            for i in 0..c {
                if i <= ceil_div(p as usize, 3) as u8 {
                    c_val.push([i + 1_u8; VALIDATOR_BYTES_LENGTH].to_vec())
                } else {
                    c_val.push([i + 50_u8; VALIDATOR_BYTES_LENGTH].to_vec())
                }
            }
            (ValidatorSet::from(p_val), ValidatorSet::from(c_val))
        };

        let simple = gen(1, 3);
        let result = verify(0, simple.0.clone(), simple.1.clone());
        assert_before_checkpoint(result, 0, simple.0.clone(), simple.1.clone());
        let result = verify(1, simple.0.clone(), simple.1.clone());
        assert_eq_checkpoint(result, 1, simple.0.clone(), simple.1.clone());
        for i in 2..199 {
            let result = verify(i, simple.0.clone(), simple.1.clone());
            assert_after_checkpoint(result, i, simple.0.clone(), simple.1.clone());
        }

        let testnet = gen(7, 8);
        for i in 0..3 {
            let result = verify(i, testnet.0.clone(), testnet.1.clone());
            assert_before_checkpoint(result, i, testnet.0.clone(), testnet.1.clone());
        }
        let result = verify(4, testnet.0.clone(), testnet.1.clone());
        assert_eq_checkpoint(result, 4, testnet.0.clone(), testnet.1.clone());
        for i in 5..199 {
            let result = verify(i, testnet.0.clone(), testnet.1.clone());
            assert_after_checkpoint(result, i, testnet.0.clone(), testnet.1.clone());
        }

        let mainnet = gen(21, 21);
        for i in 0..11 {
            let result = verify(i, mainnet.0.clone(), mainnet.1.clone());
            assert_before_checkpoint(result, i, mainnet.0.clone(), mainnet.1.clone());
        }
        let result = verify(11, mainnet.0.clone(), mainnet.1.clone());
        assert_eq_checkpoint(result, 11, mainnet.0.clone(), mainnet.1.clone());
        for i in 12..199 {
            let result = verify(i, mainnet.0.clone(), mainnet.1.clone());
            assert_after_checkpoint(result, i, mainnet.0.clone(), mainnet.1.clone());
        }
    }

    #[test]
    pub fn test_error_new_validator_sets() {
        let gen = |p, c| {
            let mut p_val: Validators = vec![];
            for i in 0..p {
                p_val.push([i + 1_u8; VALIDATOR_BYTES_LENGTH].to_vec())
            }
            let mut c_val: Validators = vec![];
            for i in 0..c {
                c_val.push([i + 50_u8; VALIDATOR_BYTES_LENGTH].to_vec())
            }
            let mut p_val = ValidatorSet::from(p_val);
            p_val.trusted = true;
            (p_val, ValidatorSet::from(c_val))
        };

        let base = header_31297200();
        let (p_val, c_val) = gen(21, 21);
        let hs = create_headers(0, base, &p_val);
        let result = ValidatorRanges::new(&hs, &p_val, &c_val).unwrap_err();
        match result {
            Error::ValidatorNotTrusted(h) => {
                assert_eq!(h, c_val.hash);
            }
            err => unreachable!("err {:?}", err),
        }
    }

    fn create_extra_data(val: Validators) -> Vec<u8> {
        let mut extra_data = Vec::new();
        extra_data.extend([0u8; EXTRA_VANITY]);
        extra_data.extend([val.len() as u8; 1]);
        for v in val {
            extra_data.extend(v);
        }
        extra_data.extend([10; EXTRA_SEAL]);
        extra_data
    }

    fn create_headers(start: u64, base: ETHHeader, p_val: &ValidatorSet) -> Vec<ETHHeader> {
        let mut hs: Vec<ETHHeader> = vec![];
        for i in start..start + 1000 {
            let mut target = base.clone();
            target.number = base.number + i;
            if target.is_epoch() {
                target.extra_data = create_extra_data(p_val.clone().validators)
            } else {
                target.extra_data = vec![];
            }
            hs.push(target);
        }
        hs
    }

    #[test]
    fn test_trustable() {
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
            let (trusted, count, required) = untrusted_validators.is_trustable(&trusted_validators);
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
