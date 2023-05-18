use alloc::collections::BTreeSet;
use alloc::vec::Vec;

use lcp_types::Height;

use parlia_ibc_proto::ibc::lightclients::parlia::v1::EthHeader;

use crate::errors::Error;
use crate::misc::{Address, ChainId, Validators};

use super::eth_header::ETHHeader;
use super::BLOCKS_PER_EPOCH;

#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct ETHHeaders {
    pub target: ETHHeader,
    pub all: Vec<ETHHeader>,
}

impl ETHHeaders {
    pub fn verify(
        &self,
        chain_id: &ChainId,
        current_validators: &Validators,
        previous_validators: &Validators,
    ) -> Result<(), Error> {
        let headers = &self.all;

        // Ensure all the headers are successfully chained.
        for (i, header) in headers.iter().enumerate() {
            if i < headers.len() - 1 {
                let child = &headers[i + 1];
                child.verify_cascading_fields(header)?;
            }
        }

        self.verify_seals(chain_id, current_validators, previous_validators)
    }

    fn verify_seals(
        &self,
        chain_id: &ChainId,
        current_validators: &Validators,
        previous_validators: &Validators,
    ) -> Result<(), Error> {
        let headers = &self.all;
        let threshold = required_header_count_to_finalize(previous_validators);
        let height_from_epoch = self.target.number % BLOCKS_PER_EPOCH;
        if height_from_epoch < threshold as u64 {
            // before checkpoint
            let header_count_to_verify = if height_from_epoch > 0 {
                // there are verifying headers between checkpoint.
                required_header_count_to_verify_between_checkpoint(
                    height_from_epoch as usize,
                    threshold,
                    previous_validators,
                    current_validators,
                )?
            } else {
                threshold
            };
            if headers.len() != header_count_to_verify {
                return Err(Error::InsufficientHeaderToVerify(
                    headers.len(),
                    header_count_to_verify,
                ));
            }

            let mut signers_before_checkpoint: BTreeSet<Address> = BTreeSet::default();
            let mut signers_after_checkpoint: BTreeSet<Address> = BTreeSet::default();
            for header in headers {
                if header.number % BLOCKS_PER_EPOCH < threshold as u64 {
                    // Each validator can sign only one header
                    let signer = header.verify_seal(previous_validators, chain_id)?;
                    if !signers_before_checkpoint.insert(signer) {
                        return Err(Error::UnexpectedDoubleSign(header.number, signer));
                    }
                } else {
                    // Current epoch validators is used after the checkpoint block.
                    let signer = header.verify_seal(current_validators, chain_id)?;
                    if !signers_after_checkpoint.insert(signer) {
                        return Err(Error::UnexpectedDoubleSign(header.number, signer));
                    }
                }
            }
        } else {
            let threshold = required_header_count_to_finalize(current_validators);
            if headers.len() != threshold {
                return Err(Error::InsufficientHeaderToVerify(headers.len(), threshold));
            }
            let mut signers: BTreeSet<Address> = BTreeSet::default();
            for header in headers {
                let signer = header.verify_seal(current_validators, chain_id)?;
                if !signers.insert(signer) {
                    return Err(Error::UnexpectedDoubleSign(header.number, signer));
                }
            }
        }

        Ok(())
    }

    pub fn new(trusted_height: Height, value: &[EthHeader]) -> Result<ETHHeaders, Error> {
        let mut new_headers: Vec<ETHHeader> = Vec::with_capacity(value.len());
        for (i, header) in value.iter().enumerate() {
            new_headers.push(
                header
                    .try_into()
                    .map_err(|e| Error::UnexpectedHeader(i, alloc::boxed::Box::new(e)))?,
            );
        }
        let target = match new_headers.first() {
            Some(v) => v,
            None => return Err(Error::EmptyHeader),
        };

        // Ensure target height is greater than or equals to trusted height.
        let trusted_header_height = trusted_height.revision_height();
        if target.number <= trusted_header_height {
            return Err(Error::UnexpectedTrustedHeight(
                target.number,
                trusted_header_height,
            ));
        }

        // Ensure valid correlation
        for (i, parent) in new_headers.iter().enumerate() {
            if let Some(child) = new_headers.get(i + 1) {
                child.verify_cascading_fields(parent)?;
            }
        }

        Ok(ETHHeaders {
            target: target.clone(),
            all: new_headers,
        })
    }
}

fn required_header_count_to_finalize(validators: &Validators) -> usize {
    let validator_size = validators.len();
    validator_size / 2 + 1
}

fn required_header_count_to_verify_between_checkpoint(
    height_from_epoch: usize,
    threshold: usize,
    previous_epoch_validators: &Validators,
    current_epoch_validators: &Validators,
) -> Result<usize, Error> {
    let before_checkpoint_count = threshold - height_from_epoch;
    let after_checkpoint_count = height_from_epoch;

    if previous_epoch_validators.len() < before_checkpoint_count {
        return Err(Error::InsufficientPreviousValidators(
            previous_epoch_validators.len(),
            before_checkpoint_count,
        ));
    }
    if current_epoch_validators.len() < after_checkpoint_count {
        return Err(Error::InsufficientCurrentValidators(
            current_epoch_validators.len(),
            after_checkpoint_count,
        ));
    }

    // Get duplicated validators between current epoch and previous epoch.
    let validators_to_verify_before_checkpoint =
        &previous_epoch_validators[0..before_checkpoint_count];
    let mut duplicated_validators_count = 0;
    let validators_to_verify_after_checkpoint =
        &current_epoch_validators[0..after_checkpoint_count];
    for a_validator in validators_to_verify_after_checkpoint.iter() {
        for b_validator in validators_to_verify_before_checkpoint.iter() {
            // same validator is used
            if a_validator == b_validator {
                duplicated_validators_count += 1
            }
        }
    }

    // Increase the number of header to verify by the amount of duplicates
    let mut increasing = 0;
    let rest_validators_after_checkpoint = &current_epoch_validators[after_checkpoint_count..];
    for r_validator in rest_validators_after_checkpoint.iter() {
        if duplicated_validators_count == 0 {
            break;
        }
        increasing += 1;
        if !validators_to_verify_after_checkpoint.contains(r_validator) {
            duplicated_validators_count -= 1;
        }
    }
    return Ok(threshold + increasing);
}

#[cfg(test)]
mod test {
    use crate::errors::Error;
    use crate::header::eth_headers::required_header_count_to_finalize;
    use crate::header::testdata::*;
    use hex_literal::hex;

    #[test]
    fn test_success_verify_eth_headers_after_checkpoint() {
        let header = create_after_checkpoint_headers();
        let new_validator_set = create_epoch_block().new_validators;
        let mainnet = &mainnet();

        // previous validator is unused
        let result = header.headers.verify(mainnet, &new_validator_set, &vec![]);
        if let Err(e) = result {
            unreachable!("{:?}", e);
        }
    }

    #[test]
    fn test_error_verify_eth_headers_after_checkpoint() {
        let header = create_after_checkpoint_headers();
        let mut new_validator_set = create_epoch_block().new_validators;
        new_validator_set.push(new_validator_set[0].clone());
        new_validator_set.push(new_validator_set[1].clone());

        let mainnet = &mainnet();
        let result = header.headers.verify(mainnet, &new_validator_set, &vec![]);
        match result.unwrap_err() {
            Error::InsufficientHeaderToVerify(actual, expected) => {
                assert_eq!(actual, header.headers.all.len(), "actual error");
                assert_eq!(
                    expected,
                    required_header_count_to_finalize(&new_validator_set),
                    "expected error"
                );
            }
            e => unreachable!("{:?}", e),
        }
    }

    #[test]
    fn test_success_verify_eth_headers_before_checkpoint() {
        let header = create_before_checkpoint_headers();
        let previous_validator_set = create_previous_epoch_block().new_validators;
        let mainnet = &mainnet();

        // new validator is unused
        let result = header
            .headers
            .verify(mainnet, &vec![], &previous_validator_set);
        if let Err(e) = result {
            unreachable!("{:?}", e);
        }
    }

    #[test]
    fn test_error_verify_eth_headers_before_checkpoint() {
        let header = create_before_checkpoint_headers();

        let mainnet = &mainnet();
        let result = header.headers.verify(mainnet, &vec![], &vec![]);
        match result.unwrap_err() {
            Error::InsufficientHeaderToVerify(actual, expected) => {
                assert_eq!(actual, header.headers.all.len(), "actual error");
                assert_eq!(expected, 1, "expected error");
            }
            e => unreachable!("{:?}", e),
        }

        // first block uses previous broken validator set
        let mut previous_validator_set = create_previous_epoch_block().new_validators;
        for v in previous_validator_set.iter_mut() {
            v.pop();
        }
        let result = header
            .headers
            .verify(mainnet, &vec![], &previous_validator_set);
        match result.unwrap_err() {
            Error::MissingSignerInValidator(number, _) => {
                assert_eq!(number, header.headers.target.number)
            }
            e => unreachable!("{:?}", e),
        }
    }

    #[test]
    fn test_success_verify_eth_headers_across_checkpoint() {
        let header = create_across_checkpoint_headers();
        let new_validator_set = create_epoch_block().new_validators;
        let previous_validator_set = create_previous_epoch_block().new_validators;
        let mainnet = &mainnet();

        // new validator is unused
        let result = header
            .headers
            .verify(mainnet, &new_validator_set, &previous_validator_set);
        if let Err(e) = result {
            unreachable!("{:?}", e);
        }
    }

    #[test]
    fn test_error_verify_eth_headers_across_checkpoint() {
        let mut new_validator_set = create_epoch_block().new_validators;
        let previous_validator_set = create_previous_epoch_block().new_validators;

        let mainnet = &mainnet();

        // insufficient header
        let mut header = create_across_checkpoint_headers();
        header.headers.all.pop();
        let result = header
            .headers
            .verify(mainnet, &new_validator_set, &previous_validator_set);
        match result.unwrap_err() {
            Error::InsufficientHeaderToVerify(actual, expected) => {
                assert_eq!(actual, 11, "actual error");
                assert_eq!(expected, 12, "expected error");
            }
            e => unreachable!("{:?}", e),
        }

        // last block uses new empty validator set
        for (i, v) in new_validator_set.iter_mut().enumerate() {
            v[0] = i as u8;
        }
        let result = header
            .headers
            .verify(mainnet, &new_validator_set, &previous_validator_set);
        match result.unwrap_err() {
            Error::MissingSignerInValidator(number, _) => {
                //25428811 uses next validator
                assert_eq!(
                    number,
                    header.headers.all[header.headers.all.len() - 2].number
                )
            }
            e => unreachable!("{:?}", e),
        }
    }

    #[test]
    fn test_error_verify_seals() {
        let mut header = create_after_checkpoint_headers();
        let new_validator_set = create_epoch_block().new_validators;
        header.headers.all[1] = header.headers.all[0].clone();

        let mainnet = &mainnet();
        let result = header
            .headers
            .verify_seals(mainnet, &new_validator_set, &vec![]);
        match result.unwrap_err() {
            Error::UnexpectedDoubleSign(block, _) => {
                assert_eq!(block, header.headers.all[1].number, "block error");
            }
            e => unreachable!("{:?}", e),
        }
    }
}
