use alloc::collections::BTreeSet;
use alloc::vec::Vec;
use lcp_types::Height;

use parlia_ibc_proto::ibc::lightclients::parlia::v1::EthHeader;

use crate::errors::Error;
use crate::misc::{required_block_count_to_finalize, Address, ChainId, Validators};

use super::eth_header::ETHHeader;
use super::EPOCH_BLOCK_PERIOD;

#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct ETHHeaders {
    pub target: ETHHeader,
    pub all: Vec<ETHHeader>,
}

impl ETHHeaders {
    pub fn verify(
        &self,
        chain_id: &ChainId,
        new_validators: &Validators,
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

        self.verify_seals(chain_id, new_validators, previous_validators)
    }

    fn verify_seals(
        &self,
        chain_id: &ChainId,
        new_validators: &Validators,
        previous_validators: &Validators,
    ) -> Result<(), Error> {
        let headers = &self.all;
        let threshold = required_block_count_to_finalize(previous_validators);
        if self.target.number % EPOCH_BLOCK_PERIOD < threshold as u64 {
            // Validators created at previous epoch is used for consensus target header
            if headers.len() != threshold {
                return Err(Error::InsufficientHeaderToVerify(headers.len(), threshold));
            }

            let mut signers_before_checkpoint: BTreeSet<Address> = BTreeSet::default();
            let mut signers_after_checkpoint: BTreeSet<Address> = BTreeSet::default();
            for header in headers {
                if header.number % EPOCH_BLOCK_PERIOD < threshold as u64 {
                    // Each validator can sign only one header
                    let signer = header.verify_seal(previous_validators, chain_id)?;
                    if !signers_before_checkpoint.insert(signer) {
                        return Err(Error::UnexpectedDoubleSign(header.number, signer));
                    }
                } else {
                    // Current epoch validators is used after the checkpoint block.
                    let signer = header.verify_seal(new_validators, chain_id)?;
                    if !signers_after_checkpoint.insert(signer) {
                        return Err(Error::UnexpectedDoubleSign(header.number, signer));
                    }
                }
            }
        } else {
            // Validators created at current epoch is used for consensus target header
            let threshold = required_block_count_to_finalize(new_validators);
            if headers.len() != threshold {
                return Err(Error::InsufficientHeaderToVerify(headers.len(), threshold));
            }
            let mut signers: BTreeSet<Address> = BTreeSet::default();
            for header in headers {
                let signer = header.verify_seal(new_validators, chain_id)?;
                if !signers.insert(signer) {
                    return Err(Error::UnexpectedDoubleSign(header.number, signer));
                }
            }
        }

        Ok(())
    }

    pub fn new(trusted_height: Height, value: &[EthHeader]) -> Result<ETHHeaders, Error> {
        let mut new_headers: Vec<ETHHeader> = Vec::with_capacity(value.len());
        for header in value {
            new_headers.push(header.try_into()?);
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

#[cfg(test)]
mod test {
    use crate::errors::Error;
    use crate::header::testdata::*;
    use crate::misc::required_block_count_to_finalize;

    #[test]
    fn test_success_verify_eth_headers_after_checkpoint() {
        let header = create_after_checkpoint_headers();
        let new_validator_set = fill(create_epoch_block()).new_validators;
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
        let mut new_validator_set = fill(create_epoch_block()).new_validators;
        new_validator_set.push(new_validator_set[0].clone());
        new_validator_set.push(new_validator_set[1].clone());

        let mainnet = &mainnet();
        let result = header.headers.verify(mainnet, &new_validator_set, &vec![]);
        match result.unwrap_err() {
            Error::InsufficientHeaderToVerify(actual, expected) => {
                assert_eq!(actual, header.headers.all.len(), "actual error");
                assert_eq!(
                    expected,
                    required_block_count_to_finalize(&new_validator_set),
                    "expected error"
                );
            }
            e => unreachable!("{:?}", e),
        }
    }

    #[test]
    fn test_success_verify_eth_headers_before_checkpoint() {
        let header = create_before_checkpoint_headers();
        let previous_validator_set = fill(create_previous_epoch_block()).new_validators;
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
                assert_eq!(expected, 0, "expected error");
            }
            e => unreachable!("{:?}", e),
        }

        // first block uses previous broken validator set
        let mut previous_validator_set = fill(create_previous_epoch_block()).new_validators;
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
        let new_validator_set = fill(create_epoch_block()).new_validators;
        let previous_validator_set = fill(create_previous_epoch_block()).new_validators;
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
        let header = create_across_checkpoint_headers();

        let mainnet = &mainnet();
        let result = header.headers.verify(mainnet, &vec![], &vec![]);
        match result.unwrap_err() {
            Error::InsufficientHeaderToVerify(actual, expected) => {
                assert_eq!(actual, header.headers.all.len(), "actual error");
                assert_eq!(expected, 0, "expected error");
            }
            e => unreachable!("{:?}", e),
        }

        // last block uses new empty validator set
        let previous_validator_set = fill(create_previous_epoch_block()).new_validators;
        let result = header
            .headers
            .verify(mainnet, &vec![], &previous_validator_set);
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
        let new_validator_set = fill(create_epoch_block()).new_validators;
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
