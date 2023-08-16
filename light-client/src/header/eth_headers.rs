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
    /// target header
    pub target: ETHHeader,
    /// target header and headers to finalize target header
    /// first element is target header
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
        if height_from_epoch == 0 {
            // epoch
            if headers.len() != threshold {
                return Err(Error::InsufficientHeaderToVerify(
                    self.target.number,
                    headers.len(),
                    threshold,
                ));
            }
            self.verify_finalized(chain_id, headers, previous_validators)?;
        } else if (height_from_epoch as usize) < threshold {
            // across checkpoint

            let mut headers_before_checkpoint: Vec<ETHHeader> = vec![];
            let mut headers_after_checkpoint: Vec<ETHHeader> = vec![];
            for h in headers.iter() {
                if h.number % BLOCKS_PER_EPOCH >= threshold as u64 {
                    headers_after_checkpoint.push(h.clone());
                } else {
                    headers_before_checkpoint.push(h.clone());
                }
            }

            let required_count_before_checkpoint = threshold - height_from_epoch as usize;
            if headers_before_checkpoint.len() != required_count_before_checkpoint {
                return Err(Error::InsufficientHeaderToVerify(
                    self.target.number,
                    headers_before_checkpoint.len(),
                    required_count_before_checkpoint,
                ));
            }

            let mut signers =
                self.verify_finalized(chain_id, &headers_before_checkpoint, previous_validators)?;
            let signers_after_checkpoint =
                self.verify_finalized(chain_id, &headers_after_checkpoint, current_validators)?;
            let signers_after_checkpoint_size = signers_after_checkpoint.len();
            for signer in signers_after_checkpoint {
                signers.insert(signer);
            }
            if signers.len() < threshold {
                return Err(Error::InsufficientHeaderToVerifyAcrossCheckpoint(
                    self.target.number,
                    height_from_epoch,
                    signers.len(),
                    threshold,
                    signers_after_checkpoint_size,
                ));
            }
        } else {
            // after checkpoint
            let threshold = required_header_count_to_finalize(current_validators);
            if headers.len() != threshold {
                return Err(Error::InsufficientHeaderToVerify(
                    self.target.number,
                    headers.len(),
                    threshold,
                ));
            }
            self.verify_finalized(chain_id, headers, current_validators)?;
        }
        Ok(())
    }

    fn verify_finalized(
        &self,
        chain_id: &ChainId,
        headers: &[ETHHeader],
        validators: &Validators,
    ) -> Result<BTreeSet<Address>, Error> {
        // signer must be unique
        let mut signers: BTreeSet<Address> = BTreeSet::default();
        for header in headers {
            let signer = header.verify_seal(validators, chain_id)?;
            if !signers.insert(signer) {
                return Err(Error::UnexpectedDoubleSign(header.number, signer));
            }
        }
        Ok(signers)
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

#[cfg(test)]
mod test {
    use crate::errors::Error;
    use crate::header::eth_headers::required_header_count_to_finalize;
    use crate::header::testdata::*;

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
            Error::InsufficientHeaderToVerify(_, actual, expected) => {
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
            Error::InsufficientHeaderToVerify(_, actual, expected) => {
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

        // insufficient header for after checkpoint
        let mut header = create_across_checkpoint_headers();
        header.headers.all.pop();
        let result = header
            .headers
            .verify(mainnet, &new_validator_set, &previous_validator_set);
        match result.unwrap_err() {
            Error::InsufficientHeaderToVerifyAcrossCheckpoint(
                _,
                height_from_epoch,
                total_signers,
                threshold,
                current_signers,
            ) => {
                assert_eq!(height_from_epoch, 2, "height_from_epoch error");
                assert_eq!(total_signers, 10, "total_signers error");
                assert_eq!(threshold, 11, "threshold error");
                assert_eq!(current_signers, 1, "current_signers error");
            }
            e => unreachable!("{:?}", e),
        }

        // last block uses new empty validator set
        let header = create_across_checkpoint_headers();
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
