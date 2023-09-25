use alloc::vec::Vec;

use light_client::types::Height;

use parlia_ibc_proto::ibc::lightclients::parlia::v1::EthHeader;

use crate::errors::Error;
use crate::misc::{ChainId, Validators};

use super::eth_header::ETHHeader;
use super::BLOCKS_PER_EPOCH;

#[derive(Clone, Debug, PartialEq)]
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
        // Ensure all the headers are successfully chained.
        for (i, header) in self.all.iter().enumerate() {
            if i < self.all.len() - 1 {
                let child = &self.all[i + 1];
                child.verify_cascading_fields(header)?;
            }
        }

        // Ensure valid seals
        let checkpoint = checkpoint(previous_validators);
        for h in self.all.iter() {
            if h.number % BLOCKS_PER_EPOCH >= checkpoint {
                h.verify_seal(current_validators, chain_id)?;
            } else {
                h.verify_seal(previous_validators, chain_id)?;
            }
        }

        // Ensure target is finalized
        self.verify_finalized()
    }

    fn verify_finalized(&self) -> Result<(), Error> {
        let mut errors: Vec<Error> = vec![];
        let headers = &self.all[0..self.all.len() - 2];
        for (i, header) in headers.iter().enumerate() {
            let child = &self.all[i + 1];
            let grand_child = &self.all[i + 2];
            if let Err(e) = child.verify_vote_attestation(header) {
                errors.push(e);
                continue;
            }
            let (grand_child_vote, _) = match grand_child.verify_vote_attestation(child) {
                Ok(vote) => vote,
                Err(e) => {
                    errors.push(e);
                    continue;
                }
            };
            if grand_child_vote.data.source_number == header.number
                || grand_child_vote.data.source_hash == header.hash
            {
                return Ok(());
            }
        }
        Err(Error::UnexpectedVoteRelation(
            self.target.number,
            self.all.len(),
            errors,
        ))
    }

    pub fn new(trusted_height: Height, value: Vec<EthHeader>) -> Result<ETHHeaders, Error> {
        let mut new_headers: Vec<ETHHeader> = Vec::with_capacity(value.len());
        for (i, header) in value.into_iter().enumerate() {
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

        Ok(ETHHeaders {
            target: target.clone(),
            all: new_headers,
        })
    }
}

/// for example when the validator count is 21 the checkpoint is 211, 411, 611 ...
/// https://github.com/bnb-chain/bsc/blob/48aaee69e9cb50fc2cedf1398ae4b98b099697db/consensus/parlia/parlia.go#L607
/// https://github.com/bnb-chain/bsc/blob/48aaee69e9cb50fc2cedf1398ae4b98b099697db/consensus/parlia/snapshot.go#L191
fn checkpoint(validators: &Validators) -> u64 {
    let validator_size = validators.len() as u64;
    validator_size / 2 + 1
}

#[cfg(test)]
mod test {
    use crate::errors::Error;
    use crate::header::eth_headers::ETHHeaders;
    use crate::header::testdata::*;

    #[test]
    fn test_success_verify_eth_headers_after_checkpoint() {
        let header = create_after_checkpoint_headers();
        let new_validator_set = header_31297200().get_validator_bytes().unwrap();
        let mainnet = &mainnet();

        let result = header.verify(mainnet, &new_validator_set, &vec![]);
        if let Err(e) = result {
            unreachable!("{:?}", e);
        }
    }

    #[test]
    fn test_error_verify_eth_headers_after_checkpoint() {
        let header = create_after_checkpoint_headers();
        let mut new_validator_set = header_31297200().get_validator_bytes().unwrap();
        new_validator_set.push(new_validator_set[0].clone());
        new_validator_set.push(new_validator_set[1].clone());

        let mainnet = &mainnet();
        let _result = header.verify(mainnet, &new_validator_set, &vec![]);
    }

    #[test]
    fn test_success_verify_eth_headers_before_checkpoint() {
        let header = create_before_checkpoint_headers();
        let previous_validator_set = validators_in_31297000();
        let mainnet = &mainnet();

        // new validator is unused
        let result = header.verify(mainnet, &vec![], &previous_validator_set);
        if let Err(e) = result {
            unreachable!("{:?}", e);
        }
    }

    #[test]
    fn test_error_verify_eth_headers_before_checkpoint() {
        let header = create_before_checkpoint_headers();

        let mainnet = &mainnet();
        let _result = header.verify(mainnet, &vec![], &vec![]);

        // first block uses previous broken validator set
        let mut previous_validator_set = validators_in_31297000();
        for v in previous_validator_set.iter_mut() {
            v.remove(0);
        }
        let result = header.verify(mainnet, &vec![], &previous_validator_set);
        match result.unwrap_err() {
            Error::MissingSignerInValidator(number, _) => {
                assert_eq!(number, header.target.number)
            }
            e => unreachable!("{:?}", e),
        }
    }

    #[test]
    fn test_success_verify_eth_headers_across_checkpoint() {
        let header = create_across_checkpoint_headers();
        let new_validator_set = header_31297200().get_validator_bytes().unwrap();
        let previous_validator_set = validators_in_31297000();
        let mainnet = &mainnet();

        // new validator is unused
        let result = header.verify(mainnet, &new_validator_set, &previous_validator_set);
        if let Err(e) = result {
            unreachable!("{:?}", e);
        }
    }

    #[test]
    fn test_error_verify_eth_headers_across_checkpoint() {
        let mut new_validator_set = header_31297200().get_validator_bytes().unwrap();
        let previous_validator_set = validators_in_31297000();

        let mainnet = &mainnet();

        // insufficient header for after checkpoint
        let mut header = create_across_checkpoint_headers();
        header.all.pop();
        let _result = header.verify(mainnet, &new_validator_set, &previous_validator_set);

        // last block uses new empty validator set
        let header = create_across_checkpoint_headers();
        for (i, v) in new_validator_set.iter_mut().enumerate() {
            v[0] = i as u8;
        }
        let result = header.verify(mainnet, &new_validator_set, &previous_validator_set);
        match result.unwrap_err() {
            Error::MissingSignerInValidator(number, _) => {
                //25428811 uses next validator
                assert_eq!(number, header.all[header.all.len() - 2].number)
            }
            e => unreachable!("{:?}", e),
        }
    }

    #[test]
    fn test_error_verify_no_finalized_header_found() {
        let mut header = create_after_checkpoint_headers();
        for h in header.all.iter_mut() {
            h.extra_data = vec![];
        }

        let _mainnet = &mainnet();
        let result = header.verify_finalized();
        match result.unwrap_err() {
            Error::UnexpectedVoteRelation(block, len, err) => {
                assert_eq!(block, header.target.number, "block error");
                assert_eq!(len, header.all.len(), "len");
                assert_eq!(err.len(), header.all.len() - 2);
            }
            e => unreachable!("{:?}", e),
        }
    }

    fn create_before_checkpoint_headers() -> ETHHeaders {
        let v = vec![
            header_31297200(),
            header_31297201(),
            header_31297202(),
            header_31297203(),
            header_31297204(),
            header_31297205(),
            header_31297206(),
            header_31297207(),
            header_31297208(),
            header_31297209(),
            header_31297210(),
        ];
        ETHHeaders {
            target: v[0].clone(),
            all: v,
        }
    }

    fn create_across_checkpoint_headers() -> ETHHeaders {
        let v = vec![
            header_31297202(),
            header_31297203(),
            header_31297204(),
            header_31297205(),
            header_31297206(),
            header_31297207(),
            header_31297208(),
            header_31297209(),
            header_31297210(),
            header_31297211(), // checkpoint
            header_31297212(),
        ];
        ETHHeaders {
            target: v[0].clone(),
            all: v,
        }
    }

    fn create_after_checkpoint_headers() -> ETHHeaders {
        let v = vec![
            header_31297211(), // checkpoint
            header_31297212(),
            header_31297213(),
            header_31297214(),
            header_31297215(),
            header_31297216(),
            header_31297217(),
            header_31297218(),
            header_31297219(),
            header_31297220(),
            header_31297221(),
        ];
        ETHHeaders {
            target: v[0].clone(),
            all: v,
        }
    }
}
