use alloc::vec::Vec;
use parlia_ibc_proto::ibc::lightclients::parlia::v1::EthHeader;

use crate::errors::Error;
use crate::header::epoch::EitherEpoch::{Trusted, Untrusted};
use crate::header::epoch::{EitherEpoch, Epoch, TrustedEpoch};

use crate::misc::{BlockNumber, ChainId, Validators};

use super::eth_header::ETHHeader;

#[derive(Clone, Debug, PartialEq)]
pub struct ETHHeaders {
    pub target: ETHHeader,
    pub all: Vec<ETHHeader>,
}

impl ETHHeaders {
    /// Verifies the headers in the `ETHHeaders` struct.
    ///
    /// This function performs several checks to ensure the validity of the headers:
    /// 1. Ensures the header after the next or next checkpoint does not exist.
    /// 2. Verifies the size of the headers within the specified epoch range.
    /// 3. Ensures all headers are successfully chained.
    /// 4. Validates the seals of all headers.
    /// 5. Ensures the target header is finalized.
    /// 6. Ensures the BLS signature is correct.
    pub fn verify(
        &self,
        chain_id: &ChainId,
        current_epoch: &EitherEpoch,
        previous_epoch: &TrustedEpoch,
    ) -> Result<(), Error> {
        // Ensure the header after the next or next checkpoint must not exist.
        let current_epoch_block_number = self.target.current_epoch_block_number()?;
        let checkpoint = current_epoch_block_number + previous_epoch.checkpoint();

        let next_epoch_info =
            self.verify_header_size(checkpoint, current_epoch, current_epoch_block_number)?;

        // Ensure all the headers are successfully chained.
        self.verify_cascading_fields()?;

        // Ensure valid seals
        let p_val = previous_epoch.validators();
        for h in self.all.iter() {
            if next_epoch_info.is_some()
                && h.number >= next_epoch_info.as_ref().unwrap().next_checkpoint
            {
                h.verify_seal(&next_epoch_info.as_ref().unwrap().next_epoch, chain_id)?;
            } else if h.number >= checkpoint {
                h.verify_seal(current_epoch.epoch(), chain_id)?;
            } else {
                h.verify_seal(previous_epoch.epoch(), chain_id)?;
            }
        }

        // Ensure target is finalized
        let (child, grand_child) = self.verify_finalized()?;

        // Ensure BLS signature is correct
        // At the just checkpoint BLS signature uses previous validator set.
        let mut last_voters: Validators = Vec::new();
        for h in &[child, grand_child] {
            let vote = h.get_vote_attestation()?;
            last_voters = if next_epoch_info.is_some()
                && h.number > next_epoch_info.as_ref().unwrap().next_checkpoint
            {
                vote.verify(
                    h.number,
                    next_epoch_info.as_ref().unwrap().next_epoch.validators(),
                )?
            } else if h.number > checkpoint {
                vote.verify(h.number, current_epoch.epoch().validators())?
            } else {
                vote.verify(h.number, p_val)?
            };
        }

        // Ensure voters for grand child are valid
        verify_voters(
            &last_voters,
            grand_child,
            next_epoch_info.map(|e| e.next_checkpoint),
            checkpoint,
            current_epoch,
            previous_epoch,
        )?;

        Ok(())
    }

    /// Verifies that all headers in the `all` vector have valid cascading fields.
    ///
    /// This function iterates through the `all` vector of `ETHHeader` objects and ensures that each
    /// header (except the last one) has valid cascading fields with its subsequent header.
    fn verify_cascading_fields(&self) -> Result<(), Error> {
        for (i, header) in self.all.iter().enumerate() {
            if i < self.all.len() - 1 {
                let child = &self.all[i + 1];
                child.verify_cascading_fields(header)?;
            }
        }
        Ok(())
    }

    /// Verifies that the headers are finalized.
    ///
    /// ex)
    /// 72486611 -> target 72486610 -> target 72486608
    /// 72486611 --------------------> source 72486608
    ///
    /// 72486610 -> target 72486608 -> target 72486607
    /// 72486610 --------------------> source 72486607
    ///
    /// 72476712 -> target 72476710 -> target 72476708
    /// 72476712 --------------------> source 72476708
    ///
    /// No extra headers after a valid grand child are acceptable.
    fn verify_finalized(&self) -> Result<(&ETHHeader, &ETHHeader), Error> {
        if self.all.len() < 3 {
            return Err(Error::InvalidVerifyingHeaderLength(
                self.target.number,
                self.all.len(),
            ));
        }
        let mut last_error: Option<Error> = None;
        for i in 0..self.all.len() - 2 {
            let finalized = &self.all[i];

            // child: descendant whose vote.TargetNumber == finalized.Number
            for j in (i + 1)..self.all.len() - 1 {
                let child = &self.all[j];

                // Ensure the relation between child and finalized is correct
                if let Err(err) = child.verify_target_attestation(finalized) {
                    last_error = Some(err);
                    continue;
                }

                // grandChild: descendant whose vote.TargetNumber == child.Number and vote.SourceNumber == child.TargetNumber
                for k in (j + 1)..self.all.len() {
                    let grand_child = &self.all[k];

                    // Ensure distance is less than or equal to k_ancestor_generation_depth
                    if (k - j) > grand_child.k_ancestor_generation_depth as usize {
                        break;
                    }

                    // Ensure the relation between grand child and child is correct
                    if let Err(err) = grand_child.verify_vote_attestation(child) {
                        last_error = Some(err);
                        continue;
                    }

                    // Ensure no extra headers
                    if k != self.all.len() - 1 {
                        return Err(Error::UnexpectedTooManyHeadersToFinalize(
                            self.target.number,
                            self.all.len(),
                        ));
                    }
                    return Ok((child, grand_child));
                }
            }
        }
        Err(Error::UnexpectedVoteRelation(
            self.target.number,
            self.all.len(),
            last_error.map(alloc::boxed::Box::new),
        ))
    }

    /// Verifies the size of the headers within the specified epoch range.
    ///
    /// This function filters the headers to include only those that are within the specified
    /// checkpoint range and ensures that they meet the size requirements for the current and next epochs.
    fn verify_header_size(
        &self,
        current_checkpoint: u64,
        current_epoch: &EitherEpoch,
        current_epoch_block_number: BlockNumber,
    ) -> Result<Option<NextEpochInfo>, Error> {
        let after_checkpoint: Vec<&ETHHeader> = self
            .all
            .iter()
            .filter(|h| h.number >= current_checkpoint)
            .collect();

        match current_epoch {
            // ex) t=200 then  200 <= h < 411 (at least 1 honest c_val(200)' can be in p_val)
            Untrusted(_) => {
                // Ensure headers are before the next_checkpoint
                let next_epoch_info = find_next_epoch(
                    &after_checkpoint,
                    current_epoch.checkpoint(),
                    current_epoch_block_number,
                )?;
                if let Some(next_epoch_info) = next_epoch_info.as_ref() {
                    if after_checkpoint
                        .iter()
                        .any(|h| h.number >= next_epoch_info.next_checkpoint)
                    {
                        return Err(Error::UnexpectedNextCheckpointHeader(
                            self.target.number,
                            next_epoch_info.next_checkpoint,
                        ));
                    }
                }
                Ok(next_epoch_info)
            }
            // ex) t=201 then 201 <= h < 611 (at least 1 honest n_val(400) can be in c_val(200))
            Trusted(_) => {
                // Get next_epoch if epoch after checkpoint ex) 400
                let next_epoch_info = find_next_epoch(
                    &after_checkpoint,
                    current_epoch.checkpoint(),
                    current_epoch_block_number,
                )?;
                let next_epoch_info = match next_epoch_info.as_ref() {
                    None => return Ok(next_epoch_info),
                    Some(v) => v,
                };

                // Finish if no headers over next checkpoint were found
                let after_next_checkpoint: Vec<&ETHHeader> = after_checkpoint
                    .into_iter()
                    .filter(|h| h.number >= next_epoch_info.next_checkpoint)
                    .collect();
                if after_next_checkpoint.is_empty() {
                    return Ok(Some(next_epoch_info.clone()));
                }

                // Ensure headers are before the next_next_checkpoint
                let next_next_epoch_info = find_next_epoch(
                    &after_next_checkpoint,
                    next_epoch_info.next_epoch.checkpoint(),
                    next_epoch_info.next_epoch_block_number,
                )?;
                if let Some(next_next_epoch_info) = next_next_epoch_info {
                    if after_next_checkpoint
                        .iter()
                        .any(|h| h.number >= next_next_epoch_info.next_checkpoint)
                    {
                        return Err(Error::UnexpectedNextNextCheckpointHeader(
                            self.target.number,
                            next_next_epoch_info.next_checkpoint,
                        ));
                    }
                }
                Ok(Some(next_epoch_info.clone()))
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
struct NextEpochInfo {
    next_epoch: Epoch,
    next_checkpoint: BlockNumber,
    next_epoch_block_number: BlockNumber,
}

impl NextEpochInfo {
    fn new(
        next_epoch: Epoch,
        next_checkpoint: BlockNumber,
        next_epoch_block_number: BlockNumber,
    ) -> Self {
        NextEpochInfo {
            next_epoch,
            next_checkpoint,
            next_epoch_block_number,
        }
    }
}

/// Finds the next epoch information based on the given headers.
///
/// This function iterates through the provided headers to find the next epoch information.
/// It checks if the current epoch block number matches the header number and retrieves the next epoch details.
fn find_next_epoch(
    hs: &[&ETHHeader],
    height_to_checkpoint: u64,
    expected_prev_epoch_number: BlockNumber,
) -> Result<Option<NextEpochInfo>, Error> {
    for h in hs.iter() {
        let self_current_epoch_number = h.current_epoch_block_number().map_err(|e| {
            Error::UnexpectedMissingForkSpecInCurrentEpochCalculation(
                h.number,
                alloc::boxed::Box::new(e),
            )
        })?;
        if self_current_epoch_number == h.number {
            return if let Some(next_epoch) = &h.epoch {
                let self_previous_epoch_number = h.previous_epoch_block_number().map_err(|e| {
                    Error::UnexpectedMissingForkSpecInPreviousEpochCalculation(
                        h.number,
                        alloc::boxed::Box::new(e),
                    )
                })?;
                if self_previous_epoch_number != expected_prev_epoch_number {
                    return Err(Error::UnexpectedPreviousEpochInCalculatingNextEpoch(
                        h.number,
                        self_previous_epoch_number,
                        expected_prev_epoch_number,
                    ));
                }
                let next_checkpoint = h.number + height_to_checkpoint;
                Ok(Some(NextEpochInfo::new(
                    next_epoch.clone(),
                    next_checkpoint,
                    self_current_epoch_number,
                )))
            } else {
                Err(Error::MissingEpochInfo(h.number))
            };
        } else if h.is_epoch() {
            return Err(Error::UnexpectedEpochInfo(
                h.number,
                self_current_epoch_number,
            ));
        }
    }
    Ok(None)
}

impl TryFrom<Vec<EthHeader>> for ETHHeaders {
    type Error = Error;

    fn try_from(value: Vec<EthHeader>) -> Result<Self, Self::Error> {
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

        Ok(ETHHeaders {
            target: target.clone(),
            all: new_headers,
        })
    }
}

fn verify_voters(
    voters: &Validators,
    h: &ETHHeader,
    next_checkpoint: Option<BlockNumber>,
    checkpoint: BlockNumber,
    current_epoch: &EitherEpoch,
    previous_epoch: &TrustedEpoch,
) -> Result<(), Error> {
    if next_checkpoint.is_some() && h.number > next_checkpoint.unwrap() {
        match current_epoch {
            Trusted(e) => e.verify_untrusted_voters(voters)?,
            _ => {
                return Err(Error::UnexpectedUntrustedValidators(
                    h.number,
                    next_checkpoint.unwrap(),
                ))
            }
        }
    } else if h.number > checkpoint {
        if let Untrusted(_) = current_epoch {
            previous_epoch.verify_untrusted_voters(voters)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod test {
    use crate::errors::Error;

    use crate::header::eth_header::{get_validator_bytes_and_turn_length, ETHHeader};
    use crate::header::eth_headers::{verify_voters, ETHHeaders};

    use crate::fixture::*;
    use crate::header::epoch::{EitherEpoch, Epoch, TrustedEpoch, UntrustedEpoch};

    use crate::misc::Validators;
    use hex_literal::hex;

    use crate::fork_spec::{ForkSpec, HeightOrTimestamp};
    use rstest::rstest;
    use std::prelude::rust_2015::{Box, Vec};
    use std::vec;

    fn trust(v: &Epoch) -> TrustedEpoch {
        TrustedEpoch::new(v)
    }

    fn untrust(v: &Epoch) -> UntrustedEpoch {
        UntrustedEpoch::new(v)
    }

    fn empty() -> Epoch {
        let validators: Validators = vec![];
        Epoch::new(validators.into(), 1)
    }

    #[rstest]
    #[case::localnet(localnet())]
    fn test_success_verify_before_checkpoint(#[case] hp: Box<dyn Network>) {
        let headers = hp.headers_before_checkpoint();
        let p_val = hp.previous_epoch_header().epoch.unwrap();
        let p_val = trust(&p_val);
        let c_val = empty();
        let c_val = EitherEpoch::Untrusted(untrust(&c_val));
        headers.verify(&hp.network(), &c_val, &p_val).unwrap();
    }

    #[rstest]
    #[case::localnet(localnet())]
    fn test_success_verify_across_checkpoint(#[case] hp: Box<dyn Network>) {
        let headers = hp.headers_across_checkpoint();
        let p_val = hp.previous_epoch_header().epoch.unwrap();
        let p_val = trust(&p_val);
        let c_val = hp.epoch_header().epoch.unwrap();
        let c_val = EitherEpoch::Trusted(trust(&c_val));
        headers.verify(&hp.network(), &c_val, &p_val).unwrap();
    }

    #[rstest]
    #[case::localnet(localnet())]
    fn test_success_verify_after_checkpoint(#[case] hp: Box<dyn Network>) {
        let headers = hp.headers_after_checkpoint();
        let p_val = empty();
        let p_val = trust(&p_val);
        let c_val = hp.epoch_header().epoch.unwrap();
        let c_val = EitherEpoch::Trusted(trust(&c_val));
        headers.verify(&hp.network(), &c_val, &p_val).unwrap();
    }

    #[rstest]
    #[case::localnet(localnet())]
    fn test_error_verify_before_checkpoint(#[case] hp: Box<dyn Network>) {
        let previous_epoch = hp.previous_epoch_header().epoch.unwrap();
        let header = hp.headers_before_checkpoint();
        let network = &hp.network();

        // first block uses previous broken validator set
        let mut validators = previous_epoch.validators().to_vec();
        for val in validators.iter_mut() {
            val[0] = 0;
        }
        let p_val = Epoch::new(validators.into(), previous_epoch.turn_length());
        let p_val = trust(&p_val);
        let c_val = hp.epoch_header().epoch.unwrap();
        let c_val = EitherEpoch::Trusted(trust(&c_val));
        let result = header.verify(network, &c_val, &p_val);
        match result.unwrap_err() {
            Error::MissingSignerInValidator(number, _) => {
                assert_eq!(number, header.target.number)
            }
            e => unreachable!("{:?}", e),
        }
    }

    #[rstest]
    #[case::localnet(localnet())]
    fn test_error_verify_across_checkpoint(#[case] hp: Box<dyn Network>) {
        let epoch = hp.epoch_header().epoch.unwrap();
        let mut c_val: Validators = epoch.validators().clone();
        for (i, v) in c_val.iter_mut().enumerate() {
            v[0] = i as u8;
        }
        let c_val = Epoch::new(c_val.into(), 1);
        let c_val = EitherEpoch::Trusted(trust(&c_val));
        let p_val = Epoch::new(hp.previous_validators().into(), 1);
        let p_val = trust(&p_val);

        let network = &hp.network();

        // last block uses new empty validator set
        let header = hp.headers_across_checkpoint();
        let result = header.verify(network, &c_val, &p_val);
        match result.unwrap_err() {
            Error::MissingSignerInValidator(number, _) => {
                //25428811 uses next validator
                assert_eq!(number, header.all[header.all.len() - 2].number)
            }
            e => unreachable!("{:?}", e),
        }
    }

    #[rstest]
    #[case::localnet(localnet())]
    fn test_error_verify_non_continuous_header(#[case] hp: Box<dyn Network>) {
        let mut headers = hp.headers_after_checkpoint();
        headers.all[1] = headers.all[0].clone();
        let p_val = empty();
        let p_val = trust(&p_val);
        let c_val = hp.epoch_header().epoch.unwrap();
        let c_val = EitherEpoch::Trusted(trust(&c_val));
        let result = headers.verify(&hp.network(), &c_val, &p_val);
        match result.unwrap_err() {
            Error::UnexpectedHeaderRelation(e1, e2, _, _, _, _) => {
                assert_eq!(e1, headers.target.number);
                assert_eq!(e2, headers.target.number);
            }
            e => unreachable!("{:?}", e),
        }
    }

    #[rstest]
    #[case::localnet(localnet())]
    fn test_error_verify_too_many_headers_to_finalize(#[case] hp: Box<dyn Network>) {
        let mut headers: ETHHeaders = vec![
            hp.epoch_header(),
            hp.epoch_header_plus_1(),
            hp.epoch_header_plus_2(),
        ]
        .into();
        headers.all.push(hp.epoch_header_plus_3());
        let p_val = Epoch::new(hp.previous_validators().into(), 1);
        let p_val = TrustedEpoch::new(&p_val);
        let c_val = hp.epoch_header().epoch.unwrap();
        let c_val = EitherEpoch::Untrusted(untrust(&c_val));
        let result = headers.verify(&hp.network(), &c_val, &p_val);
        match result.unwrap_err() {
            Error::UnexpectedTooManyHeadersToFinalize(e1, e2) => {
                assert_eq!(e1, headers.target.number, "block error");
                assert_eq!(e2, headers.all.len(), "header size");
            }
            e => unreachable!("{:?}", e),
        }
    }

    #[rstest]
    #[case::localnet(localnet())]
    fn test_error_verify_invalid_header_size(#[case] hp: Box<dyn Network>) {
        let mut headers = hp.headers_after_checkpoint();
        headers.all.pop();
        let p_val = empty();
        let p_val = trust(&p_val);
        let c_val = hp.epoch_header().epoch.unwrap();
        let c_val = EitherEpoch::Trusted(trust(&c_val));
        let result = headers.verify(&hp.network(), &c_val, &p_val);
        match result.unwrap_err() {
            Error::InvalidVerifyingHeaderLength(e1, e2) => {
                assert_eq!(e1, headers.target.number, "block error");
                assert_eq!(e2, headers.all.len(), "header size");
            }
            e => unreachable!("{:?}", e),
        }
    }

    #[test]
    fn test_success_verify_finalized_including_not_finalized_block() {
        let mut target_1 = localnet().epoch_header_plus_1();
        target_1.extra_data = vec![];
        let headers = ETHHeaders {
            target: localnet().epoch_header(),
            all: vec![
                localnet().epoch_header(),
                target_1,
                localnet().epoch_header_plus_2(),
                localnet().epoch_header_plus_3(),
            ],
        };
        headers.verify_finalized().unwrap();
    }

    #[test]
    fn test_success_verify_voters() {
        let mut h = localnet().previous_epoch_header();
        let p_vals = vec![vec![1], vec![2]];
        let p_epoch = Epoch::new(p_vals.into(), 1);
        let pt_epoch = TrustedEpoch::new(&p_epoch);
        let c_vals = vec![vec![1], vec![2]];
        let c_epoch = Epoch::new(c_vals.into(), 1);

        // after next checkpoint
        h.number = 412;
        verify_voters(
            &vec![vec![1]],
            &h,
            Some(411),
            211,
            &EitherEpoch::Trusted(TrustedEpoch::new(&c_epoch)),
            &pt_epoch,
        )
        .unwrap();

        // after checkpoint
        h.number = 212;
        verify_voters(
            &vec![vec![1]],
            &h,
            Some(411),
            211,
            &EitherEpoch::Untrusted(UntrustedEpoch::new(&c_epoch)),
            &pt_epoch,
        )
        .unwrap();

        // other
        h.number = 211;
        verify_voters(
            &vec![vec![1]],
            &h,
            Some(411),
            211,
            &EitherEpoch::Untrusted(UntrustedEpoch::new(&c_epoch)),
            &pt_epoch,
        )
        .unwrap();
    }

    #[test]
    fn test_error_verify_voters() {
        let mut h = localnet().previous_epoch_header();
        let p_vals = vec![vec![1], vec![2]];
        let p_epoch = Epoch::new(p_vals.into(), 1);
        let pt_epoch = TrustedEpoch::new(&p_epoch);
        let c_vals = vec![vec![1], vec![2]];
        let c_epoch = Epoch::new(c_vals.into(), 1);

        // after next checkpoint
        h.number = 412;
        verify_voters(
            &vec![vec![1]],
            &h,
            Some(411),
            211,
            &EitherEpoch::Untrusted(UntrustedEpoch::new(&c_epoch)),
            &pt_epoch,
        )
        .unwrap_err();
        verify_voters(
            &vec![vec![0]],
            &h,
            Some(411),
            211,
            &EitherEpoch::Trusted(TrustedEpoch::new(&c_epoch)),
            &pt_epoch,
        )
        .unwrap_err();

        // after checkpoint
        h.number = 212;
        verify_voters(
            &vec![vec![0]],
            &h,
            Some(411),
            211,
            &EitherEpoch::Untrusted(UntrustedEpoch::new(&c_epoch)),
            &pt_epoch,
        )
        .unwrap_err();
    }

    #[test]
    fn test_error_verify_finalized_no_finalized_header() {
        let mut target_1 = localnet().epoch_header_plus_1();
        target_1.extra_data = vec![];
        let mut target_2 = localnet().epoch_header();
        target_2.extra_data = vec![];
        let headers = ETHHeaders {
            target: localnet().epoch_header(),
            all: vec![
                localnet().epoch_header(),
                target_1,
                target_2,
                localnet().epoch_header_plus_3(),
            ],
        };
        let result = headers.verify_finalized();
        match result.unwrap_err() {
            Error::UnexpectedVoteRelation(e1, e2, err) => {
                assert_eq!(e1, headers.target.number, "block error");
                assert_eq!(e2, headers.all.len(), "header size");
                assert!(format!("{:?}", &err.unwrap()).contains("UnexpectedVoteLength"));
            }
            e => unreachable!("{:?}", e),
        }
    }

    #[test]
    fn test_success_verify_finalized_with_many_headers() {
        let v = vec![
            //https://testnet.bscscan.com/block/45214600
            decode_header(hex!("f9057ea06e94ae7ef8cc013f1ddff4519d44823bdb508e10cec2d8c2e191d27f741cbf8ea01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d493479440d3256eb0babe89f0ea54edaa398513136612f5a0766f9938068e5a9fa592451105996d65e587e49b90cc931b243db46891830fc4a0f070fccfa4d96d319030acf9bd07ad61df24cf24ae4c581df633739a6bb2d33da0fea7ba2221ca1582bece7533eb42f6f295d4dbc03e62f14478168e287aad5734b90100040010400040000000000040001000000241000800000000c0000000020400000000104800010000008210000000000000000000020000400100040000200000000000200004000300000008000200002110480000000000a00200004020000004480028a0020001000400000400450008600400000000000020001200000800000808000000000000000000000000000000040000000002240000008000082802008040000000200820000002800042000000000000100002002000000001000000000200000000100804200000000042400000000002c00010480200000000001008000000000001100084000001040008c000008200004040200000000000028402b1eb888405efeb20830ba24a846723446fb90338d88301040e846765746888676f312e32312e34856c696e75780000000299d9bc0808265da01e1a65d62b903c7b34c08cb389bf3d9996f763f030b1adcfb369c5a5df4a18e1529baffe7feaec66db3dbd1bc06810f7f6f88b7be6645418a7e2a2a3f40514c21a3d9d7a717d64e6088ac937d5aacdd3e20ca963979974cd8ff90cbf097023dc8c448245ceff671e965d57d82eaf9be91478cfa0f24d2993e0c5f43a6c5a4cd99850023040d3256eb0babe89f0ea54edaa398513136612f5a334b49d766ebe3eb9f6bdc163bd2c19aa7e8cee1667851ae0c1651f01c4cf7cf2cfcf8475bff3e99cab25b05631472d53387f3321fd69d1e030bb921230dfb188826affaa39ebf1c38b190851e4db0588a3e90142c5299041fb8a0db3bb9a1fa4bdf0dae84ca37ee12a6b8c26caab775f0e007b76d76ee8823de52a1a431884c2ca930c5e72bff3803af79641cf964cc001671017f0b680f93b7dde085b24bbc67b2a562a216f903ac878c5477641328172a353f1e493cf7f5f2cf1aec83bf0c74df566a41aa7ed65ea84ea99e3849ef31887c0f880a0feb92f356f58fbd023a82f5311fc87a5883a662e9ebbbefc90bf13aa533c2438a4113804bfd447b49cd040d20bc21e49ffea6487f5638e4346ad9fc6d1ec30e28016d3892b51a7898bd354cfe78643453fd3868410da412de7f2883180d0a2840111ad2e043fa403ebf9a1db0d6f22bd78ffaeccbc8f47c83df9fbdbcfaade0f78a6b92b38c9f6d45ce8fb01da2b800100201cf0936b6b4b14c98af22edbe27df8aa197fca733891b5b6ca95db04f8b381fbb860a12aed22e41385aa96efa4536ed81355b069fae16992fd46f866f4b2767c09436517e5dbc349d48c2f863cccc472b3ce096d0376779428dd5cd1b28078d5022e529e51c1c97db640b7f1c5b11b1ffb7e7208acf95986a45a0d400a46f0c4c11cf84c8402b1eb86a01125d5208ff92b1ea97d01dadcd5e277f52e143916288d671d5fec8860c3e6b48402b1eb87a06e94ae7ef8cc013f1ddff4519d44823bdb508e10cec2d8c2e191d27f741cbf8e80daa9d3b546986bceb93f5afd160958d6d32f6d9ef81a70b21802a455dad7b9157accef88cd0e459bffd3c1105a0dcb53d877091d8bf84d706274fe7f43c5093f01a0000000000000000000000000000000000000000000000000000000000000000088000000000000000080a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b4218302000080a00000000000000000000000000000000000000000000000000000000000000000").to_vec()),
            decode_header(hex!("f90359a04e47d8db81e515d75a96f36ee409190c402038c06cf05dd5bca71d1099c7cab6a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d493479440d3256eb0babe89f0ea54edaa398513136612f5a0447b10cfc9066c11310db781e39fcebcb9740ba67d4dc550e977be01907defc9a0f56e8363a75117d54a2fe8a7116b5044cb194495745d593d975cab1de018970ba057caa07d7d270fd85713bfdc42240142e48a0cc2458139e862b81413bbc11571b901000000000000000000200000400000100000000000000000000000000020000000000010000000000000000000000000000000000000800000010000000000000000000020000000020001000800000000201000000000000080000000000008000008002020020000000000000000c000084000000000000000000010000000000000400000000000000000000000000000000400000000000400000000000020000080000000002008000000020000000000000000000000020020000000000000000002000000000000000000000000000000000000008000105002002000000000000000000000010000040000030010008400000800004000000000010000028402b1eb898405e9fb36831bdde78467234472b90116d88301040e846765746888676f312e32312e34856c696e75780000000299d9bcf8b381fbb860a8ea6d387b7800147ad2155132dfa95d187f56ebd1c9ece1c8364df305761dfbd516d93423f8c57045228b7ef52fcde104c094aee3794c72efcd475311f88b6d3082f3ee399fd2b9cf58cd3c63350c7cba410fb43e219f419b4b57102daa6378f84c8402b1eb87a06e94ae7ef8cc013f1ddff4519d44823bdb508e10cec2d8c2e191d27f741cbf8e8402b1eb88a04e47d8db81e515d75a96f36ee409190c402038c06cf05dd5bca71d1099c7cab6807a03301635f5c73d1ee0f095f33c697badc2560110a3add7f7d59c995eefac4910b711317255a198ba93410bb88c7e97f860c906d1dc60229a06c551760b3bce00a0000000000000000000000000000000000000000000000000000000000000000088000000000000000080a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b4218080a00000000000000000000000000000000000000000000000000000000000000000").to_vec()),
            decode_header(hex!("f902a3a0a845b19d537d80fc8ae29c4aed49bd6578f4eb5089632d40f708588f6970ebf4a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d493479440d3256eb0babe89f0ea54edaa398513136612f5a04b50b580bbd86f6e198fd9c085f837109c6ff39053625f4a11c7aee0e2cfb63aa0abbe999c7c87fe7427d44e0b0aaf8918a723b17744678bd9ba209368cc82f8a2a08189d28f2391444d7c4868cea83360c6109abe993f55a7d2429d383632c6947bb9010000000000800000000000004000100200000000000004000000000000000800000081100000000000000000000000000000000400000000000100000000000002008000200000000200000008000400002010000000000000800000000000000000080020201200001000000000004000084000100000000008000010800000000400000400000000000004000000000000000480000000000440000000008020400080000000002108000000020000000040000000000000020020000000000000000002000000000000000000000000000000000000008020105402000000000000000000000000010000040000030000008400000000204100000000010800028402b1eb8a8405e4113c8306e52c8467234475b861d88301040e846765746888676f312e32312e34856c696e75780000000299d9bcd0a2b2dcf96ddbb4e8c201a2845fb962fa5a8ea571b6f3fc5c6f30f515cbcc4470ea5545b435334fcb6165032a91423c6803d3771c9874a9a69107e2a27e484e00a0000000000000000000000000000000000000000000000000000000000000000088000000000000000080a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b4218080a00000000000000000000000000000000000000000000000000000000000000000").to_vec()),
            decode_header(hex!("f90359a00113d3d7778af93b122871e02432ded0cc60c8c9fe1cedab69465bc2ed750f29a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d493479440d3256eb0babe89f0ea54edaa398513136612f5a01303affe211de58db87dca446d098e0dee67f3aa4edda393b2e7435f1d706283a0118805b4e132609bbab79efe56918cc539694253ed4555b2d13fe2165480ddf1a0f642c960ec442a236bb3f0749e5be8484773a16493bd9d429ed6929662248001b9010004000000000000000000004000000004000000000000000080000000000400000000100000010000008000000000000000000010000000000100000000200000000000200200800200000008000020002010000000000001800000000000000000080020200200000000000100004000084000000100000000000010000000000000000000000000000000000000000100000400000000000400000080000020020080000000022008000000020000000000000000000000020020000000010010000082000000200040000000000000020000002000008000104042000000000010000000000000010000040000014000008000000000006000000000000000028402b1eb8b8405de2d2c830424308467234478b90116d88301040e846765746888676f312e32312e34856c696e75780000000299d9bcf8b381fbb860b4fa72afe0a0b517bee1ae6ccec530926fedf8abda9f2155d70b4591d6a1cc941d7589410a3e3e61cb004d890c8b4b8002854de11c87173ba7a9dcfd32b63a58b3ffa1f3ac4847a63a4cda1aed80e3b74bafeb1350e9ab5210d81658860757c8f84c8402b1eb88a04e47d8db81e515d75a96f36ee409190c402038c06cf05dd5bca71d1099c7cab68402b1eb8aa00113d3d7778af93b122871e02432ded0cc60c8c9fe1cedab69465bc2ed750f29808b1762cfd0533f76a6853bc389b57c07d84255fcdffb8ec429753ed0cf941e4a1646277e4462b3136f00536f86910b861312fc3cb44070db94e5dccbd035de8400a0000000000000000000000000000000000000000000000000000000000000000088000000000000000080a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b4218080a00000000000000000000000000000000000000000000000000000000000000000").to_vec()),
            decode_header(hex!("f9035aa0dec5be85f92346bb546787db811d23fd88c001d05403f19295273d27a517efdfa01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d493479453387f3321fd69d1e030bb921230dfb188826affa06200e3a8d1b95f53f80ede9a9a721e873085f8df88cbc0b26635b3ee4448ae6aa0430269c352181fe7f46adcc0792dc6973264279fd29bd56af95f9dbf7d42137aa05bdd6a4d4323421b7ade5c786051b9b8b82d8d383c9fd4e4239ce415308e61edb90100b7bef4feffafbcfbdfdfbbf6f6fed3e7bd3effabd7fff76e7bbf73dfdffff5f4edfffe7f5ffedffd7def9f7feb8ebf6ff7bfff9edf7fff7b7ffefb7fbffe77fefe7a9fbfdff7ffff7f97bdf9cf3d6df777fd7ebf6f6ed7eef7d37f756ff3fefffedef7ea3a76f271dd8793b3abc7cfff3ffdeebbf979defff76befdfbbbef3fff9fafbcffffffff2af7eb7bf7ffdffffffffb5ebdbfddd8e9fbbf7fcdfcffdefdeeab71f9ff86f7f7f5e67dff3bedeeaffffedfdbb7bf5e7bb9dffa7f7ff57f773f3f19fffe7bfbc7fd77fbe5bb9ffe7cfeebf9dadfbbbd85fffffefd9ebbd5bff7ffffcd7fbefbf3f77fbbfdff57ff1fed8fffebabbf3fffbf7dd2effbffffe028402b1eb8c8405e40b5884013b6464846723447bb90116d98301040f846765746889676f312e32312e3133856c696e757800000299d9bcf8b381fbb8609126e078b6533f67623a500cbde29ac8153b1e5752d415aa71d75c0046c934da40407f23baa58a466a355a493b9e39c7107ab54ec3a1de320f26c0db35b3f54a4757f3564679f1619d52d4fd26d7ce680f60cf5fa6f67ec01f7e1c34b8b4986af84c8402b1eb8aa00113d3d7778af93b122871e02432ded0cc60c8c9fe1cedab69465bc2ed750f298402b1eb8ba0dec5be85f92346bb546787db811d23fd88c001d05403f19295273d27a517efdf80a7a4d25360dc7cac1c8c8a247e8d6b0a34bd97c689b382ef3d9ec726a74d9c4f3ea17ae295877d17b8a1f4228788fe98ddd627cf68ee27b973660a670ea5581f01a0000000000000000000000000000000000000000000000000000000000000000088000000000000000080a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b4218080a00000000000000000000000000000000000000000000000000000000000000000").to_vec()),
        ];
        let headers = ETHHeaders {
            target: v[0].clone(),
            all: v.clone(),
        };
        let result = headers.verify_finalized().unwrap();
        assert_eq!(result.0.number, v[3].number);
        assert_eq!(result.1.number, v[4].number);
    }

    #[test]
    fn test_success_verify_finalized_with_many_headers_fermi() {
        let group = [
            (vec![
                // finalized: 506
                decode_header_with_fermi(hex!("f90370a061e54cba38225d35f042c6bd5ae8d6f981a451f3a53e49313b570db907ee2dd2a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d4934794d9a13701eafb76870cb220843b8c6476824bfa15a0396436866456ceb1c4b702cb5d3a4b1e2495d84619f1ba7142b80e59e8342a88a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421b9010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000028201fa8402625a008084690eacdbb90111d983010602846765746889676f312e32342e3130856c696e757800000d382c2cf8ae07b86089aa2052e18ebe839aa3723bcad27b2a2196e22b7bc11c4d4d24d4a69e01e86bd404d19a0345c922456c8f6badd351d907fb69a6590bfad9673c8fdb9fc38bdd73b9bb4c93bb3d349380322366b1dc6d294e0e6916ef256ccbfa245255e43ad3f8488201f6a09058cfa000d451f4cd49092133047c1cf4a29d2c905a9aa17c890e96d81513d08201f8a0464df616013723293103002550e47ce3e44eb7dee4b11bfa10daeb4a2df51215802185ef1b54bfba22b6d1be5d4988c592b1da29abd380ea7d98def9b4f17e66f50b580baa6e8481b1b15b424ceddbf66964f633371d73a62825c67f9c633077d501a000000000000000000000000000000000000000000000000000000000000000c888000000000000000080a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b4218080a00000000000000000000000000000000000000000000000000000000000000000a0e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855").to_vec()),
                // no vote: 507
                decode_header_with_fermi(hex!("f902bfa06510e76fec4471a1dd46e83484608cba84a2c0860ed484dc785aaeca5bc24598a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d4934794d9a13701eafb76870cb220843b8c6476824bfa15a0ed3a25beff351197a86ea87f939c7a129d7e7b9759a5c125875e58424c774c96a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421b9010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000028201fb8402625a008084690eacdbb861d983010602846765746889676f312e32342e3130856c696e757800000d382c2c9ed5d62372f22f62c2442552b80af1e868265d205a6132a44c10bbc50fe017bc1f9ad3f3c89381a992f177e292821630df0079134f002dcaaca675e5486b796400a0000000000000000000000000000000000000000000000000000000000000028a88000000000000000080a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b4218080a00000000000000000000000000000000000000000000000000000000000000000a0e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855").to_vec()),
                // child: 508
                decode_header_with_fermi(hex!("f90370a042ac9f2075511d2293a3448edba653bd1fe6cb7bf4b6fd9597d98bd3e1168eeea01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d4934794d9a13701eafb76870cb220843b8c6476824bfa15a0027e1be8380711bbe9075b3d99dd23e59769711f03064b2a42f03c5a4ee2294da056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421b9010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000028201fc8402625a008084690eacdcb90111d983010602846765746889676f312e32342e3130856c696e757800000d382c2cf8ae07b8608509853e9fab817fba4600c12d1689548f6566e22277a0fbfc99c0c241e53362550e13bb2c1da81dd133a953539febce16760742ac3462ae106c4d7db8422bdb9e01f1d7285251940badbec7358f923e6ff267135f0c6e73963e5340edb495d7f8488201f8a0464df616013723293103002550e47ce3e44eb7dee4b11bfa10daeb4a2df512158201faa06510e76fec4471a1dd46e83484608cba84a2c0860ed484dc785aaeca5bc2459880d63a5ec69ce06dbbe045deffd2cf87000fe0b91a727973edbdb980ab86d80eee0e272ce2600c634d7ee5cb2d4f4b2139e924a6f6d6f818fda0ed8b02d69be61901a0000000000000000000000000000000000000000000000000000000000000006488000000000000000080a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b4218080a00000000000000000000000000000000000000000000000000000000000000000a0e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855").to_vec()),
                // no vote: 509
                decode_header_with_fermi(hex!("f902bfa04dbe87a2afcbd4599b997d68b7976c15d5d6c78fbaa2586541c6ab1a5d3051e9a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d4934794d9a13701eafb76870cb220843b8c6476824bfa15a0c5b6d22e10686a802dfe562e6b2de199ebecf18aae5a284aa531fd4137fdcd3ea056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421b9010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000028201fd8402625a008084690eacdcb861d983010602846765746889676f312e32342e3130856c696e757800000d382c2caf975e1c326acf700081afa54cc4b2a84fb67ec15733488c488cf2b2c4c22862646c5b21762fe5df77abfbc6076eccaaf445af23e584b33cf602f7134125999500a0000000000000000000000000000000000000000000000000000000000000022688000000000000000080a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b4218080a00000000000000000000000000000000000000000000000000000000000000000a0e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855").to_vec()),
                // grand child: 510
                decode_header_with_fermi(hex!("f90370a0fca3ee6eb6331d3caf5310dcea500b6d06ea5dee08972a285d3c8bcf2848e542a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347948fdaaa7e6631e438625ca25c857a3727ea28e565a06bfb3c7904a7b6347689fea2fc0ad3e0bcc6597d4817c9ce132e8a4962b740e2a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421b9010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000028201fe8402625a008084690eacddb90111d983010602846765746889676f312e32342e3130856c696e757800000d382c2cf8ae07b860ab54b1e139a3e5345731e228daccb85fa7641a6f4873057022d1f6979c69b2d4193d96068a9c23ea7f0540f7f2bf8e210493a01df523bc4e8b15f02c772425bbfd8577e33cb603b6d8349834cd678e4e15799e141d2bd15dba147302116566fcf8488201faa06510e76fec4471a1dd46e83484608cba84a2c0860ed484dc785aaeca5bc245988201fca04dbe87a2afcbd4599b997d68b7976c15d5d6c78fbaa2586541c6ab1a5d3051e9809de85618105acd64900a429445efd27d81e587f6dca6a8e4ea0ad219111078ec0696d6064a4b8e7251883f0cb52f2fa5e33389fc934b11be1b581c357d46bca600a0000000000000000000000000000000000000000000000000000000000000000088000000000000000080a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b4218080a00000000000000000000000000000000000000000000000000000000000000000a0e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855").to_vec()),
            ], 508, 510),
            (vec![
                // no vote: 780
                decode_header_with_fermi(hex!("f902bfa0c9e4ade6549940a3176549973e104db99f5d76414a75dac85c5c7d8ac4944c02a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d4934794a7876ea32e7a748c697d01345145485561305b24a07af9c8b256e0568fefd01da65fc184d2b99ddbc941bb73f8c1a4a88b4829733ca056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421b90100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000282030c8402625a008084690ec149b861d983010602846765746889676f312e32342e3130856c696e75780000c2625646e9f66472b1e36d0741b3a83cbb5bd08c15a2fd0d7221d740fa2cabe6fd732af37c0f21fc754af73a60d342c9361fb181d88d31559932c6ad48d6b2100e8d0cb801a000000000000000000000000000000000000000000000000000000000000000c888000000000000000080a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b4218080a00000000000000000000000000000000000000000000000000000000000000000a0e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855").to_vec()),
                // finalized: 781
                decode_header_with_fermi(hex!("f90370a06fba6c4d22a8bbeeabab7ed42399df6d1e5619583c2fa5c8501ab92fed48a008a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d4934794a7876ea32e7a748c697d01345145485561305b24a03619e2f634b93ad603a07e2cd8f74972b76430a2717ada94d8a514a41c305548a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421b90100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000282030d8402625a008084690ec149b90111d983010602846765746889676f312e32342e3130856c696e75780000c2625646f8ae03b86090555af20ed36f5aabeb62da55f3375f12579bdc1a879f5313c5d9c56b413e3eeb284aa748fb42e39553c15e3d54cb9c01d2aeaa6ad89fe64c3fe291e773e6935a7ea5dbf399cd4654555a82f6d4701b85f4f75b93cc2f57fcdcb949f87e54a0f848820307a024b038aa32c2b8788a5dd68a43d5d35425d00213fc6f61e7c35e1774a6519cdc82030aa0cad7cf4aefc3ec5ca95b1039846bc3faccc900fe1f0a798ea63f801f337588358077a98dfbef98d18c23c0d5b424124afe304dc22f50b5aadbf3f93cd1feac4e76448716c07cc72502f7a033a1ab6850ce30bc21f16240a2705bea1f7fe9403a3e00a0000000000000000000000000000000000000000000000000000000000000028a88000000000000000080a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b4218080a00000000000000000000000000000000000000000000000000000000000000000a0e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855").to_vec()),
                // no vote: 782
                decode_header_with_fermi(hex!("f902bfa0d55e5ceb7a93760e0c614643e8d181c5d3c65d2c6ad80d4343a5935a9ac037caa01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d4934794a7876ea32e7a748c697d01345145485561305b24a0506ec5106e98498ec95882fcd5f03dfbaae3c61a552d3e5308db4dbf4763e5c5a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421b90100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000282030e8402625a008084690ec14ab861d983010602846765746889676f312e32342e3130856c696e75780000c26256461e8802da3c1054ff83171c0a1b235cc70ba935d52841d7b9e60ed0bde9a3a9d31fe7d19f9a818b7426b8070a6713198cc0ed936785c05611481fad81cf3c694c01a0000000000000000000000000000000000000000000000000000000000000006488000000000000000080a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b4218080a00000000000000000000000000000000000000000000000000000000000000000a0e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855").to_vec()),
                // no vote: 783
                decode_header_with_fermi(hex!("f902bfa0342d99d1728fd05ac3a821162f7cff5569a62d0d09c78277c9e701e4b7ac4883a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d4934794d9a13701eafb76870cb220843b8c6476824bfa15a002874b20b003e0afd996d22c352c8a8ec8bc0b0986743a96fad3cd5e81cbd0d4a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421b90100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000282030f8402625a008084690ec14ab861d983010602846765746889676f312e32342e3130856c696e75780000c26256466815abc1b4b5c335ad0a1ed2bd17a021211d5b1f8d75b2c4dc7ab26ce8a5486f425ed9645510451596affdc1e602ead6dca707266f188544b02c2d247d1832ef00a0000000000000000000000000000000000000000000000000000000000000022688000000000000000080a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b4218080a00000000000000000000000000000000000000000000000000000000000000000a0e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855").to_vec()),
                // child: 784
                decode_header_with_fermi(hex!("f90370a044122401ce9e6f2bbd26016c1c6ec98f09f9d2a3f7b50dd838561b3aebdc74bca01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d4934794d9a13701eafb76870cb220843b8c6476824bfa15a0625fb0ac90a3457ceda3880024019e6ee61dbfdadd78e7386025cb8c29ed9069a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421b9010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000028203108402625a008084690ec14bb90111d983010602846765746889676f312e32342e3130856c696e75780000c2625646f8ae03b8608ee466a4507c0ed1cfc0e119d9e4e1d25c1c82047d65886cbc58c25adb71c661f5ab6c48e97ee4e84515091d93ff978b02cf9514f22b413b455a629e25f7162a02e551f7609b7e4dc8d5f83347b8b524e78fa211ced41fc04478ea6efe7b1e78f84882030aa0cad7cf4aefc3ec5ca95b1039846bc3faccc900fe1f0a798ea63f801f3375883582030da0d55e5ceb7a93760e0c614643e8d181c5d3c65d2c6ad80d4343a5935a9ac037ca802b77e755536d4064ee5c0366e175260503bb8dbfe7295c533175302de08be87e5e336eaf138730cd57069f2002d2646dca55e525d283897c62f7eeb0a9ff5c9f01a0000000000000000000000000000000000000000000000000000000000000000088000000000000000080a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b4218080a00000000000000000000000000000000000000000000000000000000000000000a0e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855").to_vec()),
                // no vote: 785
                decode_header_with_fermi(hex!("f902bfa060408654260d46aabcf65cf0dd8b29b95599b55380ea57857b29f723adc443fda01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d4934794d9a13701eafb76870cb220843b8c6476824bfa15a051ac73c5703c15e58e98df4e118219b601034918cc803e00041ed0618cf8e960a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421b9010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000028203118402625a008084690ec14bb861d983010602846765746889676f312e32342e3130856c696e75780000c262564692a109b1b71100625a7312aad649212af6c20ed6fa698bf0cfaf71b52bbe54af7f32815be4c7df330df25c2a2cdcafaa126ba01b17a69c41bb14fafab8352b0301a000000000000000000000000000000000000000000000000000000000000001c288000000000000000080a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b4218080a00000000000000000000000000000000000000000000000000000000000000000a0e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855").to_vec()),
                // no vote: 786
                decode_header_with_fermi(hex!("f902bfa02feea8d1b311b45029924cf412d39b6e9898d664ae659bf7c3e3a25df3defeb3a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d4934794a7876ea32e7a748c697d01345145485561305b24a054f8faa7215319277fa00eae4bf3886dbe7adb37c8a8968207e46bc4a073781da056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421b9010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000028203128402625a008084690ec14bb861d983010602846765746889676f312e32342e3130856c696e75780000c26256469322825fd21edfdd57dac75a867dc4060e3b234e16f771b1e186f1e2a399b7242f8b59f3fb1ea9b08228c3c12692628ac1664a75177640c862415f261481b7f300a0000000000000000000000000000000000000000000000000000000000000038488000000000000000080a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b4218080a00000000000000000000000000000000000000000000000000000000000000000a0e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855").to_vec()),
                // grand child: 787
                decode_header_with_fermi(hex!("f90370a0f2880c072f0674e90a40006553f5a28758f78902268f17e0f8b8cdcf0bea04fda01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d4934794a7876ea32e7a748c697d01345145485561305b24a001a48ccfc24533e019befebeef5131644d239fb5fc4756a7c7e251a2bdc0a231a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421b9010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000028203138402625a008084690ec14cb90111d983010602846765746889676f312e32342e3130856c696e75780000c2625646f8ae03b860b63fd76261cb5cc16f53e82133c937e2042443bddf92b8d55982c69360241067d0b707604972b10ab624d2ded8d411b71760bc28ffe89c5906595a3a43135e9678c025fe8694b77a859674bc2c0dfc9abaa58640ab6b43f607facb410d087023f84882030da0d55e5ceb7a93760e0c614643e8d181c5d3c65d2c6ad80d4343a5935a9ac037ca820310a060408654260d46aabcf65cf0dd8b29b95599b55380ea57857b29f723adc443fd80108f12a9c98aa2d2c3944a3bb0f45c0c2e479549a84f6a0ce5741475229c12ca2242d904fa10057e2dfd5ab42a4b06d1201c2565005763eda37bc060cfa00fc200a0000000000000000000000000000000000000000000000000000000000000015e88000000000000000080a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b4218080a00000000000000000000000000000000000000000000000000000000000000000a0e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855").to_vec()),
            ], 784, 787),
            (vec![
                // finalized: 72486608
                decode_header_with_fermi(hex!("f9037aa0927229adbeb44087068093a2d84ee4a537840124ae4b6143b6a00eb69861b154a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347947f5f2cf1aec83bf0c74df566a41aa7ed65ea84eaa09758bd6b22c47cbab71682ebe5a0d491d6fd602030c36191b1c452108b12ce9ba0c10ee260e1302f2968d14030935957e496a45c186e00c506401e5d1d3206dba3a09d5348954d8cc85a4f7a3d8f7782fa98168746ea673c93618a21f6b67cbd7596b90100c0c010d01000192108c080c08714a30000a00c5c86022108452210200a0007d190d113020b49e801800048285140e07441112051ea0500804314204006202941000944810a8a18330100000cc10009003990b30040c9071524349270cae14094027a20fdd20a00a19a100008106808408a2090c4030e010c00086512280a8383c6222cdd100415000020802406424800408847862421c16e1219010801b09023020429534974532168000c004a0010440880006220001280184848b0850800a0cb00173e886a292850c206104b1792a353820810280458512094508a92202301181640020864682009034c668c8115e102018032e1a97a00480720000040081a028404520ed0840393870083a7a3cb846915a242b90116d883010603846765746888676f312e32342e39856c696e75780000005b240570f8b381ffb8608fe47768d7664ebd7100b41eab5ec8ba81d0d18a823b0558894c28512e8b9011c08ff5fd8835d7c5162fae4eedc9c12710a236ee5b399028a5856cbc79e0db6ae627bd06cdf638a5aab208dc141c5156bf9cc9a791bd3842b00f2aff393239b1f84c8404520ecea0f07121ac67d5ac8171d16d6dd53a968160e091ea3346fcfa6bdb53c4bbb4c8fa8404520ecfa0927229adbeb44087068093a2d84ee4a537840124ae4b6143b6a00eb69861b154801b31de7aecb339fcfb2b43796eadaf626c43892ec60caeb3b5a2663337f93a8241bbe3dccacb4548234f9972a3e1ff2d20675a25bfa6ee9b00f55471575915a701a000000000000000000000000000000000000000000000000000000000000001c288000000000000000080a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b4218080a00000000000000000000000000000000000000000000000000000000000000000a0e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855").to_vec()),
                // no vote: 72486609
                decode_header_with_fermi(hex!("f902c4a015dd14d86358864bd7c4422cd74f2736031572dc7f6dc0acc5e04dd54c3bd6ffa01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347947f5f2cf1aec83bf0c74df566a41aa7ed65ea84eaa066ef3ab3f6400aa818434f02469813592133534dbb453377fb493adc78adc118a03ba925fd87820072d58827d2a661a5f7937e6b49a04baabc9d146b6b26e52c56a0bf08758ce3cb32054ce1a2476fcaed8c0cea284f997335617473b9ebf7c19b12b90100a00029800000801e282228c0879843c020401040000931108620b2320e0025428010941033013001107108a018c4e8242100de1011848400e154000042a16014004940e12a0201476072464c6c100208b1d88500118000040634126822210040088af0f08202c213cc1430881020080188039008a248203e10054932c048c03100620c9240848c0a6520c4c244105900008807e10021046c229003800ce09127f30a0c10e4446168e8830c0002218000800241010519020032508010c0040c610900d14e2060081800900702017390227080702028400cd5289440439005b488119256022050e000499154c6c08801050a05904020a80008c20120480018003b028404520ed18403938700839d895a846915a242b861d883010603846765746888676f312e32342e39856c696e75780000005b24057070e3f36857d8a5d61002abfa41c9d2ab6d930cccd00f2a14858ad50a7871f6f61d63bf98101465e416efe7c1b3fb5ef7ca05d1b5f4b5cd389a8df39d95da9aab01a0000000000000000000000000000000000000000000000000000000000000038488000000000000000080a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b4218080a00000000000000000000000000000000000000000000000000000000000000000a0e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855").to_vec()),
                // child : 72486610
                decode_header_with_fermi(hex!("f9037aa0f1f70f9eade2a06caf03876dbe5b77acc355290bde28c21e758201931b7d06dca01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347947f5f2cf1aec83bf0c74df566a41aa7ed65ea84eaa08b0e7d3df3a0d279160c7107d5b3c984c86c4db3cae65e1f057bf65f24f74bd7a062f2227465041b8a0729419b66744ce934dfd44ded3c89e98b64c66d854435f4a0a27c94fe9db012ddc0510d673bc2e151e1122fdf51617438e4da525da59e3002b9010020005084c0041821480001cb87001910224000c88000188904a411221a8015440114134c83416e8000020c28204160224302931008854815c114102096a0222260094082030211130800081d4280502021b1830810000000001c1a0242e36580002a20a0728e465288200580309e8812ca4130d08608c209800010180290100911027c989414ac01c0e688040500d883c43885121020226c0a1a4000012cb32147034c1000646020680226109a0010000000300400c02a094242a81002b2022039010186c162100243894613118b10a240002a8040800858215649821e0471480211503a054344540961c44500a813050201800080b224054c0920c00a00003b028404520ed2840393870083b91464846915a243b90116d883010603846765746888676f312e32342e39856c696e75780000005b240570f8b381fbb8608fd418669062ac8634bd8bb199e882e7b8b397eea7773ebb486d376405948cd00585ad5cf65458afbb939d2d862ec94d0cc95f43da645429aa847f6b373a73377ebbc9a4d74bf12c543eba4116db83f4dd0393c9aa91c87c853c1fa102bed78bf84c8404520ecfa0927229adbeb44087068093a2d84ee4a537840124ae4b6143b6a00eb69861b1548404520ed0a015dd14d86358864bd7c4422cd74f2736031572dc7f6dc0acc5e04dd54c3bd6ff80b6a41393fe771b9a5b5f7c397ff9ef5c8aa3e4a1fc5f7be3be5d3d36cf6f2f544f5d96dc9619db54aad30307aa055197a53207b57d0bd4bee7e2f1d04affc47600a0000000000000000000000000000000000000000000000000000000000000015e88000000000000000080a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b4218080a00000000000000000000000000000000000000000000000000000000000000000a0e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855").to_vec()),
                // grand child: 72486611
                decode_header_with_fermi(hex!("f90379a0bfde5240efbf9dda1381cf5ead3039a1c6b55c5dae95cb044c23fc2c2611f379a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347947f5f2cf1aec83bf0c74df566a41aa7ed65ea84eaa0c139cd27cf0c4981fab2ad057854aeff51f9c416d97a733d3cff4d8fc80fcac5a0822ba47aed5ce6f1b995eb5f9f85635e8f330b5642835fd5feaedb310e056571a0666894d3380ee97be17bcb46ce09f1c585917458d6a92be7aeb81b6a466d56cdb9010001210080122011352a0868c0c79281001778024088800008062050700f224540001b9441134370280d2008a4b009e02409050b1001050020f334122406622407000950e00a4324030020046ec00450142195c1280248000830841701022fa022808b20a0032308480820d7003c2008220b18d25c5209004c060040b10404292100120cd050a4840900209901fc20490520480f200221105c225100810020902be2048910244d4268683005000a2200008200038920181b0030498810000080a68d004586086c20a080880e11011390221a00100041900e5031b4438a1800a05008546002004050980f095cc61cb00b000313808090a000226001318091c0095b028404520ed38403938700839d2605846915a243b90115d883010603846765746888676f312e32342e39856c696e75780000005b240570f8b27fb860b256cac937e461138b0c95cd43c783efad7ae7c1bff57bf9c2366eaee6a8ffface7e809ea699b8e4f6bf5659fed22d72001fd1f7d3038bbe44036711d56140c2c9f5e1e91a6473e884bebe374dabf6b9f61d547e8ed93f908c449e18d6f65843f84c8404520ed0a015dd14d86358864bd7c4422cd74f2736031572dc7f6dc0acc5e04dd54c3bd6ff8404520ed2a0bfde5240efbf9dda1381cf5ead3039a1c6b55c5dae95cb044c23fc2c2611f379809fbce16268145ce40e6e8e7928b4a3719ff036f5814c5a22ebd4b15af108892e169598a3b849d0d069162550728367af38819a3ea79133cd3dff51ae58e8299100a0000000000000000000000000000000000000000000000000000000000000032088000000000000000080a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b4218080a00000000000000000000000000000000000000000000000000000000000000000a0e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855").to_vec()),
            ], 72486610, 72486611),
            (vec![
                // finalized: 72486607
                decode_header_with_fermi(hex!("f9037ca0f07121ac67d5ac8171d16d6dd53a968160e091ea3346fcfa6bdb53c4bbb4c8faa01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d493479476d76ee8823de52a1a431884c2ca930c5e72bff3a0a912e6ea62e22dc56dfe25f1bc6499c625aa8b0e8187c063a8a86268a9a02e97a05f357e7dc8c855f88f2d123803bbfaba01ac3b8d7c31291c50e4089c7a1772afa0c5a8a65b39d65b26a2bca5a9df1d72cf21b9c8607f5f261a3d033d49c86dbdbdb901002108018183020425882084d197000d004a0400624000050a0420122c6a0025c4001818031711a84000080960900862348d2080180004a001031710000224a206006d4d832202218e0104404c4920002021978504098800944084baa19a298000212ea0b506830981206924201a9148402a00b419c2088588a02000d800002343aa924494010ca431883082008582e810208845800921224f0b140c318828d423020aea10004441206a200c588a08002a8180040040400a30506028112b08a0a88d1009c60171406024800408834f902210200040c48888942334c1125204a0000491492258784c003d016446388101158249881220e2050044412c0141208018028404520ecf840393870083a6718a846915a242b90115d883010603846765746888676f312e32342e39856c696e75780000005b240570f8b27eb860b5a6f9f402f631ffed730409610cca7b3fabc6f5eea85c92a8cb27788c91379200ed48ebedd3917f11b485402c2a93f7188557ffde951cfbf16e46436c975195ed399eb0812869753d2f7fa0339bae003e42f740bdefef6e97df6200ca0f9fc9f84c8404520ecda098cf3fa4edde97a7f029c8a811a7cbde48f93d7e9fe061d2c5a3213131d498048404520ecea0f07121ac67d5ac8171d16d6dd53a968160e091ea3346fcfa6bdb53c4bbb4c8fa80d3562d9f71d7cbf6a8e0975dd2f94b24d481a565fc94ca5bb9a3e7bc9f5b06a752070b588f1b9abcead0513fa30e81d43ea322d3a076290a99f5a21043bf9ee700a0000000000000000000000000000000000000000000000000000000000000000088000000000000000080a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b4218302000080a00000000000000000000000000000000000000000000000000000000000000000a0e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855").to_vec()),
                // child: 72486608
                decode_header_with_fermi(hex!("f9037aa0927229adbeb44087068093a2d84ee4a537840124ae4b6143b6a00eb69861b154a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347947f5f2cf1aec83bf0c74df566a41aa7ed65ea84eaa09758bd6b22c47cbab71682ebe5a0d491d6fd602030c36191b1c452108b12ce9ba0c10ee260e1302f2968d14030935957e496a45c186e00c506401e5d1d3206dba3a09d5348954d8cc85a4f7a3d8f7782fa98168746ea673c93618a21f6b67cbd7596b90100c0c010d01000192108c080c08714a30000a00c5c86022108452210200a0007d190d113020b49e801800048285140e07441112051ea0500804314204006202941000944810a8a18330100000cc10009003990b30040c9071524349270cae14094027a20fdd20a00a19a100008106808408a2090c4030e010c00086512280a8383c6222cdd100415000020802406424800408847862421c16e1219010801b09023020429534974532168000c004a0010440880006220001280184848b0850800a0cb00173e886a292850c206104b1792a353820810280458512094508a92202301181640020864682009034c668c8115e102018032e1a97a00480720000040081a028404520ed0840393870083a7a3cb846915a242b90116d883010603846765746888676f312e32342e39856c696e75780000005b240570f8b381ffb8608fe47768d7664ebd7100b41eab5ec8ba81d0d18a823b0558894c28512e8b9011c08ff5fd8835d7c5162fae4eedc9c12710a236ee5b399028a5856cbc79e0db6ae627bd06cdf638a5aab208dc141c5156bf9cc9a791bd3842b00f2aff393239b1f84c8404520ecea0f07121ac67d5ac8171d16d6dd53a968160e091ea3346fcfa6bdb53c4bbb4c8fa8404520ecfa0927229adbeb44087068093a2d84ee4a537840124ae4b6143b6a00eb69861b154801b31de7aecb339fcfb2b43796eadaf626c43892ec60caeb3b5a2663337f93a8241bbe3dccacb4548234f9972a3e1ff2d20675a25bfa6ee9b00f55471575915a701a000000000000000000000000000000000000000000000000000000000000001c288000000000000000080a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b4218080a00000000000000000000000000000000000000000000000000000000000000000a0e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855").to_vec()),
                // no vote: 72486609
                decode_header_with_fermi(hex!("f902c4a015dd14d86358864bd7c4422cd74f2736031572dc7f6dc0acc5e04dd54c3bd6ffa01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347947f5f2cf1aec83bf0c74df566a41aa7ed65ea84eaa066ef3ab3f6400aa818434f02469813592133534dbb453377fb493adc78adc118a03ba925fd87820072d58827d2a661a5f7937e6b49a04baabc9d146b6b26e52c56a0bf08758ce3cb32054ce1a2476fcaed8c0cea284f997335617473b9ebf7c19b12b90100a00029800000801e282228c0879843c020401040000931108620b2320e0025428010941033013001107108a018c4e8242100de1011848400e154000042a16014004940e12a0201476072464c6c100208b1d88500118000040634126822210040088af0f08202c213cc1430881020080188039008a248203e10054932c048c03100620c9240848c0a6520c4c244105900008807e10021046c229003800ce09127f30a0c10e4446168e8830c0002218000800241010519020032508010c0040c610900d14e2060081800900702017390227080702028400cd5289440439005b488119256022050e000499154c6c08801050a05904020a80008c20120480018003b028404520ed18403938700839d895a846915a242b861d883010603846765746888676f312e32342e39856c696e75780000005b24057070e3f36857d8a5d61002abfa41c9d2ab6d930cccd00f2a14858ad50a7871f6f61d63bf98101465e416efe7c1b3fb5ef7ca05d1b5f4b5cd389a8df39d95da9aab01a0000000000000000000000000000000000000000000000000000000000000038488000000000000000080a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b4218080a00000000000000000000000000000000000000000000000000000000000000000a0e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855").to_vec()),
                // grand_child : 72486610
                decode_header_with_fermi(hex!("f9037aa0f1f70f9eade2a06caf03876dbe5b77acc355290bde28c21e758201931b7d06dca01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347947f5f2cf1aec83bf0c74df566a41aa7ed65ea84eaa08b0e7d3df3a0d279160c7107d5b3c984c86c4db3cae65e1f057bf65f24f74bd7a062f2227465041b8a0729419b66744ce934dfd44ded3c89e98b64c66d854435f4a0a27c94fe9db012ddc0510d673bc2e151e1122fdf51617438e4da525da59e3002b9010020005084c0041821480001cb87001910224000c88000188904a411221a8015440114134c83416e8000020c28204160224302931008854815c114102096a0222260094082030211130800081d4280502021b1830810000000001c1a0242e36580002a20a0728e465288200580309e8812ca4130d08608c209800010180290100911027c989414ac01c0e688040500d883c43885121020226c0a1a4000012cb32147034c1000646020680226109a0010000000300400c02a094242a81002b2022039010186c162100243894613118b10a240002a8040800858215649821e0471480211503a054344540961c44500a813050201800080b224054c0920c00a00003b028404520ed2840393870083b91464846915a243b90116d883010603846765746888676f312e32342e39856c696e75780000005b240570f8b381fbb8608fd418669062ac8634bd8bb199e882e7b8b397eea7773ebb486d376405948cd00585ad5cf65458afbb939d2d862ec94d0cc95f43da645429aa847f6b373a73377ebbc9a4d74bf12c543eba4116db83f4dd0393c9aa91c87c853c1fa102bed78bf84c8404520ecfa0927229adbeb44087068093a2d84ee4a537840124ae4b6143b6a00eb69861b1548404520ed0a015dd14d86358864bd7c4422cd74f2736031572dc7f6dc0acc5e04dd54c3bd6ff80b6a41393fe771b9a5b5f7c397ff9ef5c8aa3e4a1fc5f7be3be5d3d36cf6f2f544f5d96dc9619db54aad30307aa055197a53207b57d0bd4bee7e2f1d04affc47600a0000000000000000000000000000000000000000000000000000000000000015e88000000000000000080a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b4218080a00000000000000000000000000000000000000000000000000000000000000000a0e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855").to_vec()),
            ], 72486608, 72486610),
        ];
        for (v, child, grand_child) in group {
            let headers = ETHHeaders {
                target: v[0].clone(),
                all: v.clone(),
            };
            let result = headers.verify_finalized().unwrap();
            assert_eq!(result.0.number, child);
            assert_eq!(result.1.number, grand_child);
        }
    }

    #[test]
    fn test_error_verify_finalized_with_many_headers() {
        let v = vec![
            //https://testnet.bscscan.com/block/45214600
            decode_header(hex!("f9057ea06e94ae7ef8cc013f1ddff4519d44823bdb508e10cec2d8c2e191d27f741cbf8ea01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d493479440d3256eb0babe89f0ea54edaa398513136612f5a0766f9938068e5a9fa592451105996d65e587e49b90cc931b243db46891830fc4a0f070fccfa4d96d319030acf9bd07ad61df24cf24ae4c581df633739a6bb2d33da0fea7ba2221ca1582bece7533eb42f6f295d4dbc03e62f14478168e287aad5734b90100040010400040000000000040001000000241000800000000c0000000020400000000104800010000008210000000000000000000020000400100040000200000000000200004000300000008000200002110480000000000a00200004020000004480028a0020001000400000400450008600400000000000020001200000800000808000000000000000000000000000000040000000002240000008000082802008040000000200820000002800042000000000000100002002000000001000000000200000000100804200000000042400000000002c00010480200000000001008000000000001100084000001040008c000008200004040200000000000028402b1eb888405efeb20830ba24a846723446fb90338d88301040e846765746888676f312e32312e34856c696e75780000000299d9bc0808265da01e1a65d62b903c7b34c08cb389bf3d9996f763f030b1adcfb369c5a5df4a18e1529baffe7feaec66db3dbd1bc06810f7f6f88b7be6645418a7e2a2a3f40514c21a3d9d7a717d64e6088ac937d5aacdd3e20ca963979974cd8ff90cbf097023dc8c448245ceff671e965d57d82eaf9be91478cfa0f24d2993e0c5f43a6c5a4cd99850023040d3256eb0babe89f0ea54edaa398513136612f5a334b49d766ebe3eb9f6bdc163bd2c19aa7e8cee1667851ae0c1651f01c4cf7cf2cfcf8475bff3e99cab25b05631472d53387f3321fd69d1e030bb921230dfb188826affaa39ebf1c38b190851e4db0588a3e90142c5299041fb8a0db3bb9a1fa4bdf0dae84ca37ee12a6b8c26caab775f0e007b76d76ee8823de52a1a431884c2ca930c5e72bff3803af79641cf964cc001671017f0b680f93b7dde085b24bbc67b2a562a216f903ac878c5477641328172a353f1e493cf7f5f2cf1aec83bf0c74df566a41aa7ed65ea84ea99e3849ef31887c0f880a0feb92f356f58fbd023a82f5311fc87a5883a662e9ebbbefc90bf13aa533c2438a4113804bfd447b49cd040d20bc21e49ffea6487f5638e4346ad9fc6d1ec30e28016d3892b51a7898bd354cfe78643453fd3868410da412de7f2883180d0a2840111ad2e043fa403ebf9a1db0d6f22bd78ffaeccbc8f47c83df9fbdbcfaade0f78a6b92b38c9f6d45ce8fb01da2b800100201cf0936b6b4b14c98af22edbe27df8aa197fca733891b5b6ca95db04f8b381fbb860a12aed22e41385aa96efa4536ed81355b069fae16992fd46f866f4b2767c09436517e5dbc349d48c2f863cccc472b3ce096d0376779428dd5cd1b28078d5022e529e51c1c97db640b7f1c5b11b1ffb7e7208acf95986a45a0d400a46f0c4c11cf84c8402b1eb86a01125d5208ff92b1ea97d01dadcd5e277f52e143916288d671d5fec8860c3e6b48402b1eb87a06e94ae7ef8cc013f1ddff4519d44823bdb508e10cec2d8c2e191d27f741cbf8e80daa9d3b546986bceb93f5afd160958d6d32f6d9ef81a70b21802a455dad7b9157accef88cd0e459bffd3c1105a0dcb53d877091d8bf84d706274fe7f43c5093f01a0000000000000000000000000000000000000000000000000000000000000000088000000000000000080a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b4218302000080a00000000000000000000000000000000000000000000000000000000000000000").to_vec()),
            decode_header(hex!("f90359a04e47d8db81e515d75a96f36ee409190c402038c06cf05dd5bca71d1099c7cab6a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d493479440d3256eb0babe89f0ea54edaa398513136612f5a0447b10cfc9066c11310db781e39fcebcb9740ba67d4dc550e977be01907defc9a0f56e8363a75117d54a2fe8a7116b5044cb194495745d593d975cab1de018970ba057caa07d7d270fd85713bfdc42240142e48a0cc2458139e862b81413bbc11571b901000000000000000000200000400000100000000000000000000000000020000000000010000000000000000000000000000000000000800000010000000000000000000020000000020001000800000000201000000000000080000000000008000008002020020000000000000000c000084000000000000000000010000000000000400000000000000000000000000000000400000000000400000000000020000080000000002008000000020000000000000000000000020020000000000000000002000000000000000000000000000000000000008000105002002000000000000000000000010000040000030010008400000800004000000000010000028402b1eb898405e9fb36831bdde78467234472b90116d88301040e846765746888676f312e32312e34856c696e75780000000299d9bcf8b381fbb860a8ea6d387b7800147ad2155132dfa95d187f56ebd1c9ece1c8364df305761dfbd516d93423f8c57045228b7ef52fcde104c094aee3794c72efcd475311f88b6d3082f3ee399fd2b9cf58cd3c63350c7cba410fb43e219f419b4b57102daa6378f84c8402b1eb87a06e94ae7ef8cc013f1ddff4519d44823bdb508e10cec2d8c2e191d27f741cbf8e8402b1eb88a04e47d8db81e515d75a96f36ee409190c402038c06cf05dd5bca71d1099c7cab6807a03301635f5c73d1ee0f095f33c697badc2560110a3add7f7d59c995eefac4910b711317255a198ba93410bb88c7e97f860c906d1dc60229a06c551760b3bce00a0000000000000000000000000000000000000000000000000000000000000000088000000000000000080a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b4218080a00000000000000000000000000000000000000000000000000000000000000000").to_vec()),
            decode_header(hex!("f902a3a0a845b19d537d80fc8ae29c4aed49bd6578f4eb5089632d40f708588f6970ebf4a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d493479440d3256eb0babe89f0ea54edaa398513136612f5a04b50b580bbd86f6e198fd9c085f837109c6ff39053625f4a11c7aee0e2cfb63aa0abbe999c7c87fe7427d44e0b0aaf8918a723b17744678bd9ba209368cc82f8a2a08189d28f2391444d7c4868cea83360c6109abe993f55a7d2429d383632c6947bb9010000000000800000000000004000100200000000000004000000000000000800000081100000000000000000000000000000000400000000000100000000000002008000200000000200000008000400002010000000000000800000000000000000080020201200001000000000004000084000100000000008000010800000000400000400000000000004000000000000000480000000000440000000008020400080000000002108000000020000000040000000000000020020000000000000000002000000000000000000000000000000000000008020105402000000000000000000000000010000040000030000008400000000204100000000010800028402b1eb8a8405e4113c8306e52c8467234475b861d88301040e846765746888676f312e32312e34856c696e75780000000299d9bcd0a2b2dcf96ddbb4e8c201a2845fb962fa5a8ea571b6f3fc5c6f30f515cbcc4470ea5545b435334fcb6165032a91423c6803d3771c9874a9a69107e2a27e484e00a0000000000000000000000000000000000000000000000000000000000000000088000000000000000080a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b4218080a00000000000000000000000000000000000000000000000000000000000000000").to_vec()),
            decode_header(hex!("f90359a00113d3d7778af93b122871e02432ded0cc60c8c9fe1cedab69465bc2ed750f29a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d493479440d3256eb0babe89f0ea54edaa398513136612f5a01303affe211de58db87dca446d098e0dee67f3aa4edda393b2e7435f1d706283a0118805b4e132609bbab79efe56918cc539694253ed4555b2d13fe2165480ddf1a0f642c960ec442a236bb3f0749e5be8484773a16493bd9d429ed6929662248001b9010004000000000000000000004000000004000000000000000080000000000400000000100000010000008000000000000000000010000000000100000000200000000000200200800200000008000020002010000000000001800000000000000000080020200200000000000100004000084000000100000000000010000000000000000000000000000000000000000100000400000000000400000080000020020080000000022008000000020000000000000000000000020020000000010010000082000000200040000000000000020000002000008000104042000000000010000000000000010000040000014000008000000000006000000000000000028402b1eb8b8405de2d2c830424308467234478b90116d88301040e846765746888676f312e32312e34856c696e75780000000299d9bcf8b381fbb860b4fa72afe0a0b517bee1ae6ccec530926fedf8abda9f2155d70b4591d6a1cc941d7589410a3e3e61cb004d890c8b4b8002854de11c87173ba7a9dcfd32b63a58b3ffa1f3ac4847a63a4cda1aed80e3b74bafeb1350e9ab5210d81658860757c8f84c8402b1eb88a04e47d8db81e515d75a96f36ee409190c402038c06cf05dd5bca71d1099c7cab68402b1eb8aa00113d3d7778af93b122871e02432ded0cc60c8c9fe1cedab69465bc2ed750f29808b1762cfd0533f76a6853bc389b57c07d84255fcdffb8ec429753ed0cf941e4a1646277e4462b3136f00536f86910b861312fc3cb44070db94e5dccbd035de8400a0000000000000000000000000000000000000000000000000000000000000000088000000000000000080a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b4218080a00000000000000000000000000000000000000000000000000000000000000000").to_vec()),
            decode_header(hex!("f9035aa0dec5be85f92346bb546787db811d23fd88c001d05403f19295273d27a517efdfa01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d493479453387f3321fd69d1e030bb921230dfb188826affa06200e3a8d1b95f53f80ede9a9a721e873085f8df88cbc0b26635b3ee4448ae6aa0430269c352181fe7f46adcc0792dc6973264279fd29bd56af95f9dbf7d42137aa05bdd6a4d4323421b7ade5c786051b9b8b82d8d383c9fd4e4239ce415308e61edb90100b7bef4feffafbcfbdfdfbbf6f6fed3e7bd3effabd7fff76e7bbf73dfdffff5f4edfffe7f5ffedffd7def9f7feb8ebf6ff7bfff9edf7fff7b7ffefb7fbffe77fefe7a9fbfdff7ffff7f97bdf9cf3d6df777fd7ebf6f6ed7eef7d37f756ff3fefffedef7ea3a76f271dd8793b3abc7cfff3ffdeebbf979defff76befdfbbbef3fff9fafbcffffffff2af7eb7bf7ffdffffffffb5ebdbfddd8e9fbbf7fcdfcffdefdeeab71f9ff86f7f7f5e67dff3bedeeaffffedfdbb7bf5e7bb9dffa7f7ff57f773f3f19fffe7bfbc7fd77fbe5bb9ffe7cfeebf9dadfbbbd85fffffefd9ebbd5bff7ffffcd7fbefbf3f77fbbfdff57ff1fed8fffebabbf3fffbf7dd2effbffffe028402b1eb8c8405e40b5884013b6464846723447bb90116d98301040f846765746889676f312e32312e3133856c696e757800000299d9bcf8b381fbb8609126e078b6533f67623a500cbde29ac8153b1e5752d415aa71d75c0046c934da40407f23baa58a466a355a493b9e39c7107ab54ec3a1de320f26c0db35b3f54a4757f3564679f1619d52d4fd26d7ce680f60cf5fa6f67ec01f7e1c34b8b4986af84c8402b1eb8aa00113d3d7778af93b122871e02432ded0cc60c8c9fe1cedab69465bc2ed750f298402b1eb8ba0dec5be85f92346bb546787db811d23fd88c001d05403f19295273d27a517efdf80a7a4d25360dc7cac1c8c8a247e8d6b0a34bd97c689b382ef3d9ec726a74d9c4f3ea17ae295877d17b8a1f4228788fe98ddd627cf68ee27b973660a670ea5581f01a0000000000000000000000000000000000000000000000000000000000000000088000000000000000080a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b4218080a00000000000000000000000000000000000000000000000000000000000000000").to_vec()),
            // needless extra header 45214605
            decode_header(hex!("f9035ca09b8a254f9d47b514499f4a04cbefcdd56187a817bb0c63bac0ce4d13286109c0a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d493479453387f3321fd69d1e030bb921230dfb188826affa0421c3102871a05a9979c407de975640782787a7b8f7a392961c7c64e3c85e325a08cf4795784183f5c2ec8042a2da4881f794035a0f0aff1849e664268fd7591ffa086c1602ec35d3220bd9e102fd1b6a2ac3041a92b0a0b4ec3efd33d05bc7792a7b901001620000a28280d08851831c5860a2f14310001205813003088a10c0038240c285213596b11a1091000f86014002000005438633a104008000121003a41300c41c04244012a50c400c03c149878acb110a830d80851081c07881040052342104018180e68a802e10204404483040884200871c20419102302844065be030480328425c072500290600528008801000a0140441420021a644905051c888d20d1a006108c2531418733aa83840002812a0898000d04a20240a186122438040011011692d08322c214001440122693e611c4c81b0002c21482c58410444a2ca482000c320a806420045e0321081460320578804a90090113082071840020ca196304028402b1eb8d8405e9ef628339ba31846723447eb90116d98301040f846765746889676f312e32312e3133856c696e757800000299d9bcf8b381fbb86092d8322498605243d598d94daa1e8811ea1dca1329a85b5e469c5db21ccacc0d8b98ceb7d2c38f03f9e28aa9491c7b5808e6186eda83665c1e44642e84505974fe94cad46da0fda27cc8226c669b2c4ba4665fcf5a5080d420d08bfb7f1ef657f84c8402b1eb8ba0dec5be85f92346bb546787db811d23fd88c001d05403f19295273d27a517efdf8402b1eb8ca09b8a254f9d47b514499f4a04cbefcdd56187a817bb0c63bac0ce4d13286109c08011235fdd3e6e156439d7bf240c25457ac219d545129108ead575663444f503d6244e3f979c3a7f12040eb5f9d33832c03be3ed674467897d2294e4aedfd96c3800a0000000000000000000000000000000000000000000000000000000000000000088000000000000000080a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b4218304000080a00000000000000000000000000000000000000000000000000000000000000000").to_vec()),
        ];
        let headers = ETHHeaders {
            target: v[0].clone(),
            all: v.clone(),
        };
        let result = headers.verify_finalized();
        match result.unwrap_err() {
            Error::UnexpectedTooManyHeadersToFinalize(e1, e2) => {
                assert_eq!(e1, headers.target.number, "block error");
                assert_eq!(e2, headers.all.len(), "header size");
            }
            e => unreachable!("{:?}", e),
        }
    }

    #[test]
    fn test_error_verify_finalized_with_many_headers_fermi() {
        let group = [
            vec![
                decode_header_with_fermi(hex!("f90370a061e54cba38225d35f042c6bd5ae8d6f981a451f3a53e49313b570db907ee2dd2a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d4934794d9a13701eafb76870cb220843b8c6476824bfa15a0396436866456ceb1c4b702cb5d3a4b1e2495d84619f1ba7142b80e59e8342a88a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421b9010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000028201fa8402625a008084690eacdbb90111d983010602846765746889676f312e32342e3130856c696e757800000d382c2cf8ae07b86089aa2052e18ebe839aa3723bcad27b2a2196e22b7bc11c4d4d24d4a69e01e86bd404d19a0345c922456c8f6badd351d907fb69a6590bfad9673c8fdb9fc38bdd73b9bb4c93bb3d349380322366b1dc6d294e0e6916ef256ccbfa245255e43ad3f8488201f6a09058cfa000d451f4cd49092133047c1cf4a29d2c905a9aa17c890e96d81513d08201f8a0464df616013723293103002550e47ce3e44eb7dee4b11bfa10daeb4a2df51215802185ef1b54bfba22b6d1be5d4988c592b1da29abd380ea7d98def9b4f17e66f50b580baa6e8481b1b15b424ceddbf66964f633371d73a62825c67f9c633077d501a000000000000000000000000000000000000000000000000000000000000000c888000000000000000080a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b4218080a00000000000000000000000000000000000000000000000000000000000000000a0e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855").to_vec()),
                decode_header_with_fermi(hex!("f902bfa06510e76fec4471a1dd46e83484608cba84a2c0860ed484dc785aaeca5bc24598a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d4934794d9a13701eafb76870cb220843b8c6476824bfa15a0ed3a25beff351197a86ea87f939c7a129d7e7b9759a5c125875e58424c774c96a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421b9010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000028201fb8402625a008084690eacdbb861d983010602846765746889676f312e32342e3130856c696e757800000d382c2c9ed5d62372f22f62c2442552b80af1e868265d205a6132a44c10bbc50fe017bc1f9ad3f3c89381a992f177e292821630df0079134f002dcaaca675e5486b796400a0000000000000000000000000000000000000000000000000000000000000028a88000000000000000080a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b4218080a00000000000000000000000000000000000000000000000000000000000000000a0e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855").to_vec()),
                decode_header_with_fermi(hex!("f90370a042ac9f2075511d2293a3448edba653bd1fe6cb7bf4b6fd9597d98bd3e1168eeea01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d4934794d9a13701eafb76870cb220843b8c6476824bfa15a0027e1be8380711bbe9075b3d99dd23e59769711f03064b2a42f03c5a4ee2294da056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421b9010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000028201fc8402625a008084690eacdcb90111d983010602846765746889676f312e32342e3130856c696e757800000d382c2cf8ae07b8608509853e9fab817fba4600c12d1689548f6566e22277a0fbfc99c0c241e53362550e13bb2c1da81dd133a953539febce16760742ac3462ae106c4d7db8422bdb9e01f1d7285251940badbec7358f923e6ff267135f0c6e73963e5340edb495d7f8488201f8a0464df616013723293103002550e47ce3e44eb7dee4b11bfa10daeb4a2df512158201faa06510e76fec4471a1dd46e83484608cba84a2c0860ed484dc785aaeca5bc2459880d63a5ec69ce06dbbe045deffd2cf87000fe0b91a727973edbdb980ab86d80eee0e272ce2600c634d7ee5cb2d4f4b2139e924a6f6d6f818fda0ed8b02d69be61901a0000000000000000000000000000000000000000000000000000000000000006488000000000000000080a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b4218080a00000000000000000000000000000000000000000000000000000000000000000a0e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855").to_vec()),
                decode_header_with_fermi(hex!("f902bfa04dbe87a2afcbd4599b997d68b7976c15d5d6c78fbaa2586541c6ab1a5d3051e9a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d4934794d9a13701eafb76870cb220843b8c6476824bfa15a0c5b6d22e10686a802dfe562e6b2de199ebecf18aae5a284aa531fd4137fdcd3ea056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421b9010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000028201fd8402625a008084690eacdcb861d983010602846765746889676f312e32342e3130856c696e757800000d382c2caf975e1c326acf700081afa54cc4b2a84fb67ec15733488c488cf2b2c4c22862646c5b21762fe5df77abfbc6076eccaaf445af23e584b33cf602f7134125999500a0000000000000000000000000000000000000000000000000000000000000022688000000000000000080a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b4218080a00000000000000000000000000000000000000000000000000000000000000000a0e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855").to_vec()),
                decode_header_with_fermi(hex!("f90370a0fca3ee6eb6331d3caf5310dcea500b6d06ea5dee08972a285d3c8bcf2848e542a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347948fdaaa7e6631e438625ca25c857a3727ea28e565a06bfb3c7904a7b6347689fea2fc0ad3e0bcc6597d4817c9ce132e8a4962b740e2a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421b9010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000028201fe8402625a008084690eacddb90111d983010602846765746889676f312e32342e3130856c696e757800000d382c2cf8ae07b860ab54b1e139a3e5345731e228daccb85fa7641a6f4873057022d1f6979c69b2d4193d96068a9c23ea7f0540f7f2bf8e210493a01df523bc4e8b15f02c772425bbfd8577e33cb603b6d8349834cd678e4e15799e141d2bd15dba147302116566fcf8488201faa06510e76fec4471a1dd46e83484608cba84a2c0860ed484dc785aaeca5bc245988201fca04dbe87a2afcbd4599b997d68b7976c15d5d6c78fbaa2586541c6ab1a5d3051e9809de85618105acd64900a429445efd27d81e587f6dca6a8e4ea0ad219111078ec0696d6064a4b8e7251883f0cb52f2fa5e33389fc934b11be1b581c357d46bca600a0000000000000000000000000000000000000000000000000000000000000000088000000000000000080a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b4218080a00000000000000000000000000000000000000000000000000000000000000000a0e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855").to_vec()),
                // needless extra header 511
                decode_header_with_fermi(hex!("f902bfa017ba2114c707b78b79e70fc2f8dc8b6ddcfd8ca3fad0c2115cf05111ff865695a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347948fdaaa7e6631e438625ca25c857a3727ea28e565a065f0ba129f50fbcbf32eb7de857c4c4c44badd35a99a0c6bfb517c0462de74b0a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421b9010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000028201ff8402625a008084690eacddb861d983010602846765746889676f312e32342e3130856c696e757800000d382c2c1e40742b370bb15747155578c7f59f64ad37dd399daac65551a8fa5c3676b2f16b07ab1fbc426420a99cdbd995c35e6f3944b28a1f870743e74defb75743bafd00a000000000000000000000000000000000000000000000000000000000000001c288000000000000000080a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b4218080a00000000000000000000000000000000000000000000000000000000000000000a0e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855").to_vec()),
            ],
            vec![
                decode_header_with_fermi(hex!("f902bfa0c9e4ade6549940a3176549973e104db99f5d76414a75dac85c5c7d8ac4944c02a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d4934794a7876ea32e7a748c697d01345145485561305b24a07af9c8b256e0568fefd01da65fc184d2b99ddbc941bb73f8c1a4a88b4829733ca056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421b90100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000282030c8402625a008084690ec149b861d983010602846765746889676f312e32342e3130856c696e75780000c2625646e9f66472b1e36d0741b3a83cbb5bd08c15a2fd0d7221d740fa2cabe6fd732af37c0f21fc754af73a60d342c9361fb181d88d31559932c6ad48d6b2100e8d0cb801a000000000000000000000000000000000000000000000000000000000000000c888000000000000000080a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b4218080a00000000000000000000000000000000000000000000000000000000000000000a0e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855").to_vec()),
                decode_header_with_fermi(hex!("f90370a06fba6c4d22a8bbeeabab7ed42399df6d1e5619583c2fa5c8501ab92fed48a008a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d4934794a7876ea32e7a748c697d01345145485561305b24a03619e2f634b93ad603a07e2cd8f74972b76430a2717ada94d8a514a41c305548a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421b90100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000282030d8402625a008084690ec149b90111d983010602846765746889676f312e32342e3130856c696e75780000c2625646f8ae03b86090555af20ed36f5aabeb62da55f3375f12579bdc1a879f5313c5d9c56b413e3eeb284aa748fb42e39553c15e3d54cb9c01d2aeaa6ad89fe64c3fe291e773e6935a7ea5dbf399cd4654555a82f6d4701b85f4f75b93cc2f57fcdcb949f87e54a0f848820307a024b038aa32c2b8788a5dd68a43d5d35425d00213fc6f61e7c35e1774a6519cdc82030aa0cad7cf4aefc3ec5ca95b1039846bc3faccc900fe1f0a798ea63f801f337588358077a98dfbef98d18c23c0d5b424124afe304dc22f50b5aadbf3f93cd1feac4e76448716c07cc72502f7a033a1ab6850ce30bc21f16240a2705bea1f7fe9403a3e00a0000000000000000000000000000000000000000000000000000000000000028a88000000000000000080a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b4218080a00000000000000000000000000000000000000000000000000000000000000000a0e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855").to_vec()),
                decode_header_with_fermi(hex!("f902bfa0d55e5ceb7a93760e0c614643e8d181c5d3c65d2c6ad80d4343a5935a9ac037caa01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d4934794a7876ea32e7a748c697d01345145485561305b24a0506ec5106e98498ec95882fcd5f03dfbaae3c61a552d3e5308db4dbf4763e5c5a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421b90100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000282030e8402625a008084690ec14ab861d983010602846765746889676f312e32342e3130856c696e75780000c26256461e8802da3c1054ff83171c0a1b235cc70ba935d52841d7b9e60ed0bde9a3a9d31fe7d19f9a818b7426b8070a6713198cc0ed936785c05611481fad81cf3c694c01a0000000000000000000000000000000000000000000000000000000000000006488000000000000000080a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b4218080a00000000000000000000000000000000000000000000000000000000000000000a0e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855").to_vec()),
                decode_header_with_fermi(hex!("f902bfa0342d99d1728fd05ac3a821162f7cff5569a62d0d09c78277c9e701e4b7ac4883a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d4934794d9a13701eafb76870cb220843b8c6476824bfa15a002874b20b003e0afd996d22c352c8a8ec8bc0b0986743a96fad3cd5e81cbd0d4a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421b90100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000282030f8402625a008084690ec14ab861d983010602846765746889676f312e32342e3130856c696e75780000c26256466815abc1b4b5c335ad0a1ed2bd17a021211d5b1f8d75b2c4dc7ab26ce8a5486f425ed9645510451596affdc1e602ead6dca707266f188544b02c2d247d1832ef00a0000000000000000000000000000000000000000000000000000000000000022688000000000000000080a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b4218080a00000000000000000000000000000000000000000000000000000000000000000a0e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855").to_vec()),
                decode_header_with_fermi(hex!("f90370a044122401ce9e6f2bbd26016c1c6ec98f09f9d2a3f7b50dd838561b3aebdc74bca01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d4934794d9a13701eafb76870cb220843b8c6476824bfa15a0625fb0ac90a3457ceda3880024019e6ee61dbfdadd78e7386025cb8c29ed9069a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421b9010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000028203108402625a008084690ec14bb90111d983010602846765746889676f312e32342e3130856c696e75780000c2625646f8ae03b8608ee466a4507c0ed1cfc0e119d9e4e1d25c1c82047d65886cbc58c25adb71c661f5ab6c48e97ee4e84515091d93ff978b02cf9514f22b413b455a629e25f7162a02e551f7609b7e4dc8d5f83347b8b524e78fa211ced41fc04478ea6efe7b1e78f84882030aa0cad7cf4aefc3ec5ca95b1039846bc3faccc900fe1f0a798ea63f801f3375883582030da0d55e5ceb7a93760e0c614643e8d181c5d3c65d2c6ad80d4343a5935a9ac037ca802b77e755536d4064ee5c0366e175260503bb8dbfe7295c533175302de08be87e5e336eaf138730cd57069f2002d2646dca55e525d283897c62f7eeb0a9ff5c9f01a0000000000000000000000000000000000000000000000000000000000000000088000000000000000080a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b4218080a00000000000000000000000000000000000000000000000000000000000000000a0e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855").to_vec()),
                decode_header_with_fermi(hex!("f902bfa060408654260d46aabcf65cf0dd8b29b95599b55380ea57857b29f723adc443fda01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d4934794d9a13701eafb76870cb220843b8c6476824bfa15a051ac73c5703c15e58e98df4e118219b601034918cc803e00041ed0618cf8e960a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421b9010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000028203118402625a008084690ec14bb861d983010602846765746889676f312e32342e3130856c696e75780000c262564692a109b1b71100625a7312aad649212af6c20ed6fa698bf0cfaf71b52bbe54af7f32815be4c7df330df25c2a2cdcafaa126ba01b17a69c41bb14fafab8352b0301a000000000000000000000000000000000000000000000000000000000000001c288000000000000000080a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b4218080a00000000000000000000000000000000000000000000000000000000000000000a0e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855").to_vec()),
                decode_header_with_fermi(hex!("f902bfa02feea8d1b311b45029924cf412d39b6e9898d664ae659bf7c3e3a25df3defeb3a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d4934794a7876ea32e7a748c697d01345145485561305b24a054f8faa7215319277fa00eae4bf3886dbe7adb37c8a8968207e46bc4a073781da056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421b9010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000028203128402625a008084690ec14bb861d983010602846765746889676f312e32342e3130856c696e75780000c26256469322825fd21edfdd57dac75a867dc4060e3b234e16f771b1e186f1e2a399b7242f8b59f3fb1ea9b08228c3c12692628ac1664a75177640c862415f261481b7f300a0000000000000000000000000000000000000000000000000000000000000038488000000000000000080a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b4218080a00000000000000000000000000000000000000000000000000000000000000000a0e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855").to_vec()),
                decode_header_with_fermi(hex!("f90370a0f2880c072f0674e90a40006553f5a28758f78902268f17e0f8b8cdcf0bea04fda01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d4934794a7876ea32e7a748c697d01345145485561305b24a001a48ccfc24533e019befebeef5131644d239fb5fc4756a7c7e251a2bdc0a231a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421b9010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000028203138402625a008084690ec14cb90111d983010602846765746889676f312e32342e3130856c696e75780000c2625646f8ae03b860b63fd76261cb5cc16f53e82133c937e2042443bddf92b8d55982c69360241067d0b707604972b10ab624d2ded8d411b71760bc28ffe89c5906595a3a43135e9678c025fe8694b77a859674bc2c0dfc9abaa58640ab6b43f607facb410d087023f84882030da0d55e5ceb7a93760e0c614643e8d181c5d3c65d2c6ad80d4343a5935a9ac037ca820310a060408654260d46aabcf65cf0dd8b29b95599b55380ea57857b29f723adc443fd80108f12a9c98aa2d2c3944a3bb0f45c0c2e479549a84f6a0ce5741475229c12ca2242d904fa10057e2dfd5ab42a4b06d1201c2565005763eda37bc060cfa00fc200a0000000000000000000000000000000000000000000000000000000000000015e88000000000000000080a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b4218080a00000000000000000000000000000000000000000000000000000000000000000a0e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855").to_vec()),
                // needless extra header 788
                decode_header_with_fermi(hex!("f902bfa005f5c1fbf4b14ee14c269b267e3afc97d30df31076f6d7ebfad3e866e9a3fc77a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d4934794a7876ea32e7a748c697d01345145485561305b24a084f3d57cc35e7f88c4ba1f61e783b241680c27149b0b820d0808b1bb9311ef9ea056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421b9010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000028203148402625a008084690ec14cb861d983010602846765746889676f312e32342e3130856c696e75780000c262564626c826948d0e3fe1cf3ca4c7a2a139dd9bb69e95f4a1ed45c461c890baf69b14480f15d9acf53924d5c1744b0f28ab93e9af847093816d52664dd3d63c00c05301a0000000000000000000000000000000000000000000000000000000000000032088000000000000000080a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b4218080a00000000000000000000000000000000000000000000000000000000000000000a0e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855").to_vec()),
            ],
            vec![
                decode_header_with_fermi(hex!("f9037aa0927229adbeb44087068093a2d84ee4a537840124ae4b6143b6a00eb69861b154a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347947f5f2cf1aec83bf0c74df566a41aa7ed65ea84eaa09758bd6b22c47cbab71682ebe5a0d491d6fd602030c36191b1c452108b12ce9ba0c10ee260e1302f2968d14030935957e496a45c186e00c506401e5d1d3206dba3a09d5348954d8cc85a4f7a3d8f7782fa98168746ea673c93618a21f6b67cbd7596b90100c0c010d01000192108c080c08714a30000a00c5c86022108452210200a0007d190d113020b49e801800048285140e07441112051ea0500804314204006202941000944810a8a18330100000cc10009003990b30040c9071524349270cae14094027a20fdd20a00a19a100008106808408a2090c4030e010c00086512280a8383c6222cdd100415000020802406424800408847862421c16e1219010801b09023020429534974532168000c004a0010440880006220001280184848b0850800a0cb00173e886a292850c206104b1792a353820810280458512094508a92202301181640020864682009034c668c8115e102018032e1a97a00480720000040081a028404520ed0840393870083a7a3cb846915a242b90116d883010603846765746888676f312e32342e39856c696e75780000005b240570f8b381ffb8608fe47768d7664ebd7100b41eab5ec8ba81d0d18a823b0558894c28512e8b9011c08ff5fd8835d7c5162fae4eedc9c12710a236ee5b399028a5856cbc79e0db6ae627bd06cdf638a5aab208dc141c5156bf9cc9a791bd3842b00f2aff393239b1f84c8404520ecea0f07121ac67d5ac8171d16d6dd53a968160e091ea3346fcfa6bdb53c4bbb4c8fa8404520ecfa0927229adbeb44087068093a2d84ee4a537840124ae4b6143b6a00eb69861b154801b31de7aecb339fcfb2b43796eadaf626c43892ec60caeb3b5a2663337f93a8241bbe3dccacb4548234f9972a3e1ff2d20675a25bfa6ee9b00f55471575915a701a000000000000000000000000000000000000000000000000000000000000001c288000000000000000080a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b4218080a00000000000000000000000000000000000000000000000000000000000000000a0e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855").to_vec()),
                decode_header_with_fermi(hex!("f902c4a015dd14d86358864bd7c4422cd74f2736031572dc7f6dc0acc5e04dd54c3bd6ffa01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347947f5f2cf1aec83bf0c74df566a41aa7ed65ea84eaa066ef3ab3f6400aa818434f02469813592133534dbb453377fb493adc78adc118a03ba925fd87820072d58827d2a661a5f7937e6b49a04baabc9d146b6b26e52c56a0bf08758ce3cb32054ce1a2476fcaed8c0cea284f997335617473b9ebf7c19b12b90100a00029800000801e282228c0879843c020401040000931108620b2320e0025428010941033013001107108a018c4e8242100de1011848400e154000042a16014004940e12a0201476072464c6c100208b1d88500118000040634126822210040088af0f08202c213cc1430881020080188039008a248203e10054932c048c03100620c9240848c0a6520c4c244105900008807e10021046c229003800ce09127f30a0c10e4446168e8830c0002218000800241010519020032508010c0040c610900d14e2060081800900702017390227080702028400cd5289440439005b488119256022050e000499154c6c08801050a05904020a80008c20120480018003b028404520ed18403938700839d895a846915a242b861d883010603846765746888676f312e32342e39856c696e75780000005b24057070e3f36857d8a5d61002abfa41c9d2ab6d930cccd00f2a14858ad50a7871f6f61d63bf98101465e416efe7c1b3fb5ef7ca05d1b5f4b5cd389a8df39d95da9aab01a0000000000000000000000000000000000000000000000000000000000000038488000000000000000080a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b4218080a00000000000000000000000000000000000000000000000000000000000000000a0e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855").to_vec()),
                decode_header_with_fermi(hex!("f9037aa0f1f70f9eade2a06caf03876dbe5b77acc355290bde28c21e758201931b7d06dca01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347947f5f2cf1aec83bf0c74df566a41aa7ed65ea84eaa08b0e7d3df3a0d279160c7107d5b3c984c86c4db3cae65e1f057bf65f24f74bd7a062f2227465041b8a0729419b66744ce934dfd44ded3c89e98b64c66d854435f4a0a27c94fe9db012ddc0510d673bc2e151e1122fdf51617438e4da525da59e3002b9010020005084c0041821480001cb87001910224000c88000188904a411221a8015440114134c83416e8000020c28204160224302931008854815c114102096a0222260094082030211130800081d4280502021b1830810000000001c1a0242e36580002a20a0728e465288200580309e8812ca4130d08608c209800010180290100911027c989414ac01c0e688040500d883c43885121020226c0a1a4000012cb32147034c1000646020680226109a0010000000300400c02a094242a81002b2022039010186c162100243894613118b10a240002a8040800858215649821e0471480211503a054344540961c44500a813050201800080b224054c0920c00a00003b028404520ed2840393870083b91464846915a243b90116d883010603846765746888676f312e32342e39856c696e75780000005b240570f8b381fbb8608fd418669062ac8634bd8bb199e882e7b8b397eea7773ebb486d376405948cd00585ad5cf65458afbb939d2d862ec94d0cc95f43da645429aa847f6b373a73377ebbc9a4d74bf12c543eba4116db83f4dd0393c9aa91c87c853c1fa102bed78bf84c8404520ecfa0927229adbeb44087068093a2d84ee4a537840124ae4b6143b6a00eb69861b1548404520ed0a015dd14d86358864bd7c4422cd74f2736031572dc7f6dc0acc5e04dd54c3bd6ff80b6a41393fe771b9a5b5f7c397ff9ef5c8aa3e4a1fc5f7be3be5d3d36cf6f2f544f5d96dc9619db54aad30307aa055197a53207b57d0bd4bee7e2f1d04affc47600a0000000000000000000000000000000000000000000000000000000000000015e88000000000000000080a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b4218080a00000000000000000000000000000000000000000000000000000000000000000a0e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855").to_vec()),
                decode_header_with_fermi(hex!("f90379a0bfde5240efbf9dda1381cf5ead3039a1c6b55c5dae95cb044c23fc2c2611f379a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347947f5f2cf1aec83bf0c74df566a41aa7ed65ea84eaa0c139cd27cf0c4981fab2ad057854aeff51f9c416d97a733d3cff4d8fc80fcac5a0822ba47aed5ce6f1b995eb5f9f85635e8f330b5642835fd5feaedb310e056571a0666894d3380ee97be17bcb46ce09f1c585917458d6a92be7aeb81b6a466d56cdb9010001210080122011352a0868c0c79281001778024088800008062050700f224540001b9441134370280d2008a4b009e02409050b1001050020f334122406622407000950e00a4324030020046ec00450142195c1280248000830841701022fa022808b20a0032308480820d7003c2008220b18d25c5209004c060040b10404292100120cd050a4840900209901fc20490520480f200221105c225100810020902be2048910244d4268683005000a2200008200038920181b0030498810000080a68d004586086c20a080880e11011390221a00100041900e5031b4438a1800a05008546002004050980f095cc61cb00b000313808090a000226001318091c0095b028404520ed38403938700839d2605846915a243b90115d883010603846765746888676f312e32342e39856c696e75780000005b240570f8b27fb860b256cac937e461138b0c95cd43c783efad7ae7c1bff57bf9c2366eaee6a8ffface7e809ea699b8e4f6bf5659fed22d72001fd1f7d3038bbe44036711d56140c2c9f5e1e91a6473e884bebe374dabf6b9f61d547e8ed93f908c449e18d6f65843f84c8404520ed0a015dd14d86358864bd7c4422cd74f2736031572dc7f6dc0acc5e04dd54c3bd6ff8404520ed2a0bfde5240efbf9dda1381cf5ead3039a1c6b55c5dae95cb044c23fc2c2611f379809fbce16268145ce40e6e8e7928b4a3719ff036f5814c5a22ebd4b15af108892e169598a3b849d0d069162550728367af38819a3ea79133cd3dff51ae58e8299100a0000000000000000000000000000000000000000000000000000000000000032088000000000000000080a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b4218080a00000000000000000000000000000000000000000000000000000000000000000a0e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855").to_vec()),
                // needless extra header 72486612
                decode_header_with_fermi(hex!("f90379a0e8aa64f5f44279a1e3bfcd29989cdedcc7793c568a2b4aa62350ec9875a96353a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347947f5f2cf1aec83bf0c74df566a41aa7ed65ea84eaa05be98e8b2b167c935ec6ba77224bb2c3e287abf097664b682d5b396896f1940aa0d09a64a9d4c18262f028ac50a817f679ec2bedb96bca0e3721c33041d3de4893a0013496ca883b899be1d51e226f9514912a9361df7703ceeeda2a70a0dc917492b9010000202090101410a51d0400c297409100103000c80310143c847011200a0015411810180083012000f380086310006436736801380a0400248f1400404224a49550495180a2060c032408080c41132400a994c13c12810254029412902a210000221a21a07242c00408a00412d68009000a04901c028840490880c0160c21902110036d980404172000288a2024104dc600186f118829004c1212c4004271d2251e040810004640e468870cd00a04d802067004200b40864411643410000c01a009098117a8e02451008014c4934798220a480008400208702934400b520021048018502a2240c05c09054c6620a0c508c209802014a20443c271a01cc0010b1a028404520ed4840393870083b5c17a846915a244b90115d883010603846765746888676f312e32342e39856c696e75780000005b240570f8b27eb860853c54a7020f687fc2635018b215b7be7d713d6b8c593c718cacbff7d67ddacabc1e9db6c60281c8894c071598c4154d18864b32d27c38e9f541551663bc3f423f569262cf7bf4b10b85f740642a87a29b226dc59fdaa143f993e135c5057856f84c8404520ed2a0bfde5240efbf9dda1381cf5ead3039a1c6b55c5dae95cb044c23fc2c2611f3798404520ed3a0e8aa64f5f44279a1e3bfcd29989cdedcc7793c568a2b4aa62350ec9875a9635380f6f44c19e25d912c5aa103c448e8b1dfb9292b67730c44406ca22b3caa8e590035dd08960989a9d9ea760f912909e3795fb1738107f34ab8042d126258ac484f01a000000000000000000000000000000000000000000000000000000000000000fa88000000000000000080a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b4218080a00000000000000000000000000000000000000000000000000000000000000000a0e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855").to_vec()),
            ],
            vec![
                decode_header_with_fermi(hex!("f9037ca0f07121ac67d5ac8171d16d6dd53a968160e091ea3346fcfa6bdb53c4bbb4c8faa01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d493479476d76ee8823de52a1a431884c2ca930c5e72bff3a0a912e6ea62e22dc56dfe25f1bc6499c625aa8b0e8187c063a8a86268a9a02e97a05f357e7dc8c855f88f2d123803bbfaba01ac3b8d7c31291c50e4089c7a1772afa0c5a8a65b39d65b26a2bca5a9df1d72cf21b9c8607f5f261a3d033d49c86dbdbdb901002108018183020425882084d197000d004a0400624000050a0420122c6a0025c4001818031711a84000080960900862348d2080180004a001031710000224a206006d4d832202218e0104404c4920002021978504098800944084baa19a298000212ea0b506830981206924201a9148402a00b419c2088588a02000d800002343aa924494010ca431883082008582e810208845800921224f0b140c318828d423020aea10004441206a200c588a08002a8180040040400a30506028112b08a0a88d1009c60171406024800408834f902210200040c48888942334c1125204a0000491492258784c003d016446388101158249881220e2050044412c0141208018028404520ecf840393870083a6718a846915a242b90115d883010603846765746888676f312e32342e39856c696e75780000005b240570f8b27eb860b5a6f9f402f631ffed730409610cca7b3fabc6f5eea85c92a8cb27788c91379200ed48ebedd3917f11b485402c2a93f7188557ffde951cfbf16e46436c975195ed399eb0812869753d2f7fa0339bae003e42f740bdefef6e97df6200ca0f9fc9f84c8404520ecda098cf3fa4edde97a7f029c8a811a7cbde48f93d7e9fe061d2c5a3213131d498048404520ecea0f07121ac67d5ac8171d16d6dd53a968160e091ea3346fcfa6bdb53c4bbb4c8fa80d3562d9f71d7cbf6a8e0975dd2f94b24d481a565fc94ca5bb9a3e7bc9f5b06a752070b588f1b9abcead0513fa30e81d43ea322d3a076290a99f5a21043bf9ee700a0000000000000000000000000000000000000000000000000000000000000000088000000000000000080a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b4218302000080a00000000000000000000000000000000000000000000000000000000000000000a0e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855").to_vec()),
                decode_header_with_fermi(hex!("f9037aa0927229adbeb44087068093a2d84ee4a537840124ae4b6143b6a00eb69861b154a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347947f5f2cf1aec83bf0c74df566a41aa7ed65ea84eaa09758bd6b22c47cbab71682ebe5a0d491d6fd602030c36191b1c452108b12ce9ba0c10ee260e1302f2968d14030935957e496a45c186e00c506401e5d1d3206dba3a09d5348954d8cc85a4f7a3d8f7782fa98168746ea673c93618a21f6b67cbd7596b90100c0c010d01000192108c080c08714a30000a00c5c86022108452210200a0007d190d113020b49e801800048285140e07441112051ea0500804314204006202941000944810a8a18330100000cc10009003990b30040c9071524349270cae14094027a20fdd20a00a19a100008106808408a2090c4030e010c00086512280a8383c6222cdd100415000020802406424800408847862421c16e1219010801b09023020429534974532168000c004a0010440880006220001280184848b0850800a0cb00173e886a292850c206104b1792a353820810280458512094508a92202301181640020864682009034c668c8115e102018032e1a97a00480720000040081a028404520ed0840393870083a7a3cb846915a242b90116d883010603846765746888676f312e32342e39856c696e75780000005b240570f8b381ffb8608fe47768d7664ebd7100b41eab5ec8ba81d0d18a823b0558894c28512e8b9011c08ff5fd8835d7c5162fae4eedc9c12710a236ee5b399028a5856cbc79e0db6ae627bd06cdf638a5aab208dc141c5156bf9cc9a791bd3842b00f2aff393239b1f84c8404520ecea0f07121ac67d5ac8171d16d6dd53a968160e091ea3346fcfa6bdb53c4bbb4c8fa8404520ecfa0927229adbeb44087068093a2d84ee4a537840124ae4b6143b6a00eb69861b154801b31de7aecb339fcfb2b43796eadaf626c43892ec60caeb3b5a2663337f93a8241bbe3dccacb4548234f9972a3e1ff2d20675a25bfa6ee9b00f55471575915a701a000000000000000000000000000000000000000000000000000000000000001c288000000000000000080a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b4218080a00000000000000000000000000000000000000000000000000000000000000000a0e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855").to_vec()),
                decode_header_with_fermi(hex!("f902c4a015dd14d86358864bd7c4422cd74f2736031572dc7f6dc0acc5e04dd54c3bd6ffa01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347947f5f2cf1aec83bf0c74df566a41aa7ed65ea84eaa066ef3ab3f6400aa818434f02469813592133534dbb453377fb493adc78adc118a03ba925fd87820072d58827d2a661a5f7937e6b49a04baabc9d146b6b26e52c56a0bf08758ce3cb32054ce1a2476fcaed8c0cea284f997335617473b9ebf7c19b12b90100a00029800000801e282228c0879843c020401040000931108620b2320e0025428010941033013001107108a018c4e8242100de1011848400e154000042a16014004940e12a0201476072464c6c100208b1d88500118000040634126822210040088af0f08202c213cc1430881020080188039008a248203e10054932c048c03100620c9240848c0a6520c4c244105900008807e10021046c229003800ce09127f30a0c10e4446168e8830c0002218000800241010519020032508010c0040c610900d14e2060081800900702017390227080702028400cd5289440439005b488119256022050e000499154c6c08801050a05904020a80008c20120480018003b028404520ed18403938700839d895a846915a242b861d883010603846765746888676f312e32342e39856c696e75780000005b24057070e3f36857d8a5d61002abfa41c9d2ab6d930cccd00f2a14858ad50a7871f6f61d63bf98101465e416efe7c1b3fb5ef7ca05d1b5f4b5cd389a8df39d95da9aab01a0000000000000000000000000000000000000000000000000000000000000038488000000000000000080a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b4218080a00000000000000000000000000000000000000000000000000000000000000000a0e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855").to_vec()),
                decode_header_with_fermi(hex!("f9037aa0f1f70f9eade2a06caf03876dbe5b77acc355290bde28c21e758201931b7d06dca01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347947f5f2cf1aec83bf0c74df566a41aa7ed65ea84eaa08b0e7d3df3a0d279160c7107d5b3c984c86c4db3cae65e1f057bf65f24f74bd7a062f2227465041b8a0729419b66744ce934dfd44ded3c89e98b64c66d854435f4a0a27c94fe9db012ddc0510d673bc2e151e1122fdf51617438e4da525da59e3002b9010020005084c0041821480001cb87001910224000c88000188904a411221a8015440114134c83416e8000020c28204160224302931008854815c114102096a0222260094082030211130800081d4280502021b1830810000000001c1a0242e36580002a20a0728e465288200580309e8812ca4130d08608c209800010180290100911027c989414ac01c0e688040500d883c43885121020226c0a1a4000012cb32147034c1000646020680226109a0010000000300400c02a094242a81002b2022039010186c162100243894613118b10a240002a8040800858215649821e0471480211503a054344540961c44500a813050201800080b224054c0920c00a00003b028404520ed2840393870083b91464846915a243b90116d883010603846765746888676f312e32342e39856c696e75780000005b240570f8b381fbb8608fd418669062ac8634bd8bb199e882e7b8b397eea7773ebb486d376405948cd00585ad5cf65458afbb939d2d862ec94d0cc95f43da645429aa847f6b373a73377ebbc9a4d74bf12c543eba4116db83f4dd0393c9aa91c87c853c1fa102bed78bf84c8404520ecfa0927229adbeb44087068093a2d84ee4a537840124ae4b6143b6a00eb69861b1548404520ed0a015dd14d86358864bd7c4422cd74f2736031572dc7f6dc0acc5e04dd54c3bd6ff80b6a41393fe771b9a5b5f7c397ff9ef5c8aa3e4a1fc5f7be3be5d3d36cf6f2f544f5d96dc9619db54aad30307aa055197a53207b57d0bd4bee7e2f1d04affc47600a0000000000000000000000000000000000000000000000000000000000000015e88000000000000000080a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b4218080a00000000000000000000000000000000000000000000000000000000000000000a0e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855").to_vec()),
                // needless extra header 72486611
                decode_header_with_fermi(hex!("f90379a0bfde5240efbf9dda1381cf5ead3039a1c6b55c5dae95cb044c23fc2c2611f379a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347947f5f2cf1aec83bf0c74df566a41aa7ed65ea84eaa0c139cd27cf0c4981fab2ad057854aeff51f9c416d97a733d3cff4d8fc80fcac5a0822ba47aed5ce6f1b995eb5f9f85635e8f330b5642835fd5feaedb310e056571a0666894d3380ee97be17bcb46ce09f1c585917458d6a92be7aeb81b6a466d56cdb9010001210080122011352a0868c0c79281001778024088800008062050700f224540001b9441134370280d2008a4b009e02409050b1001050020f334122406622407000950e00a4324030020046ec00450142195c1280248000830841701022fa022808b20a0032308480820d7003c2008220b18d25c5209004c060040b10404292100120cd050a4840900209901fc20490520480f200221105c225100810020902be2048910244d4268683005000a2200008200038920181b0030498810000080a68d004586086c20a080880e11011390221a00100041900e5031b4438a1800a05008546002004050980f095cc61cb00b000313808090a000226001318091c0095b028404520ed38403938700839d2605846915a243b90115d883010603846765746888676f312e32342e39856c696e75780000005b240570f8b27fb860b256cac937e461138b0c95cd43c783efad7ae7c1bff57bf9c2366eaee6a8ffface7e809ea699b8e4f6bf5659fed22d72001fd1f7d3038bbe44036711d56140c2c9f5e1e91a6473e884bebe374dabf6b9f61d547e8ed93f908c449e18d6f65843f84c8404520ed0a015dd14d86358864bd7c4422cd74f2736031572dc7f6dc0acc5e04dd54c3bd6ff8404520ed2a0bfde5240efbf9dda1381cf5ead3039a1c6b55c5dae95cb044c23fc2c2611f379809fbce16268145ce40e6e8e7928b4a3719ff036f5814c5a22ebd4b15af108892e169598a3b849d0d069162550728367af38819a3ea79133cd3dff51ae58e8299100a0000000000000000000000000000000000000000000000000000000000000032088000000000000000080a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b4218080a00000000000000000000000000000000000000000000000000000000000000000a0e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855").to_vec()),
            ]
        ];
        for v in group {
            let headers = ETHHeaders {
                target: v[0].clone(),
                all: v.clone(),
            };
            let result = headers.verify_finalized();
            match result.unwrap_err() {
                Error::UnexpectedTooManyHeadersToFinalize(e1, e2) => {
                    assert_eq!(e1, headers.target.number, "block error");
                    assert_eq!(e2, headers.all.len(), "header size");
                }
                e => unreachable!("{:?}", e),
            }
        }
    }

    #[rstest]
    #[case::localnet(localnet())]
    fn test_error_verify_too_many_headers_to_seal(#[case] hp: Box<dyn Network>) {
        let v = vec![
            hp.epoch_header(),
            hp.epoch_header_plus_1(),
            hp.epoch_header_plus_2(),
            hp.epoch_header_plus_3(),
        ];
        let c_val = v.first().unwrap().clone().epoch.unwrap();
        let c_val = EitherEpoch::Untrusted(untrust(&c_val));
        let headers = ETHHeaders {
            target: v[0].clone(),
            all: v,
        };

        let p_val = Epoch::new(hp.previous_validators().into(), 1);
        let p_val = trust(&p_val);
        let result = headers.verify(&hp.network(), &c_val, &p_val);
        match result.unwrap_err() {
            Error::UnexpectedTooManyHeadersToFinalize(e1, e2) => {
                assert_eq!(e1, headers.target.number, "block error");
                assert_eq!(e2, headers.all.len(), "header size");
            }
            e => unreachable!("{:?}", e),
        }
    }

    #[rstest]
    #[case::localnet(localnet())]
    fn test_error_next_checkpoint_header_found_target_epoch(#[case] hp: Box<dyn Network>) {
        let f = |mut headers: ETHHeaders,
                 c_val: &EitherEpoch,
                 p_val: &TrustedEpoch,
                 include_limit: bool| {
            let next_epoch_checkpoint = headers.target.current_epoch_block_number().unwrap()
                + fork_spec_after_lorentz().epoch_length
                + c_val.checkpoint();
            loop {
                let last = headers.all.last().unwrap();
                let drift = u64::from(!include_limit);
                if last.number >= (next_epoch_checkpoint - drift) {
                    break;
                }
                let mut next = last.clone();
                next.number = last.number + 1;

                // dummy validator set
                if next.number % fork_spec_after_lorentz().epoch_length == 0 {
                    next.extra_data = hp.epoch_header().extra_data;
                    let (v, t) = get_validator_bytes_and_turn_length(&next.extra_data).unwrap();
                    next.epoch = Some(Epoch::new(v.into(), t));
                } else {
                    next.epoch = None
                }
                headers.all.push(next);
            }
            let result = headers.verify(&hp.network(), c_val, p_val).unwrap_err();
            if include_limit {
                match result {
                    Error::UnexpectedNextCheckpointHeader(e1, e2) => {
                        assert_eq!(e1, headers.target.number);
                        assert_eq!(e2, next_epoch_checkpoint);
                    }
                    err => unreachable!("err {:?}", err),
                };
            } else {
                match result {
                    Error::UnexpectedHeaderRelation(_, _, _, _, _, _) => {}
                    err => unreachable!("err {:?}", err),
                };
            }
        };
        let v = vec![
            hp.epoch_header(),
            hp.epoch_header_plus_1(),
            hp.epoch_header_plus_2(),
        ];
        let headers = ETHHeaders {
            target: v[0].clone(),
            all: v,
        };
        let p_val = Epoch::new(hp.previous_validators().into(), 1);
        let p_val = trust(&p_val);
        let c_val = hp.epoch_header().epoch.unwrap();
        let c_val = EitherEpoch::Untrusted(untrust(&c_val));
        f(headers.clone(), &c_val, &p_val, true);
        f(headers, &c_val, &p_val, false);
    }

    #[rstest]
    #[case::localnet(localnet())]
    fn test_error_next_next_checkpoint_header_found(#[case] hp: Box<dyn Network>) {
        let f = |mut headers: ETHHeaders,
                 c_val: &EitherEpoch,
                 p_val: &TrustedEpoch,
                 n_val_header: ETHHeader,
                 include_limit: bool| {
            let n_val = n_val_header.epoch.clone().unwrap();
            let next_next_epoch_checkpoint = headers.target.current_epoch_block_number().unwrap()
                + fork_spec_after_lorentz().epoch_length
                + fork_spec_after_lorentz().epoch_length
                + n_val.checkpoint();
            loop {
                let last = headers.all.last().unwrap();
                let drift = u64::from(!include_limit);
                if last.number >= next_next_epoch_checkpoint - drift {
                    break;
                }
                let mut next = last.clone();
                next.number = last.number + 1;
                if next.number % fork_spec_after_lorentz().epoch_length == 0 {
                    // set validator set
                    next.extra_data = n_val_header.extra_data.clone();
                    let (v, t) = get_validator_bytes_and_turn_length(&next.extra_data).unwrap();
                    next.epoch = Some(Epoch::new(v.into(), t));
                } else {
                    next.epoch = None
                }

                headers.all.push(next);
            }
            let result = headers.verify(&hp.network(), c_val, p_val).unwrap_err();
            if include_limit {
                match result {
                    Error::UnexpectedNextNextCheckpointHeader(e1, e2) => {
                        assert_eq!(e1, headers.target.number);
                        assert_eq!(e2, next_next_epoch_checkpoint);
                    }
                    err => unreachable!("err {:?}", err),
                }
            } else {
                match result {
                    Error::UnexpectedHeaderRelation(_, _, _, _, _, _) => {}
                    err => unreachable!("err {:?}", err),
                }
            }
        };
        let headers = hp.headers_after_checkpoint();
        let c_val = hp.epoch_header().epoch.unwrap();
        let c_val = EitherEpoch::Trusted(trust(&c_val));
        let p_val = empty();
        let p_val = trust(&p_val);
        let n_val_header = hp.epoch_header();
        f(headers.clone(), &c_val, &p_val, n_val_header.clone(), true);
        f(headers, &c_val, &p_val, n_val_header.clone(), false);

        let headers = hp.headers_before_checkpoint();
        let p_val = Epoch::new(hp.previous_validators().into(), 1);
        let p_val = trust(&p_val);
        let c_val = hp.epoch_header().epoch.unwrap();
        let c_val = EitherEpoch::Trusted(trust(&c_val));
        f(headers.clone(), &c_val, &p_val, n_val_header.clone(), true);
        f(headers, &c_val, &p_val, hp.epoch_header(), false);

        let headers = hp.headers_across_checkpoint();
        f(headers.clone(), &c_val, &p_val, n_val_header.clone(), true);
        f(headers, &c_val, &p_val, n_val_header, false);
    }

    #[rstest]
    #[case::localnet(localnet())]
    fn test_error_verify_header_size_missing_epoch_info(#[case] hp: Box<dyn Network>) {
        let previous_epoch = hp.previous_epoch_header().epoch.unwrap();
        let mut headers = hp.headers_after_checkpoint();

        // No epoch info in next epoch
        for _i in 0..1000 {
            let mut header = headers.all.last().unwrap().clone();
            header.number += 1;
            header.epoch = None;
            headers.all.push(header);
        }

        let epoch = &hp.epoch_header().epoch.unwrap();
        let epoch = TrustedEpoch::new(epoch);
        let epoch = EitherEpoch::Trusted(epoch);

        let current_epoch_block_number = headers.target.current_epoch_block_number().unwrap();
        let checkpoint = current_epoch_block_number + previous_epoch.checkpoint();

        let err = headers
            .verify_header_size(checkpoint, &epoch, current_epoch_block_number)
            .unwrap_err();
        match err {
            Error::MissingEpochInfo(e1) => {
                assert_eq!(e1, current_epoch_block_number + 500);
            }
            _ => unreachable!("err {:?}", err),
        }
    }

    #[rstest]
    #[case::localnet(localnet())]
    fn test_error_verify_header_size_unexpected_prev_epoch(#[case] hp: Box<dyn Network>) {
        let previous_epoch = hp.previous_epoch_header().epoch.unwrap();
        let mut headers = hp.headers_after_checkpoint();

        // Set invalid fork spec
        let invalid_prev_fork_spec = ForkSpec {
            height_or_timestamp: HeightOrTimestamp::Height(1499),
            epoch_length: 10,
            additional_header_item_count: 1,
            max_turn_length: 64,
            enable_header_msec: true,
            gas_limit_bound_divider: 256,
            k_ancestor_generation_depth: 1,
        };

        let invalid_current_fork_spec = ForkSpec {
            height_or_timestamp: HeightOrTimestamp::Height(1500),
            epoch_length: 500,
            additional_header_item_count: 1,
            max_turn_length: 64,
            enable_header_msec: true,
            gas_limit_bound_divider: 1024,
            k_ancestor_generation_depth: 1,
        };
        for _i in 0..1000 {
            let mut header = headers.all.last().unwrap().clone();
            header.number += 1;
            if header.number == 1500 {
                header.epoch = hp.epoch_header().epoch;
                header
                    .assign_fork_spec(&[
                        invalid_prev_fork_spec.clone(),
                        invalid_current_fork_spec.clone(),
                    ])
                    .unwrap();
            } else {
                header.epoch = None;
            }
            headers.all.push(header);
        }

        let epoch = &hp.epoch_header().epoch.unwrap();
        let epoch = TrustedEpoch::new(epoch);
        let epoch = EitherEpoch::Trusted(epoch);

        let current_epoch_block_number = headers.target.current_epoch_block_number().unwrap();
        let checkpoint = current_epoch_block_number + previous_epoch.checkpoint();

        let err = headers
            .verify_header_size(checkpoint, &epoch, current_epoch_block_number)
            .unwrap_err();
        match err {
            Error::UnexpectedPreviousEpochInCalculatingNextEpoch(e1, e2, e3) => {
                assert_eq!(e1, 1500);
                assert_eq!(e2, 1500 - invalid_prev_fork_spec.epoch_length);
                assert_eq!(e3, 1500 - invalid_current_fork_spec.epoch_length);
            }
            _ => unreachable!("err {:?}", err),
        }
    }

    #[rstest]
    #[case::localnet(localnet())]
    fn test_error_verify_header_size_invalid_number(#[case] hp: Box<dyn Network>) {
        let previous_epoch = hp.previous_epoch_header().epoch.unwrap();
        let mut headers = hp.headers_after_checkpoint();

        // Epoch info in non epoch
        for _i in 0..1000 {
            let mut header = headers.all.last().unwrap().clone();
            header.number += 1;
            header.epoch = hp.epoch_header().epoch;
            headers.all.push(header);
        }

        let epoch = &hp.epoch_header().epoch.unwrap();
        let epoch = TrustedEpoch::new(epoch);
        let epoch = EitherEpoch::Trusted(epoch);

        let current_epoch_block_number = headers.target.current_epoch_block_number().unwrap();
        let checkpoint = current_epoch_block_number + previous_epoch.checkpoint();

        let err = headers
            .verify_header_size(checkpoint, &epoch, current_epoch_block_number)
            .unwrap_err();
        match err {
            Error::UnexpectedEpochInfo(e1, e2) => {
                assert_eq!(
                    e1,
                    hp.headers_after_checkpoint().all.last().unwrap().number + 1
                );
                assert_eq!(e2, current_epoch_block_number);
            }
            _ => unreachable!("err {:?}", err),
        }
    }

    impl From<Vec<ETHHeader>> for ETHHeaders {
        fn from(value: Vec<ETHHeader>) -> Self {
            Self {
                target: value[0].clone(),
                all: value,
            }
        }
    }
}
