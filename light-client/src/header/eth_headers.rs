use alloc::vec::Vec;
use parlia_ibc_proto::ibc::lightclients::parlia::v1::EthHeader;

use crate::errors::Error;
use crate::errors::Error::MissingEpochInfoInEpochBlock;
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
        let current_epoch_block_number = self.target.current_epoch_block_number();
        let checkpoint = current_epoch_block_number + previous_epoch.checkpoint();

        let next_epoch_block_number = self.target.next_epoch_block_number();
        let next_checkpoint = next_epoch_block_number + current_epoch.checkpoint();

        let n_val = self.verify_header_size(
            self.target.next_next_epoch_block_number(),
            checkpoint,
            next_checkpoint,
            current_epoch,
        )?;

        // Ensure all the headers are successfully chained.
        self.verify_cascading_fields()?;

        // Ensure valid seals
        let p_val = previous_epoch.validators();
        for h in self.all.iter() {
            if h.number >= next_checkpoint {
                h.verify_seal(unwrap_n_val(h.number, &n_val)?, chain_id)?;
            } else if h.number >= checkpoint {
                h.verify_seal(current_epoch.epoch(), chain_id)?;
            } else {
                h.verify_seal(previous_epoch.epoch(), chain_id)?;
            }
        }

        // Ensure target is finalized
        let (child, grand_child) = self.verify_finalized()?;

        // Ensure BLS signature is collect
        // At the just checkpoint BLS signature uses previous validator set.
        let mut last_voters: Validators = Vec::new();
        for h in &[child, grand_child] {
            let vote = h.get_vote_attestation()?;
            last_voters = if h.number > next_checkpoint {
                vote.verify(h.number, unwrap_n_val(h.number, &n_val)?.validators())?
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
            next_checkpoint,
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
    /// Only one set of three consecutive valid headers must exist.
    /// This means that if [x, x+1, x+2] is valid then x+3 must not exist.
    fn verify_finalized(&self) -> Result<(&ETHHeader, &ETHHeader), Error> {
        if self.all.len() < 3 {
            return Err(Error::InvalidVerifyingHeaderLength(
                self.target.number,
                self.all.len(),
            ));
        }
        let mut last_error: Option<Error> = None;
        let headers = &self.all[..self.all.len() - 2];
        for (i, header) in headers.iter().enumerate() {
            let child = &self.all[i + 1];
            let grand_child = &self.all[i + 2];
            match verify_finalized(header, child, grand_child) {
                Err(e) => last_error = Some(e),
                Ok(()) => {
                    if i + 2 != self.all.len() - 1 {
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
        next_next_epoch_block_number: BlockNumber,
        checkpoint: u64,
        next_checkpoint: u64,
        current_epoch: &EitherEpoch,
    ) -> Result<Option<&Epoch>, Error> {
        let hs: Vec<&ETHHeader> = self.all.iter().filter(|h| h.number >= checkpoint).collect();
        match current_epoch {
            // ex) t=200 then  200 <= h < 411 (at least 1 honest c_val(200)' can be in p_val)
            Untrusted(_) => {
                // Ensure headers are before the next_checkpoint
                if hs.iter().any(|h| h.number >= next_checkpoint) {
                    return Err(Error::UnexpectedNextCheckpointHeader(
                        self.target.number,
                        next_checkpoint,
                    ));
                }
                Ok(None)
            }
            // ex) t=201 then 201 <= h < 611 (at least 1 honest n_val(400) can be in c_val(200))
            Trusted(_) => {
                // Get next_epoch if epoch after checkpoint ex) 400
                let next_epoch = match hs.iter().find(|h| h.is_epoch()) {
                    Some(h) => h
                        .epoch
                        .as_ref()
                        .ok_or_else(|| MissingEpochInfoInEpochBlock(h.number))?,
                    None => return Ok(None),
                };

                // Finish if no headers over next checkpoint were found
                let hs: Vec<&&ETHHeader> =
                    hs.iter().filter(|h| h.number >= next_checkpoint).collect();
                if hs.is_empty() {
                    return Ok(None);
                }

                let next_next_checkpoint = next_next_epoch_block_number + next_epoch.checkpoint();

                // Ensure headers are before the next_next_checkpoint
                if hs.iter().any(|h| h.number >= next_next_checkpoint) {
                    return Err(Error::UnexpectedNextNextCheckpointHeader(
                        self.target.number,
                        next_next_checkpoint,
                    ));
                }
                Ok(Some(next_epoch))
            }
        }
    }
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

fn verify_finalized(
    header: &ETHHeader,
    child: &ETHHeader,
    grand_child: &ETHHeader,
) -> Result<(), Error> {
    child.verify_target_attestation(header)?;
    let grand_child_vote = grand_child.verify_vote_attestation(child)?;
    if grand_child_vote.data.source_number != header.number
        || grand_child_vote.data.source_hash != header.hash
    {
        return Err(Error::UnexpectedSourceInGrandChild(
            header.number,
            grand_child_vote.data.source_number,
            header.hash,
            grand_child_vote.data.source_hash,
        ));
    }
    Ok(())
}

fn unwrap_n_val<'a>(n: BlockNumber, n_val: &'a Option<&'a Epoch>) -> Result<&'a Epoch, Error> {
    n_val.ok_or_else(|| Error::MissingNextValidatorSet(n))
}

fn verify_voters(
    voters: &Validators,
    h: &ETHHeader,
    next_checkpoint: BlockNumber,
    checkpoint: BlockNumber,
    current_epoch: &EitherEpoch,
    previous_epoch: &TrustedEpoch,
) -> Result<(), Error> {
    if h.number > next_checkpoint {
        match current_epoch {
            Trusted(e) => e.verify_untrusted_voters(voters)?,
            _ => {
                return Err(Error::UnexpectedUntrustedValidators(
                    h.number,
                    next_checkpoint,
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

    use crate::header::eth_header::{
        get_validator_bytes_and_turn_length, ETHHeader,
    };
    use crate::header::eth_headers::{verify_voters, ETHHeaders};

    use crate::fixture::*;
    use crate::header::epoch::{EitherEpoch, Epoch, TrustedEpoch, UntrustedEpoch};

    use crate::misc::Validators;
    use hex_literal::hex;

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
            411,
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
            411,
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
            411,
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
            411,
            211,
            &EitherEpoch::Untrusted(UntrustedEpoch::new(&c_epoch)),
            &pt_epoch,
        )
        .unwrap_err();
        verify_voters(
            &vec![vec![0]],
            &h,
            411,
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
            411,
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
            let next_epoch_checkpoint =
                headers.target.next_epoch_block_number() + c_val.checkpoint();
            loop {
                let last = headers.all.last().unwrap();
                let drift = u64::from(!include_limit);
                if last.number >= (next_epoch_checkpoint - drift) {
                    break;
                }
                let mut next = last.clone();
                next.number = last.number + 1;
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
            let next_next_epoch_checkpoint =
                headers.target.next_next_epoch_block_number() + n_val.checkpoint();
            loop {
                let last = headers.all.last().unwrap();
                let drift = u64::from(!include_limit);
                if last.number >= next_next_epoch_checkpoint - drift {
                    break;
                }
                let mut next = last.clone();
                next.number = last.number + 1;
                if next.is_epoch() {
                    // set n_val
                    next.extra_data = n_val_header.extra_data.clone();
                    let (validators, turn_length) =
                        get_validator_bytes_and_turn_length(&next.extra_data).unwrap();
                    next.epoch = Some(Epoch::new(validators.into(), turn_length));
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

    impl From<Vec<ETHHeader>> for ETHHeaders {
        fn from(value: Vec<ETHHeader>) -> Self {
            Self {
                target: value[0].clone(),
                all: value,
            }
        }
    }
}
