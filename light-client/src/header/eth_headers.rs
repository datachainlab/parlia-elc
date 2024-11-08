use alloc::vec::Vec;

use parlia_ibc_proto::ibc::lightclients::parlia::v1::EthHeader;

use crate::errors::Error;
use crate::errors::Error::MissingEpochInfoInEpochBlock;
use crate::header::epoch::EitherEpoch::{Trusted, Untrusted};
use crate::header::epoch::{EitherEpoch, Epoch, TrustedEpoch, UntrustedEpoch};

use crate::misc::{BlockNumber, ChainId};

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
        current_epoch: &EitherEpoch,
        previous_epoch: &TrustedEpoch,
    ) -> Result<(), Error> {
        // Ensure the header after the next or next checkpoint must not exist.
        let epoch = self.target.number / BLOCKS_PER_EPOCH;
        let checkpoint = epoch * BLOCKS_PER_EPOCH + previous_epoch.checkpoint();
        let next_checkpoint = (epoch + 1) * BLOCKS_PER_EPOCH + current_epoch.checkpoint();
        let (c_val, n_val) = self.verify_header_size(
            epoch,
            checkpoint,
            next_checkpoint,
            previous_epoch,
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
                h.verify_seal(unwrap_c_val(h.number, &c_val)?, chain_id)?;
            } else {
                h.verify_seal(previous_epoch.epoch(), chain_id)?;
            }
        }

        // Ensure target is finalized
        let (child, grand_child) = self.verify_finalized()?;

        // Ensure BLS signature is collect
        // At the just checkpoint BLS signature uses previous validator set.
        for h in &[child, grand_child] {
            let vote = h.get_vote_attestation()?;
            if h.number > next_checkpoint {
                let voted_vals =
                    vote.verify(h.number, unwrap_n_val(h.number, &n_val)?.validators())?;
                //TODO validate voted_vals contain 1/3 of trusted
            } else if h.number > checkpoint {
                let voted_vals =
                    vote.verify(h.number, unwrap_c_val(h.number, &c_val)?.validators())?;
                if let Untrusted(_) = current_epoch {
                    //TODO validate voted_vals contain 1/3 of trusted
                }
            } else {
                vote.verify(h.number, p_val)?;
            }
        }
        Ok(())
    }

    fn verify_cascading_fields(&self) -> Result<(), Error> {
        for (i, header) in self.all.iter().enumerate() {
            if i < self.all.len() - 1 {
                let child = &self.all[i + 1];
                child.verify_cascading_fields(header)?;
            }
        }
        Ok(())
    }

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

    fn verify_header_size<'a, 'b>(
        &'b self,
        epoch: u64,
        checkpoint: u64,
        next_checkpoint: u64,
        previous_epoch: &TrustedEpoch,
        current_epoch: &'a EitherEpoch,
    ) -> Result<(Option<&'a Epoch>, Option<&'b Epoch>), Error> {
        let hs: Vec<&ETHHeader> = self.all.iter().filter(|h| h.number >= checkpoint).collect();
        match current_epoch {
            // ex) t=200 then  200 <= h < 411 (c_val(200) can be borrowed by p_val)
            Untrusted(untrusted) => {
                // Ensure headers are before the next_checkpoint
                if hs.iter().any(|h| h.number >= next_checkpoint) {
                    return Err(Error::UnexpectedNextCheckpointHeader(
                        self.target.number,
                        next_checkpoint,
                    ));
                }

                // Ensure c_val is validated by trusted p_val when the checkpoint header is found
                if hs.is_empty() {
                    Ok((None, None))
                } else {
                    Ok((Some(untrusted.borrow()), None))
                }
            }
            // ex) t=201 then 201 <= h < 611 (n_val(400) can be borrowed by c_val(200))
            Trusted(trusted) => {
                // Get next_epoch if epoch after checkpoint ex) 400
                let next_epoch = match hs.iter().find(|h| h.is_epoch()) {
                    Some(h) => h
                        .epoch
                        .as_ref()
                        .ok_or_else(|| MissingEpochInfoInEpochBlock(h.number))?,
                    None => return Ok((Some(trusted.epoch()), None)),
                };

                // Finish if no headers over next checkpoint were found
                let hs: Vec<&&ETHHeader> =
                    hs.iter().filter(|h| h.number >= next_checkpoint).collect();
                if hs.is_empty() {
                    return Ok((Some(trusted.epoch()), None));
                }

                // Ensure n_val(400) can be borrowed by c_val(200)
                let next_next_checkpoint = (epoch + 2) * BLOCKS_PER_EPOCH + next_epoch.checkpoint();

                // Ensure headers are before the next_next_checkpoint
                if hs.iter().any(|h| h.number >= next_next_checkpoint) {
                    return Err(Error::UnexpectedNextNextCheckpointHeader(
                        self.target.number,
                        next_next_checkpoint,
                    ));
                }
                Ok((Some(trusted.epoch()), Some(next_epoch)))
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

fn unwrap_c_val<'a>(n: BlockNumber, c_val: &'a Option<&'a Epoch>) -> Result<&'a Epoch, Error> {
    c_val.ok_or_else(|| Error::MissingCurrentValidatorSet(n))
}

#[cfg(test)]
mod test {
    use crate::errors::Error;

    use crate::header::constant::BLOCKS_PER_EPOCH;
    use crate::header::eth_header::{get_validator_bytes_and_tern_term, ETHHeader};
    use crate::header::eth_headers::ETHHeaders;

    use crate::fixture::*;
    use crate::header::epoch::{EitherEpoch, Epoch, TrustedEpoch, UntrustedEpoch};
    use crate::header::Header;
    use crate::misc::{ChainId, Validators};
    use hex_literal::hex;
    use light_client::types::Any;
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
        let header= hex!("0a222f6962632e6c69676874636c69656e74732e7061726c69612e76312e48656164657212ed200ae9080ae608f90463a0794978ac680964fb5ada43366fa4d33a490c93ec6893304ddee68a59f2cafabaa01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d4934794d9a13701eafb76870cb220843b8c6476824bfa15a0558eacf75665a00d1eef186ffc4f79985db5e5fcb1aa24892df5d600ae869313a09f0bb93d54df1fcbfd84d4173496de9cff0f403319bbbaf15791ccde774b73d8a03cd1ebc99cd975182c58de47be968c97658cff4c465e20654185f408a851403cb9010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000028211308402625a008229a884669fb2e3b90223d98301040c846765746889676f312e32312e3132856c696e75780000d24ec9e8048fdaaa7e6631e438625ca25c857a3727ea28e565b876532dd999985816f1df35a5d6359177f1d49bfb3c20e25d6760197246ad0b6b8efb77ad316a0f31360c3733cabd6ca7876ea32e7a748c697d01345145485561305b24b6c305acd27ad7aff76367fd3a1dfe8da19afba969c8464f37a29e60923c3a85cfacbdef18daa782d5724f13d415f98cb2e42bc54d19116d2348ac83461e2e0915d508ad976963272de9af796035a7c68771d03c92709aa174ce1e8723cb6d7d1f6d960790e83c59e1f9867721e6302520a30a44e04db2de85453e0936b441c339a26d10cfa71b50b359d8b4d1e5fd24f5a99712ed2e5a8f7180621828a1ae567b86ff60792ff27f2fd62d410aa8b9b858316495867f833309f8ae0fb860834538868d2c79371ead2f10fc7229fd3b3aaf1d7d8607fd7e1d2efba7df1008c105fdab4ad8029f86cfde1e3aa7dd24194fcf07502bb6c281fc3cbc08ad8cb467de57cbfd1bb93fabe72f77ece8f991a2b7a4d7fb301d54547c6cb4b612d06ff84882112ea042dfe9761fb9a677b088a868f237a171d511bea581f643844a1c98267902391882112fa0794978ac680964fb5ada43366fa4d33a490c93ec6893304ddee68a59f2cafaba80321f35c8454a2691a2efff6894cae6277ea06390978294fe0d10fe03f432fd07440d802ca0858a2d6138230b37d1a9148a3d76fbe8492854e637c9aad7494e3401a0000000000000000000000000000000000000000000000000000000000000000088000000000000000080a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b4218080a000000000000000000000000000000000000000000000000000000000000000000ad5060ad206f9034fa09696424e13500cdc742b049c6459c0bc4cb357eab5d9fb48a2e79787c8897a1fa01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d4934794d9a13701eafb76870cb220843b8c6476824bfa15a0558eacf75665a00d1eef186ffc4f79985db5e5fcb1aa24892df5d600ae869313a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421b9010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000028211318402625a008084669fb2e6b90111d98301040c846765746889676f312e32312e3132856c696e75780000d24ec9e8f8ae0fb860b6de9ffe941751cd11463bbd4bde69d3bc2b79868f669f9e2c4c327f036e6d558b013469a91670607dd88d63dc50b95d00719e118a17e5b72418b6ae4bef7aebbcdaa44b79f8c0677ac32c71312d84db44e6e9216bd84fb97c7d0701a4a03431f84882112fa0794978ac680964fb5ada43366fa4d33a490c93ec6893304ddee68a59f2cafaba821130a09696424e13500cdc742b049c6459c0bc4cb357eab5d9fb48a2e79787c8897a1f80e5619874ecb4463f8d86981d939ddb4d0eaa151c6080c7067788e06699789d0a415e921b8824e8adc7907e5bbccec9373b22c7fe8a48527e9348aa957871b63300a0000000000000000000000000000000000000000000000000000000000000000088000000000000000080a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b4218080a000000000000000000000000000000000000000000000000000000000000000000ad5060ad206f9034fa0e3aa9bc64f82ccd7e70ec415d73263d9da9f3bb44b78bed500033379df9be8aaa01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d4934794d9a13701eafb76870cb220843b8c6476824bfa15a0558eacf75665a00d1eef186ffc4f79985db5e5fcb1aa24892df5d600ae869313a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421b9010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000028211328402625a008084669fb2e9b90111d98301040c846765746889676f312e32312e3132856c696e75780000d24ec9e8f8ae0fb86095a056c77bdeb59da26e665d69e75cc5667cd43df693a55f20f5f248483a3ce10cdd996b29c7fd6ba3f9e31cb4ac089c0b5bc13e77d83f17096d88f280b8d47ffd8b58b66bd760d0ccd4d26e0c2a7bb3ec168a06a815cfbdde9a2e18c32ac74ef848821130a09696424e13500cdc742b049c6459c0bc4cb357eab5d9fb48a2e79787c8897a1f821131a0e3aa9bc64f82ccd7e70ec415d73263d9da9f3bb44b78bed500033379df9be8aa80c04c6f70fa142c7486f7bed7e29a247f1203d58c7481c9aefef1193e6404112e32486f8d4dc8c7c558ae0b1bf860f6e05d425b7726ba7a4e2dac6e3e3eb83d3d00a0000000000000000000000000000000000000000000000000000000000000000088000000000000000080a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b4218080a00000000000000000000000000000000000000000000000000000000000000000120310e8201a9506f90312f901f1a094e7dcd05ddcc3923085b451330f3aa5ce5a628d6685506d99cb09b3aef0e11ea065b83aa9b59125f9b090432f556c6ff947b5708eb11ca5ea26342392860be00aa0b116ef7733a93eed23f018027c116e60436a228a9f9173bb9b0c40eb71216da6a064c0a17f12a753c3fc032723866ac267ad8b7e05e7aa2e75bb680175d936617580a01a41c640130c53b3c90b1b5c691ed467218cee97aade5aac9306e72865851e27a004371241b9d6f35e1f361f2109d19a9192a9c0c749b2bd15fcb131a1a6ce5e3ba00577e3e2c4649c5a23cbdabe0bbfed7cdf6e85c136d84d58127cdec86264ad6ea070c0f30031f40c8017dbfc2ef008e6a3aae2e3105a654e0c5439b6104752882ea08f81903ec8515875682785142e1f92bdeaf65fccd5d0cf78b1ff2905a07e5883a03052420ba2d24a04d3f830584d3dbd6907b6d82bab84ddd806d03470e2c9d51ca06fb1a1498c2c8f93944a4f672ff4e982480ad181c835c0d8078159c517c7977aa013a426820f7b7249edc97cc5c002e653ac84b437f3ac12ac940c3d4b09e09827a09fbc54eac488b27315b09a1afa8d12f168e4c4cb5aea2d9a6ab5e7266da2f7e8a077c5e5cd5bd518bc509ee5e71790f1e42e492e23875b097e565cff8e809e7c8aa0a1575ef06513a19d2a28390e83958d2a3ffe166b530255b0fb5559d33409914d80f8b18080a0dc77b6ae50b675036e77b31973c79ec60c28c0d2c57b03ad99c2acfff2f0cd4e80a063a8a6161448a60a47ddbafa00899bed224e9f80072b35a1dbc64a82e85cd9b5a05e0f116451aaa1baab3f3abff2793c8318050eeed6bf62d464d343a11d86eb2880808080808080a0abbb1987d09a71106f586030d1ab913bae0008e2a7dec0d08f2d60cd30fb2ac8a096c706907bfc6472dd88315cb8e21ee6f60a661cd8050065e2ba387023ee96858080f869a020b1e2b1f9852058ee0aaadca3c963f77f6483a1a51c644d79386bcada360583b846f8440180a0e39304f0ec064a98e4b0a96432dfb0a9e4c7fd0f26a6bbcf9c75bff68c51a7a9a0b3d632130dcb5cb583b47ec0623e59ca3703e6e2564f144272b597f3e3511ba822448fdaaa7e6631e438625ca25c857a3727ea28e565b876532dd999985816f1df35a5d6359177f1d49bfb3c20e25d6760197246ad0b6b8efb77ad316a0f31360c3733cabd6c2244a7876ea32e7a748c697d01345145485561305b24b6c305acd27ad7aff76367fd3a1dfe8da19afba969c8464f37a29e60923c3a85cfacbdef18daa782d5724f13d415f98c2244b2e42bc54d19116d2348ac83461e2e0915d508ad976963272de9af796035a7c68771d03c92709aa174ce1e8723cb6d7d1f6d960790e83c59e1f9867721e6302520a30a442244e04db2de85453e0936b441c339a26d10cfa71b50b359d8b4d1e5fd24f5a99712ed2e5a8f7180621828a1ae567b86ff60792ff27f2fd62d410aa8b9b858316495867f83332a448fdaaa7e6631e438625ca25c857a3727ea28e565b876532dd999985816f1df35a5d6359177f1d49bfb3c20e25d6760197246ad0b6b8efb77ad316a0f31360c3733cabd6c2a44b2e42bc54d19116d2348ac83461e2e0915d508ad976963272de9af796035a7c68771d03c92709aa174ce1e8723cb6d7d1f6d960790e83c59e1f9867721e6302520a30a442a44d9a13701eafb76870cb220843b8c6476824bfa15b9ebdc1d1a70721d7f9c57622e0a5d1175df1e09672ab1e8909bf9a9433592107024bd8a3ad47fbbdca199ede96c50d22a44e04db2de85453e0936b441c339a26d10cfa71b50b359d8b4d1e5fd24f5a99712ed2e5a8f7180621828a1ae567b86ff60792ff27f2fd62d410aa8b9b858316495867f833330093808").to_vec();
        let any: Any = header.try_into().unwrap();
        let header = Header::try_from(any).unwrap();
        header.headers.verify_finalized().unwrap();
    }

    #[test]
    fn test_error_verify_finalized_no_finalized_header() {
        let header= hex!("0a222f6962632e6c69676874636c69656e74732e7061726c69612e76312e48656164657212ed200ae9080ae608f90463a0794978ac680964fb5ada43366fa4d33a490c93ec6893304ddee68a59f2cafabaa01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d4934794d9a13701eafb76870cb220843b8c6476824bfa15a0558eacf75665a00d1eef186ffc4f79985db5e5fcb1aa24892df5d600ae869313a09f0bb93d54df1fcbfd84d4173496de9cff0f403319bbbaf15791ccde774b73d8a03cd1ebc99cd975182c58de47be968c97658cff4c465e20654185f408a851403cb9010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000028211308402625a008229a884669fb2e3b90223d98301040c846765746889676f312e32312e3132856c696e75780000d24ec9e8048fdaaa7e6631e438625ca25c857a3727ea28e565b876532dd999985816f1df35a5d6359177f1d49bfb3c20e25d6760197246ad0b6b8efb77ad316a0f31360c3733cabd6ca7876ea32e7a748c697d01345145485561305b24b6c305acd27ad7aff76367fd3a1dfe8da19afba969c8464f37a29e60923c3a85cfacbdef18daa782d5724f13d415f98cb2e42bc54d19116d2348ac83461e2e0915d508ad976963272de9af796035a7c68771d03c92709aa174ce1e8723cb6d7d1f6d960790e83c59e1f9867721e6302520a30a44e04db2de85453e0936b441c339a26d10cfa71b50b359d8b4d1e5fd24f5a99712ed2e5a8f7180621828a1ae567b86ff60792ff27f2fd62d410aa8b9b858316495867f833309f8ae0fb860834538868d2c79371ead2f10fc7229fd3b3aaf1d7d8607fd7e1d2efba7df1008c105fdab4ad8029f86cfde1e3aa7dd24194fcf07502bb6c281fc3cbc08ad8cb467de57cbfd1bb93fabe72f77ece8f991a2b7a4d7fb301d54547c6cb4b612d06ff84882112ea042dfe9761fb9a677b088a868f237a171d511bea581f643844a1c98267902391882112fa0794978ac680964fb5ada43366fa4d33a490c93ec6893304ddee68a59f2cafaba80321f35c8454a2691a2efff6894cae6277ea06390978294fe0d10fe03f432fd07440d802ca0858a2d6138230b37d1a9148a3d76fbe8492854e637c9aad7494e3401a0000000000000000000000000000000000000000000000000000000000000000088000000000000000080a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b4218080a000000000000000000000000000000000000000000000000000000000000000000ad5060ad206f9034fa09696424e13500cdc742b049c6459c0bc4cb357eab5d9fb48a2e79787c8897a1fa01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d4934794d9a13701eafb76870cb220843b8c6476824bfa15a0558eacf75665a00d1eef186ffc4f79985db5e5fcb1aa24892df5d600ae869313a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421b9010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000028211318402625a008084669fb2e6b90111d98301040c846765746889676f312e32312e3132856c696e75780000d24ec9e8f8ae0fb860b6de9ffe941751cd11463bbd4bde69d3bc2b79868f669f9e2c4c327f036e6d558b013469a91670607dd88d63dc50b95d00719e118a17e5b72418b6ae4bef7aebbcdaa44b79f8c0677ac32c71312d84db44e6e9216bd84fb97c7d0701a4a03431f84882112fa0794978ac680964fb5ada43366fa4d33a490c93ec6893304ddee68a59f2cafaba821130a09696424e13500cdc742b049c6459c0bc4cb357eab5d9fb48a2e79787c8897a1f80e5619874ecb4463f8d86981d939ddb4d0eaa151c6080c7067788e06699789d0a415e921b8824e8adc7907e5bbccec9373b22c7fe8a48527e9348aa957871b63300a0000000000000000000000000000000000000000000000000000000000000000088000000000000000080a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b4218080a000000000000000000000000000000000000000000000000000000000000000000ad5060ad206f9034fa0e3aa9bc64f82ccd7e70ec415d73263d9da9f3bb44b78bed500033379df9be8aaa01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d4934794d9a13701eafb76870cb220843b8c6476824bfa15a0558eacf75665a00d1eef186ffc4f79985db5e5fcb1aa24892df5d600ae869313a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421b9010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000028211328402625a008084669fb2e9b90111d98301040c846765746889676f312e32312e3132856c696e75780000d24ec9e8f8ae0fb86095a056c77bdeb59da26e665d69e75cc5667cd43df693a55f20f5f248483a3ce10cdd996b29c7fd6ba3f9e31cb4ac089c0b5bc13e77d83f17096d88f280b8d47ffd8b58b66bd760d0ccd4d26e0c2a7bb3ec168a06a815cfbdde9a2e18c32ac74ef848821130a09696424e13500cdc742b049c6459c0bc4cb357eab5d9fb48a2e79787c8897a1f821131a0e3aa9bc64f82ccd7e70ec415d73263d9da9f3bb44b78bed500033379df9be8aa80c04c6f70fa142c7486f7bed7e29a247f1203d58c7481c9aefef1193e6404112e32486f8d4dc8c7c558ae0b1bf860f6e05d425b7726ba7a4e2dac6e3e3eb83d3d00a0000000000000000000000000000000000000000000000000000000000000000088000000000000000080a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b4218080a00000000000000000000000000000000000000000000000000000000000000000120310e8201a9506f90312f901f1a094e7dcd05ddcc3923085b451330f3aa5ce5a628d6685506d99cb09b3aef0e11ea065b83aa9b59125f9b090432f556c6ff947b5708eb11ca5ea26342392860be00aa0b116ef7733a93eed23f018027c116e60436a228a9f9173bb9b0c40eb71216da6a064c0a17f12a753c3fc032723866ac267ad8b7e05e7aa2e75bb680175d936617580a01a41c640130c53b3c90b1b5c691ed467218cee97aade5aac9306e72865851e27a004371241b9d6f35e1f361f2109d19a9192a9c0c749b2bd15fcb131a1a6ce5e3ba00577e3e2c4649c5a23cbdabe0bbfed7cdf6e85c136d84d58127cdec86264ad6ea070c0f30031f40c8017dbfc2ef008e6a3aae2e3105a654e0c5439b6104752882ea08f81903ec8515875682785142e1f92bdeaf65fccd5d0cf78b1ff2905a07e5883a03052420ba2d24a04d3f830584d3dbd6907b6d82bab84ddd806d03470e2c9d51ca06fb1a1498c2c8f93944a4f672ff4e982480ad181c835c0d8078159c517c7977aa013a426820f7b7249edc97cc5c002e653ac84b437f3ac12ac940c3d4b09e09827a09fbc54eac488b27315b09a1afa8d12f168e4c4cb5aea2d9a6ab5e7266da2f7e8a077c5e5cd5bd518bc509ee5e71790f1e42e492e23875b097e565cff8e809e7c8aa0a1575ef06513a19d2a28390e83958d2a3ffe166b530255b0fb5559d33409914d80f8b18080a0dc77b6ae50b675036e77b31973c79ec60c28c0d2c57b03ad99c2acfff2f0cd4e80a063a8a6161448a60a47ddbafa00899bed224e9f80072b35a1dbc64a82e85cd9b5a05e0f116451aaa1baab3f3abff2793c8318050eeed6bf62d464d343a11d86eb2880808080808080a0abbb1987d09a71106f586030d1ab913bae0008e2a7dec0d08f2d60cd30fb2ac8a096c706907bfc6472dd88315cb8e21ee6f60a661cd8050065e2ba387023ee96858080f869a020b1e2b1f9852058ee0aaadca3c963f77f6483a1a51c644d79386bcada360583b846f8440180a0e39304f0ec064a98e4b0a96432dfb0a9e4c7fd0f26a6bbcf9c75bff68c51a7a9a0b3d632130dcb5cb583b47ec0623e59ca3703e6e2564f144272b597f3e3511ba822448fdaaa7e6631e438625ca25c857a3727ea28e565b876532dd999985816f1df35a5d6359177f1d49bfb3c20e25d6760197246ad0b6b8efb77ad316a0f31360c3733cabd6c2244a7876ea32e7a748c697d01345145485561305b24b6c305acd27ad7aff76367fd3a1dfe8da19afba969c8464f37a29e60923c3a85cfacbdef18daa782d5724f13d415f98c2244b2e42bc54d19116d2348ac83461e2e0915d508ad976963272de9af796035a7c68771d03c92709aa174ce1e8723cb6d7d1f6d960790e83c59e1f9867721e6302520a30a442244e04db2de85453e0936b441c339a26d10cfa71b50b359d8b4d1e5fd24f5a99712ed2e5a8f7180621828a1ae567b86ff60792ff27f2fd62d410aa8b9b858316495867f83332a448fdaaa7e6631e438625ca25c857a3727ea28e565b876532dd999985816f1df35a5d6359177f1d49bfb3c20e25d6760197246ad0b6b8efb77ad316a0f31360c3733cabd6c2a44b2e42bc54d19116d2348ac83461e2e0915d508ad976963272de9af796035a7c68771d03c92709aa174ce1e8723cb6d7d1f6d960790e83c59e1f9867721e6302520a30a442a44d9a13701eafb76870cb220843b8c6476824bfa15b9ebdc1d1a70721d7f9c57622e0a5d1175df1e09672ab1e8909bf9a9433592107024bd8a3ad47fbbdca199ede96c50d22a44e04db2de85453e0936b441c339a26d10cfa71b50b359d8b4d1e5fd24f5a99712ed2e5a8f7180621828a1ae567b86ff60792ff27f2fd62d410aa8b9b858316495867f833330093808").to_vec();
        let any: Any = header.try_into().unwrap();
        let mut header = Header::try_from(any).unwrap();
        header.headers.all[1].extra_data = vec![];
        let result = header.headers.verify_finalized();
        match result.unwrap_err() {
            Error::UnexpectedVoteRelation(e1, e2, err) => {
                assert_eq!(e1, header.headers.target.number, "block error");
                assert_eq!(e2, header.headers.all.len(), "header size");
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
            let epoch = headers.target.number / BLOCKS_PER_EPOCH;
            let next_epoch_checkpoint = (epoch + 1) * BLOCKS_PER_EPOCH + c_val.checkpoint();
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
            let epoch = headers.target.number / BLOCKS_PER_EPOCH;
            let next_next_epoch_checkpoint = (epoch + 2) * BLOCKS_PER_EPOCH + n_val.checkpoint();
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
                        get_validator_bytes_and_tern_term(&next.extra_data).unwrap();
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
