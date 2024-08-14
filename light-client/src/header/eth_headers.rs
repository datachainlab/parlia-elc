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
                vote.verify(h.number, unwrap_n_val(h.number, &n_val)?.validators())?;
            } else if h.number > checkpoint {
                vote.verify(h.number, unwrap_c_val(h.number, &c_val)?.validators())?;
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
                    Ok((Some(untrusted.try_borrow(previous_epoch)?), None))
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
                UntrustedEpoch::new(next_epoch).try_borrow(trusted)?;

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
    use crate::misc::Validators;
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
