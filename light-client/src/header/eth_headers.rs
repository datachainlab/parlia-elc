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
    use crate::header::Header;
    use crate::misc::ChainId;
    use hex_literal::hex;
    use lcp_types::Any;

    #[test]
    fn test_success_verify_from_testnet_after_luban() {
        let header_bytes = hex!("0a222f6962632e6c69676874636c69656e74732e7061726c69612e76312e48656164657212f21d0af7090af409f904f1a031cc31dc48e5e0bd80817fd932977e81b93914c2c5b6ab615c2be78bdeee3edba01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d493479447788386d0ed6c748e03a53160b4b30ed3748cc5a0d37497aaea0b3f8b7d25859c3c4187acc83e7ad1b837cbb61299051da7c1a969a075040f4cc734ffaa9a14e81aff58b75ccdfc1f1f05a1751218c482ddc11f055ea0e8dc2b081d45c2b5743cb7832f141b1a147010dae22b511a25bee2002393e3dcb90100012000000000480000500042820000080200600002020800800004080200101200005000000000000000100000040080002000000000000002001000002e0000004000000015a0804000001a0008002024100000022400001000010080040800000c002802020000244000c0100008000a0800c0000019800201001000021000820000042000000000000000400000001000046128110008000102c00002002002000400400022200000000002000000000000080000104000800202000000000090101a002008000002028008020000118000800400001000904082000062001210000010000006411003042000011000008000280000490400204200000000028401fa10588402f7f591831ec2d98464fb55abb902f2d88301020a846765746888676f312e31392e39856c696e7578000000dc55905c071284214b9b9c85549ab3d2b972df0deef66ac2c98e82934ca974fdcd97f3309de967d3c9c43fa711a8d673af5d75465844bf8969c8d1948d903748ac7b8b1720fa64e50c35552c16704d214347f29fa77f77da6d75d7c752b742ad4855bae330426b823e742da31f816cc83bc16d69a9134be0cfb4a1d17ec34f1b5b32d5c20440b8536b1e88f0f247788386d0ed6c748e03a53160b4b30ed3748cc5000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000980a75ecd1309ea12fa2ed87a8744fbfc9b863d589037a9ace3b590165ea1c0c5ac72bf600b7c88c1e435f41932c1132aae1bfa0bb68e46b96ccb12c3415e4d82af717d8a2959d3f95eae5dc7d70144ce1b73b403b7eb6e0b973c2d38487e58fd6e145491b110080fb14ac915a0411fc78f19e09a399ddee0d20c63a75d8f930f1694544ad2dc01bb71b214cb885500844365e95cd9942c7276e7fd8a2750ec6dded3dcdc2f351782310b0eadc077db59abca0f0cd26776e2e7acb9f3bce40b1fa5221fd1561226c6263cc5ff474cf03cceff28abc65c9cbae594f725c80e12d96c9b86c3400e529bfe184056e257c07940bb664636f689e8d2027c834681f8f878b73445261034e946bb2d901b4b878f8b27bb860923a27ea73f20c73fc672cc2004a9131cbfe634c671e53d799f68e9ec4b7602ae98f51b3c0dc9a7485df7080c7df26f00a6e192bdb6d0ce94ab23ae4727013bdfeff882b9ee5a3b96f9aaf6b901a914e225dac1a8c9b889c03bdc74f7ac056bef84c8401fa1056a014c2d898033ae031070c90827f0f1bd2d582205b69f9d15c972abea3f22399c98401fa1057a031cc31dc48e5e0bd80817fd932977e81b93914c2c5b6ab615c2be78bdeee3edb80e6bc648d3918d7196795cf450a9d7586215548ed1041b952b288cfb3552a98b258089767dce7ae19a43a96a2323402151dea908ace7a56fa69ea004d19eb684300a00000000000000000000000000000000000000000000000000000000000000000880000000000000000800a9a060a9706f90314a07b3e85509d533664e8467684de404663c53b786cb62fd31b878eb1b0c4064151a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d4934794980a75ecd1309ea12fa2ed87a8744fbfc9b863d5a0e5be742d069281a7d98e67426fb52a63582d01327b1b748c7e3fbed910c28370a0165260f804a0921b6a0656f10c078c4cd96dce83d8cd881a4e89faa67549152ea06c2d779dbd690b8fbc012d0d3bdf015f52b53bb463f9cdc446a867e705e7b956b901000120000000804000001000428000000800000020000010800000000000800000000050000000000000000000000440800000000000000000100110000002000000004000000401044000000a00000020241000000000000000400000c0040000002800200202000000500000000008010e0801c0000000000001001000000000020000000000000000000000000000001000048100000008020120400000202000000000100080000000000040000000000000000000004000800002000000000000000a000800000000000008020000110000000000001000104002000060600000100200001004010000002000010000008000281080510400000000000000028401fa10598402faed85830fa47c8464fb55aeb90115d883010209846765746888676f312e31392e38856c696e7578000000dc55905cf8b27bb86085584b5b05264dcf974b88ff2c49e12baefb8838fe255c99c43448985620754a00425d24c60caf5c2d4ac23c796fb9f8075cd19491eb543066b655c7ac429e08eb46b2f4d28ca530770acd49c3639af6a38ff5a58b81559243455af393ef7bb3f84c8401fa1057a031cc31dc48e5e0bd80817fd932977e81b93914c2c5b6ab615c2be78bdeee3edb8401fa1058a07b3e85509d533664e8467684de404663c53b786cb62fd31b878eb1b0c4064151808c86585a754e5a8af5412cd686bfff8016c862666a6958076950f4ee4498b88649b4b230eed6640076ac06301d64f65d7c6a70611780a2b46e1142f1da7c069501a00000000000000000000000000000000000000000000000000000000000000000880000000000000000800a9a060a9706f90314a04537c173f51fa1eebe012641e5f292ad8c93ac970c3b7d21ae275870457415cba01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d4934794a2959d3f95eae5dc7d70144ce1b73b403b7eb6e0a004cfb057a5b7c86693bce8d7ec799ab8f147aed49dcb9b95bd80ac84bd4c3213a0d95b3caf807a943577cb0944279eb7a7638a66edd4ff4c86cdb2f59e16ceba98a041fb977bce5a2fc1bd793bdb8f62acf2724836b262c53942e515216846c20c82b901000120000000004000001000428000000a00000000040000080000000000000300800010000020001000000000000400800000000000400000000010000026000018014400001480004000020a000100202c100000000400000000000000040000000800200202000000000000000408000a0800e0000000000001001000000000021000002000000000000200000000000000040000000008000108400000002002000200000000000000200000000000000020000200004000802002000400000000200a000000000000000088020000110020000000001000104002000060000110000000000004010000002000010000008000280000010400000002000000028401fa105a8402faf080830c02038464fb55b1b90115d883010209846765746888676f312e31392e38856c696e7578000000dc55905cf8b27bb8608d78483e986c9514bdf3bad154ee670c4ce5a37cda5b0c9a28fede649e8f6493e87129d026c9899d2d1fbcbb550e28d402c8417fba2f83cdca3f97268771dd62d22baf4b8fc9c7b08158da8a88ecdf64f62d741fd122aee11f07409d21acbf4cf84c8401fa1058a07b3e85509d533664e8467684de404663c53b786cb62fd31b878eb1b0c40641518401fa1059a04537c173f51fa1eebe012641e5f292ad8c93ac970c3b7d21ae275870457415cb80f88bda730d8c24b5e49a06cfd1948fe466a336716450d1f759a78b7bafb5e82832c4dc95f65e0d30a2051f7421d09822036b5d3db8b2dd042ef447beb31e02a700a00000000000000000000000000000000000000000000000000000000000000000880000000000000000800a9a060a9706f90314a09ac299d64d67946b3c859a8db18ef13ec21256e64dbb02324f54e27c6747a016a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d4934794b71b214cb885500844365e95cd9942c7276e7fd8a00a4f00dafd02c141afba8d99d8fc7411235128d1f3cd79c8ee83a879c17e1f8aa07ee816d6cc8df108bf3d7b2ef10a937be1d712614bc2c4775064f16dabd36f7aa0f60f4d692f64738815e9945cf52460ff939c5c82f72f7dc2b2d68aac35450669b9010000000000000000000000004000000000000000000000000000000000000000010000100000000000000000000000080000000000000000000000000000000000000000000010000000000008000800002018000000000000000000000000080000080020000200000000000000000000080000000000000400000010000000000000000002004000000100000000000000000400000000000000000000000020000000000000000000200000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000104002000000000000000000000000010000000004010000000000000000000000000000000000028401fa105b8402faf080830494558464fb55b4b90115d883010209846765746888676f312e31392e38856c696e7578000000dc55905cf8b27bb86081f18a112cc17ab77e6c39e0482c14d31e8f6160d6578685e906ed6c77d6e8f9c0b69affcb30e0bc1a4149e594e3b8ea15bfe9113060869dc17e4bfffdaa54dbd192e7cd7976936fbf17658e49b76b0ba0edb14aabb42da6eaf00add29f45c9ef84c8401fa1059a04537c173f51fa1eebe012641e5f292ad8c93ac970c3b7d21ae275870457415cb8401fa105aa09ac299d64d67946b3c859a8db18ef13ec21256e64dbb02324f54e27c6747a01680f5c744d1686358c8c20c2368a542afcac58c750f4a3fa47c85c271821a5bb185017c2a5b09849545c5d23a05c666e52849d93ff2a271b4c8e4278ba9d2bc699301a0000000000000000000000000000000000000000000000000000000000000000088000000000000000080120510d7a0e80f22141284214b9b9c85549ab3d2b972df0deef66ac2c9221435552c16704d214347f29fa77f77da6d75d7c752221447788386d0ed6c748e03a53160b4b30ed3748cc52214980a75ecd1309ea12fa2ed87a8744fbfc9b863d52214a2959d3f95eae5dc7d70144ce1b73b403b7eb6e02214b71b214cb885500844365e95cd9942c7276e7fd82214f474cf03cceff28abc65c9cbae594f725c80e12d").to_vec();
        let any: Any = header_bytes.try_into().unwrap();
        let header = Header::try_from(any.clone()).unwrap();
        header.verify(&ChainId::new(97)).unwrap()
    }

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
