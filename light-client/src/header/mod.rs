use alloc::borrow::ToOwned as _;
use alloc::vec::Vec;

use lcp_types::{Any, Height, Time};
use prost::Message as _;

use parlia_ibc_proto::google::protobuf::Any as IBCAny;
use parlia_ibc_proto::ibc::lightclients::parlia::v1::Header as RawHeader;

use crate::header::validator_set::ValidatorSet;
use crate::misc::{keccak_256_vec, new_height, new_timestamp, ChainId, Hash};
use crate::proof::decode_eip1184_rlp_proof;

use super::errors::Error;

use self::constant::BLOCKS_PER_EPOCH;
use self::eth_headers::ETHHeaders;

pub const PARLIA_HEADER_TYPE_URL: &str = "/ibc.lightclients.parlia.v1.Header";

// inner header is module private
pub mod constant;
mod eth_header;
mod eth_headers;
pub(crate) mod validator_set;

#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct Header {
    inner: RawHeader,
    headers: ETHHeaders,
    trusted_height: Height,
    previous_validators: ValidatorSet,
    current_validators: ValidatorSet,
}

impl Header {
    pub fn height(&self) -> Height {
        new_height(
            self.trusted_height.revision_number(),
            self.headers.target.number,
        )
    }

    pub fn is_target_epoch(&self) -> bool {
        self.headers.target.is_epoch
    }

    pub fn timestamp(&self) -> Result<Time, Error> {
        new_timestamp(self.headers.target.timestamp)
    }

    pub fn account_proof(&self) -> Result<Vec<Vec<u8>>, Error> {
        decode_eip1184_rlp_proof(&self.inner.account_proof)
    }

    pub fn trusted_height(&self) -> Height {
        self.trusted_height
    }

    pub fn state_root(&self) -> &Hash {
        &self.headers.target.root
    }

    pub fn new_validators_hash(&self) -> Hash {
        keccak_256_vec(&self.headers.target.new_validators)
    }

    pub fn previous_validator_hash(&self) -> (&Height, &Hash) {
        (
            self.previous_validators.height(),
            self.previous_validators.hash(),
        )
    }

    pub fn current_validator_hash(&self) -> (&Height, &Hash) {
        (
            self.current_validators.height(),
            self.current_validators.hash(),
        )
    }

    pub fn verify(&self, chain_id: &ChainId) -> Result<(), Error> {
        self.headers.verify(
            chain_id,
            self.current_validators.validators(),
            self.previous_validators.validators(),
        )
    }
}

impl TryFrom<RawHeader> for Header {
    type Error = Error;

    fn try_from(value: RawHeader) -> Result<Header, Self::Error> {
        let trusted_height = value
            .trusted_height
            .as_ref()
            .ok_or(Error::MissingTrustedHeight)?;
        let trusted_height = new_height(
            trusted_height.revision_number,
            trusted_height.revision_height,
        );

        // All the header revision must be same as the revision of trusted_height.
        let headers = ETHHeaders::new(trusted_height, value.headers.as_slice())?;

        let raw_previous_validators = value
            .previous_validators
            .as_ref()
            .ok_or_else(|| Error::MissingPreviousTrustedValidators(headers.target.number))?
            .clone();
        let previous_validators: ValidatorSet = raw_previous_validators.try_into()?;

        // Epoch header contains validator set
        let current_validators: ValidatorSet = if headers.target.is_epoch {
            ValidatorSet::new(trusted_height.revision_number(), &headers.target)
        } else {
            let raw_current_validators = value
                .current_validators
                .as_ref()
                .ok_or_else(|| Error::MissingCurrentTrustedValidators(headers.target.number))?
                .clone();
            raw_current_validators.try_into()?
        };

        Ok(Self {
            inner: value,
            headers,
            trusted_height,
            previous_validators,
            current_validators,
        })
    }
}

impl From<Header> for RawHeader {
    fn from(value: Header) -> Self {
        value.inner
    }
}

impl TryFrom<IBCAny> for Header {
    type Error = Error;

    fn try_from(any: IBCAny) -> Result<Header, Self::Error> {
        if any.type_url != PARLIA_HEADER_TYPE_URL {
            return Err(Error::UnknownHeaderType(any.type_url));
        }
        let raw = RawHeader::decode(any.value.as_slice()).map_err(Error::ProtoDecodeError)?;
        raw.try_into()
    }
}

impl From<Header> for Any {
    fn from(value: Header) -> Self {
        IBCAny::from(value).into()
    }
}

impl TryFrom<Any> for Header {
    type Error = Error;

    fn try_from(any: Any) -> Result<Self, Self::Error> {
        IBCAny::from(any).try_into()
    }
}

impl From<Header> for IBCAny {
    fn from(value: Header) -> Self {
        let value: RawHeader = value.into();
        let mut v = Vec::new();
        value
            .encode(&mut v)
            .expect("encoding to `Any` from `ParliaHeader`");
        Self {
            type_url: PARLIA_HEADER_TYPE_URL.to_owned(),
            value: v,
        }
    }
}

#[cfg(test)]
pub(crate) mod testdata;

#[cfg(test)]
mod test {

    use hex_literal::hex;

    use parlia_ibc_proto::ibc::core::client::v1::Height;
    use parlia_ibc_proto::ibc::lightclients::parlia::v1::{Header as RawHeader, ValidatorSet};

    use crate::errors::Error;
    use crate::header::testdata::*;
    use crate::header::Header;
    use crate::misc::ChainId;

    #[test]
    fn test_success_try_from_header() {
        let header = create_after_checkpoint_headers();
        assert_eq!(header.headers.all.len(), 11);
        assert_eq!(
            header.headers.target, header.headers.all[0],
            "invalid target"
        );
        assert_eq!(
            header.timestamp().unwrap().as_unix_timestamp_secs(),
            header.headers.target.timestamp,
            "invalid timestamp"
        );
        assert_eq!(
            header.height().revision_number(),
            header.trusted_height.revision_number(),
            "invalid revision number"
        );
        assert_eq!(
            header.height().revision_height(),
            header.headers.target.number,
            "invalid revision height"
        );
        assert!(!header.is_target_epoch(), "invalid epoch");
        let cvh = header.current_validators;
        assert_eq!(cvh.validators().len(), 21, "invalid epoch");
        let pvh = header.previous_validators;
        assert_eq!(pvh.validators().len(), 21, "invalid epoch");
    }

    #[test]
    fn test_error_try_from_header() {
        let h1 = create_non_epoch_block();
        let raw_eth_headers = vec![
            h1.clone().try_into().unwrap(),
            h1.clone().try_into().unwrap(),
        ];

        let mut raw_header = RawHeader {
            headers: raw_eth_headers,
            trusted_height: None,
            account_proof: vec![],
            previous_validators: None,
            current_validators: None,
        };

        // Check require trusted height
        match Header::try_from(raw_header.clone()).unwrap_err() {
            Error::MissingTrustedHeight => {}
            _ => unreachable!(),
        }

        // Check greater than trusted height
        let trusted_height = Height {
            revision_number: 1,
            revision_height: h1.number,
        };
        raw_header.trusted_height = Some(trusted_height.clone());
        match Header::try_from(raw_header.clone()).unwrap_err() {
            Error::UnexpectedTrustedHeight(a, b) => {
                assert_eq!(a, h1.number);
                assert_eq!(b, trusted_height.revision_height);
            }
            _ => unreachable!(),
        }

        // Check relation
        let trusted_height = Height {
            revision_number: 1,
            revision_height: 1,
        };
        raw_header.trusted_height = Some(trusted_height);
        match Header::try_from(raw_header.clone()).unwrap_err() {
            Error::UnexpectedHeaderRelation(a, b) => {
                assert_eq!(a, h1.number);
                assert_eq!(b, h1.number);
            }
            _ => unreachable!(),
        }

        // Check previous validator set
        raw_header.headers[1] = create_non_epoch_block1().try_into().unwrap();
        match Header::try_from(raw_header.clone()).unwrap_err() {
            Error::MissingPreviousTrustedValidators(a) => {
                assert_eq!(a, h1.number);
            }
            _ => unreachable!(),
        }

        // Check current validator set
        raw_header.previous_validators = Some(ValidatorSet {
            epoch_height: Some(Height {
                revision_number: 0,
                revision_height: 1,
            }),
            validators: vec![],
        });
        match Header::try_from(raw_header.clone()).unwrap_err() {
            Error::MissingCurrentTrustedValidators(a) => {
                assert_eq!(a, h1.number);
            }
            _ => unreachable!(),
        }
    }

    #[test]
    fn test_success_verify_after_checkpoint() {
        let header = create_after_checkpoint_headers();
        let mainnet = &mainnet();
        let result = header.verify(mainnet);
        assert!(result.is_ok())
    }

    #[test]
    fn test_success_verify_epoch() {
        let header = create_before_checkpoint_headers();
        let mainnet = &mainnet();
        // use new validator from epoch
        let result = header.verify(mainnet);
        assert!(result.is_ok())
    }

    #[test]
    fn test_success_verify_across_checkpoint() {
        let header = create_across_checkpoint_headers();
        let mainnet = &mainnet();
        let result = header.verify(mainnet);
        assert!(result.is_ok())
    }

    #[test]
    fn test_try_from_any() {
        // local net relayer data
        // not epoch
        let relayer_protobuf_any= hex!("0a222f6962632e6c69676874636c69656e74732e7061726c69612e76312e48656164657212ed150adf040adc04f90259a0be2e2be652d2fab005526d730d842431fe0a62511552f68a17ccdd3efac5fcfba01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d4934794c1b53c6bf112a572f3059e2ec156fd24667a2b9fa06283fa44addd18c8c757f1136f732b48a2ef1e8c5eded318c460e4ad2610d6aaa056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421b90100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000282027a8402625a0080846460b1a8b861d983010111846765746889676f312e31362e3135856c696e757800008956373651dd48eba1bb11b8f9bd12aac2778bf74e0c4df2d98286bb10c09d6572f4ea433aff1c88731281f7ed8e571d5eb28086a6b413fe50f48632146d3aa259511b7f00a000000000000000000000000000000000000000000000000000000000000000008800000000000000000adf040adc04f90259a0c0a529cb2f705c7cc4ff7fc4703b9e2bb49c34234bfd1768a621b80dd3783e2ea01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d493479410515e82bc63b61f072e3b4f2b64d0c70f275e7ca06283fa44addd18c8c757f1136f732b48a2ef1e8c5eded318c460e4ad2610d6aaa056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421b90100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000282027b8402625a0080846460b1abb861d983010111846765746889676f312e31362e3135856c696e75780000895637368adfdf7a32bcf5b47ccba1d22860b8f8d5dedb639c2bf9bf2af9b080134b2e785a5d9c345fd27de395c0fce515cb8d8389c7213f22715eba8778baa26cf7339a00a000000000000000000000000000000000000000000000000000000000000000008800000000000000000adf040adc04f90259a0b6476d63cb5ac37bd939f66c36facc2f4a6fe881e7cbe6ea7b1d1560bdf3a0d3a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347943cbeba7180b31b37a253c42b69aa40df3e2d51eba06283fa44addd18c8c757f1136f732b48a2ef1e8c5eded318c460e4ad2610d6aaa056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421b90100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000282027c8402625a0080846460b1aeb861d983010111846765746889676f312e31362e3135856c696e7578000089563736769383600e87d9dd933304b4c09de4d7dea13f560813001f9abe969fb6eeed605be0afbcdbab2caabe40b9906666c343a71e843202ce96a238054dc7628a1be000a00000000000000000000000000000000000000000000000000000000000000000880000000000000000120310f1041ad505f902d2f901d1a0720a09fc803cc6c8935813289e0934d5dbb3dcdaee735f9a343a93b851ba8de7a088bbc97920b6c8e02b2e306623b41b5256445fe59a408c000f8ba4d18725f9b7a0dcf0908675c7b75cfb42c358d48bb594a10c0c689c1eaee95e119235a949acdc8080a0ce574fc452b8e3543191406758d8f14744f1c3239882ff36de65c311a31032c8a0e72573919bd9e9a5ae04b5ceca9d823ddc66ec9c535a4dd2ca8505fc8b51d4eca099ea5f03336678dd624cda4dae4bd14efaff9e42506708d5b715f5a92780caf7a0ea5d9b712a33f5eae8426276eb8d22c325276a8936111c45b3489db4f166d32aa0e83c004ac957487c6838c3b73bc7b52981e91f94952127c58b1156d18dcd01dba0eb2c6da4f74980351ee9612496af26b6b4152c254a2c0f9245c5f4814fbe33aca01011c052441780ca70b46a1b8affbe8cd6b8a650f7f063f3943a524742d0b468a02a53b86c1c583f89d0894cc0e0d2e321f4e2bac4f08d2f477980f9dad1828d58a041eee44d7cfd75235296a3a6805d64339166f35ea79419f5313fb975e4b51e9da04ab3d2fe1684946e19287a90b6a16c42aa258bfc3d85fecc2e06c91235498c2ba014aba434eb1d9c3fe9dc4a71d5d01591d2718b0b7ff9774e78650f832ad58ec980f8918080808080808080a0d0bb13caaa0b3753a32816bb2af8e832e7f70e782c287a757f820a7a996d9b4780a08aca4b4250df553243de7b7eb4315161178efe38e3f523235e9323681fa44a3280a0e2ec5bfa0874d74ec0fdffc07602dab45aa5a426ed8ce5c3f11c957ef5cceccaa063bbda017ccca59c09f11befce4a83265aa2422d818230c3d37b6cefb9008f42808080f869a0209cc2669227c563939b3db2109a60801ee273f50dea6929d2646facb70ad234b846f8440180a0d7cb130faec40201a8c1656faee693ca0902f6220c9b67649f0a306daa85d113a00615ec2683804db553073603c86cc49e83d62d68cd3495c1d45e464c451cfafd22730a03109003121410515e82bc63b61f072e3b4f2b64d0c70f275e7c12143cbeba7180b31b37a253c42b69aa40df3e2d51eb1214475284ee3de01899b76ee28ac3d2b2e3d5f5dc681214a5d3a2383997efc142bedf703c143b37b39306ac1214c1b53c6bf112a572f3059e2ec156fd24667a2b9f2a730a0310d804121410515e82bc63b61f072e3b4f2b64d0c70f275e7c12143cbeba7180b31b37a253c42b69aa40df3e2d51eb1214475284ee3de01899b76ee28ac3d2b2e3d5f5dc681214a5d3a2383997efc142bedf703c143b37b39306ac1214c1b53c6bf112a572f3059e2ec156fd24667a2b9f").to_vec();
        let any: lcp_types::Any = relayer_protobuf_any.try_into().unwrap();
        let header: Header = any.try_into().unwrap();
        header.verify(&ChainId::new(9999)).unwrap();

        // epoch
        let relayer_protobuf_any = hex!("0a222f6962632e6c69676874636c69656e74732e7061726c69612e76312e48656164657212d3150ac2050abf05f902bca07d7339e4e08e56b43c78aa262d4afdc42d0e514a12119948239e8c0619774093a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d493479410515e82bc63b61f072e3b4f2b64d0c70f275e7ca0ba36e3d8983c0530ff72bfa265ad56258e07c91a3d5225096ce23d845f257be3a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421b90100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000281c88402625a0080846460ac92b8c5d983010111846765746889676f312e31362e3135856c696e757800008956373610515e82bc63b61f072e3b4f2b64d0c70f275e7c3cbeba7180b31b37a253c42b69aa40df3e2d51eb475284ee3de01899b76ee28ac3d2b2e3d5f5dc68a5d3a2383997efc142bedf703c143b37b39306acc1b53c6bf112a572f3059e2ec156fd24667a2b9fa66f4a829ecd4f0f473e0714ae3c0389cc5efd1412ffa91c48d450210ff60fb44e953e7f8502660e19733200bb414941fc55de814bc6077d526ba83c554214d300a000000000000000000000000000000000000000000000000000000000000000008800000000000000000ade040adb04f90258a0e6c062a5e130ed7138af090af9fa0711698cbe878301f96f0fc809b084b03b99a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347943cbeba7180b31b37a253c42b69aa40df3e2d51eba0ba36e3d8983c0530ff72bfa265ad56258e07c91a3d5225096ce23d845f257be3a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421b90100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000281c98402625a0080846460ac95b861d983010111846765746889676f312e31362e3135856c696e7578000089563736b58a49a8ee3fb1c6c7358d1990f7e48a187f048abfd96097857329e864f65d525f2865fdfffb9ffc3e97962f0cad385d7a435a2c8a301e3eaae276477143899a01a000000000000000000000000000000000000000000000000000000000000000008800000000000000000ade040adb04f90258a0809bedfd97f2a5cfcb181c8376eda7823a59ba028a13a7559f9936e82026b80ca01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d4934794475284ee3de01899b76ee28ac3d2b2e3d5f5dc68a0ba36e3d8983c0530ff72bfa265ad56258e07c91a3d5225096ce23d845f257be3a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421b90100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000281ca8402625a0080846460ac98b861d983010111846765746889676f312e31362e3135856c696e75780000895637368c371b6d8dcf9ff1913f0f4536d71e60d6b634b0ad20496a5f5b752d91f7cb3b00f98d183e5c7143f42224da4148e8bc3d7a9ff6712009c00eec07b0c784230d01a0000000000000000000000000000000000000000000000000000000000000000088000000000000000012001ad505f902d2f901d1a0f4d08c855f50773f4d1a11a2515ab0393f99d2fa4f905d5b8202b08d40b0f5a9a02ec372669b3cfa315d75e136320ca1c13c6d63ebdf69a0230390b9c15262a183a0323178286ad0a78bf7ae83987b763252ed8e5bb0a80eddf982e74f2269f0c2b38080a0ce574fc452b8e3543191406758d8f14744f1c3239882ff36de65c311a31032c8a057788c0986772b5e5a564795da42161f16f91f80592ab8b80cf047a2132647cda099ea5f03336678dd624cda4dae4bd14efaff9e42506708d5b715f5a92780caf7a041418a712e542559e46c0defcc27ecb9d94b875f0d045aa54551680607340787a04546cc9466917501c6e28c0f63f236c90f39a44b78ad2c4729436568165a1747a03d9861bda954cdff78d3984aede03b075fe68d82573025d5277d9c43c9be5bf4a01011c052441780ca70b46a1b8affbe8cd6b8a650f7f063f3943a524742d0b468a07f9c9c2309555384d2dcf477da93a4a63f3ffbc8b1d88c34d45e5c047c4bf7dfa041eee44d7cfd75235296a3a6805d64339166f35ea79419f5313fb975e4b51e9da04ab3d2fe1684946e19287a90b6a16c42aa258bfc3d85fecc2e06c91235498c2ba014aba434eb1d9c3fe9dc4a71d5d01591d2718b0b7ff9774e78650f832ad58ec980f8918080808080808080a05106fd600139e7ccdf76042ae7fa628a4094a1dc6a1c3bcd421eaef2888f672d80a0cddae46842361b36165c01a52e4c8721da7d41d743b68d6cde9cde563dcef31280a0e2ec5bfa0874d74ec0fdffc07602dab45aa5a426ed8ce5c3f11c957ef5cceccaa063bbda017ccca59c09f11befce4a83265aa2422d818230c3d37b6cefb9008f42808080f869a0209cc2669227c563939b3db2109a60801ee273f50dea6929d2646facb70ad234b846f8440180a061abbfed57bf46a4f0dae8ba56057f9f21f59d935c63d18be2e99ef2c2651e56a00615ec2683804db553073603c86cc49e83d62d68cd3495c1d45e464c451cfafd22700a001214475284ee3de01899b76ee28ac3d2b2e3d5f5dc681214a5d3a2383997efc142bedf703c143b37b39306ac1214c1b53c6bf112a572f3059e2ec156fd24667a2b9f12143cbeba7180b31b37a253c42b69aa40df3e2d51eb121410515e82bc63b61f072e3b4f2b64d0c70f275e7c").to_vec();
        let any: lcp_types::Any = relayer_protobuf_any.try_into().unwrap();
        let header: Header = any.try_into().unwrap();
        header.verify(&ChainId::new(9999)).unwrap();
    }
}
