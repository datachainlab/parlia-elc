use alloc::borrow::ToOwned as _;
use alloc::vec::Vec;

use lcp_types::{Any, Height, Time};
use parlia_ibc_proto::google::protobuf::Any as IBCAny;
use prost::Message as _;
use rlp::Rlp;

use parlia_ibc_proto::ibc::lightclients::parlia::v1::Header as RawHeader;

use crate::misc::{new_height, new_timestamp, ChainId, ValidatorReader, Validators};

use super::errors::Error;

use self::eth_headers::ETHHeaders;

pub const PARLIA_HEADER_TYPE_URL: &str = "/ibc.lightclients.parlia.v1.Header";

const EPOCH_BLOCK_PERIOD: u64 = 200;

// inner header is module private
mod eth_header;
mod eth_headers;

#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct Header {
    inner: RawHeader,
    headers: ETHHeaders,
    trusted_height: Height,
}

impl Header {
    pub fn height(&self) -> Height {
        new_height(
            self.trusted_height.revision_number(),
            self.headers.target.number,
        )
    }

    pub fn timestamp(&self) -> Result<Time, Error> {
        new_timestamp(self.headers.target.timestamp)
    }

    pub fn account_proof(&self) -> Result<Vec<Vec<u8>>, Error> {
        let rlp = Rlp::new(&self.inner.account_proof);
        rlp.as_list().map_err(Error::RLPDecodeError)
    }

    pub fn trusted_height(&self) -> Height {
        self.trusted_height
    }

    //TODO cfg when the sufficient test data is found.
    #[cfg(not(test))]
    pub fn state_root(&self) -> &crate::misc::Hash {
        &self.headers.target.root
    }

    pub fn validator_set(&self) -> &Validators {
        &self.headers.target.new_validators
    }

    pub fn verify(&self, ctx: impl ValidatorReader, chain_id: &ChainId) -> Result<(), Error> {
        let target = &self.headers.target;
        if target.is_epoch {
            if target.number >= EPOCH_BLOCK_PERIOD {
                let previous_epoch_block = target.number - EPOCH_BLOCK_PERIOD;
                let previous_epoch_height = new_height(chain_id.version(), previous_epoch_block);
                let previous_validator_set = ctx.read(previous_epoch_height)?;
                if previous_validator_set.is_empty() {
                    return Err(Error::UnexpectedValidatorInEpochBlock(target.number));
                }
                self.headers
                    .verify(chain_id, &target.new_validators, &previous_validator_set)
            } else {
                // genesis block
                let genesis_validator_set = &target.new_validators;
                self.headers
                    .verify(chain_id, genesis_validator_set, genesis_validator_set)
            }
        } else {
            let epoch_count = target.number / EPOCH_BLOCK_PERIOD;
            let last_epoch_number = epoch_count * EPOCH_BLOCK_PERIOD;
            let last_epoch_height = new_height(chain_id.version(), last_epoch_number);
            let new_validator_set = &ctx.read(last_epoch_height)?;
            if new_validator_set.is_empty() {
                return Err(Error::UnexpectedValidatorInEpochBlock(target.number));
            }
            if epoch_count == 0 {
                // Use genesis epoch validator set
                self.headers
                    .verify(chain_id, new_validator_set, new_validator_set)
            } else {
                let previous_epoch_number = (epoch_count - 1) * EPOCH_BLOCK_PERIOD;
                let previous_epoch_height = new_height(chain_id.version(), previous_epoch_number);
                let previous_validator_set = &ctx.read(previous_epoch_height)?;
                if previous_validator_set.is_empty() {
                    return Err(Error::UnexpectedValidatorInEpochBlock(target.number));
                }
                self.headers
                    .verify(chain_id, new_validator_set, previous_validator_set)
            }
        }
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

        Ok(Self {
            inner: value,
            headers,
            trusted_height,
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
    use std::collections::HashMap;

    use parlia_ibc_proto::ibc::core::client::v1::Height;
    use parlia_ibc_proto::ibc::lightclients::parlia::v1::Header as RawHeader;

    use crate::errors::Error;
    use crate::header::testdata::*;
    use crate::header::Header;
    use crate::misc::{new_height, ValidatorReader, Validators};

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
        match Header::try_from(raw_header).unwrap_err() {
            Error::UnexpectedHeaderRelation(a, b) => {
                assert_eq!(a, h1.number);
                assert_eq!(b, h1.number);
            }
            _ => unreachable!(),
        }
    }

    struct MockValidatorReader {
        validators: HashMap<lcp_types::Height, Validators>,
    }
    impl MockValidatorReader {
        fn previous_only() -> Self {
            let mainnet = &mainnet();
            let previous_epoch = fill(create_previous_epoch_block());
            let mut validators = HashMap::<lcp_types::Height, Validators>::new();
            validators.insert(
                new_height(mainnet.version(), previous_epoch.number),
                previous_epoch.new_validators,
            );
            Self { validators }
        }
        fn default() -> Self {
            let mainnet = &mainnet();
            let previous_epoch = fill(create_previous_epoch_block());
            let current_epoch = fill(create_epoch_block());
            let mut validators = HashMap::<lcp_types::Height, Validators>::new();
            validators.insert(
                new_height(mainnet.version(), current_epoch.number),
                current_epoch.new_validators,
            );
            validators.insert(
                new_height(mainnet.version(), previous_epoch.number),
                previous_epoch.new_validators,
            );
            Self { validators }
        }
    }
    impl ValidatorReader for MockValidatorReader {
        fn read(&self, height: lcp_types::Height) -> Result<Validators, Error> {
            Ok(self.validators.get(&height).unwrap_or(&vec![]).clone())
        }
    }

    #[test]
    fn test_success_verify_after_checkpoint() {
        let header = create_after_checkpoint_headers();
        let reader = MockValidatorReader::default();
        let mainnet = &mainnet();
        let result = header.verify(reader, mainnet);
        assert!(result.is_ok())
    }

    #[test]
    fn test_error_verify_after_checkpoint() {
        let header = create_after_checkpoint_headers();
        let mainnet = &mainnet();

        // empty new validator
        let epoch = create_epoch_block();
        let mut reader = MockValidatorReader::default();
        reader
            .validators
            .remove(&new_height(mainnet.version(), epoch.number));
        match header.verify(reader, mainnet).unwrap_err() {
            Error::UnexpectedValidatorInEpochBlock(number) => {
                assert_eq!(number, header.headers.target.number)
            }
            e => unreachable!("{:?}", e),
        }

        // empty previous validator
        let epoch = create_previous_epoch_block();
        let mut reader = MockValidatorReader::default();
        reader
            .validators
            .remove(&new_height(mainnet.version(), epoch.number));
        match header.verify(reader, mainnet).unwrap_err() {
            Error::UnexpectedValidatorInEpochBlock(number) => {
                assert_eq!(number, header.headers.target.number)
            }
            e => unreachable!("{:?}", e),
        }
    }

    #[test]
    fn test_success_verify_epoch() {
        let header = create_before_checkpoint_headers();
        let reader = MockValidatorReader::previous_only();
        let mainnet = &mainnet();
        // use new validator from epoch
        let result = header.verify(reader, mainnet);
        assert!(result.is_ok())
    }

    #[test]
    fn test_error_verify_epoch() {
        let header = create_before_checkpoint_headers();
        let _reader = MockValidatorReader::previous_only();
        let mainnet = &mainnet();

        // empty previous validator
        let epoch = create_previous_epoch_block();
        let mut reader = MockValidatorReader::default();
        reader
            .validators
            .remove(&new_height(mainnet.version(), epoch.number));
        match header.verify(reader, mainnet).unwrap_err() {
            Error::UnexpectedValidatorInEpochBlock(number) => {
                assert_eq!(number, header.headers.target.number)
            }
            e => unreachable!("{:?}", e),
        }
    }

    #[test]
    fn test_success_verify_across_checkpoint() {
        let header = create_across_checkpoint_headers();
        let reader = MockValidatorReader::default();
        let mainnet = &mainnet();
        let result = header.verify(reader, mainnet);
        assert!(result.is_ok())
    }

    #[test]
    fn test_error_verify_across_checkpoint() {
        let header = create_across_checkpoint_headers();
        let _reader = MockValidatorReader::default();
        let mainnet = &mainnet();

        // empty new validator
        let epoch = create_epoch_block();
        let mut reader = MockValidatorReader::default();
        reader
            .validators
            .remove(&new_height(mainnet.version(), epoch.number));
        match header.verify(reader, mainnet).unwrap_err() {
            Error::UnexpectedValidatorInEpochBlock(number) => {
                assert_eq!(number, header.headers.target.number)
            }
            e => unreachable!("{:?}", e),
        }

        // empty previous validator
        let epoch = create_previous_epoch_block();
        let mut reader = MockValidatorReader::default();
        reader
            .validators
            .remove(&new_height(mainnet.version(), epoch.number));
        match header.verify(reader, mainnet).unwrap_err() {
            Error::UnexpectedValidatorInEpochBlock(number) => {
                assert_eq!(number, header.headers.target.number)
            }
            e => unreachable!("{:?}", e),
        }
    }

    #[test]
    fn test_try_from_any() {
        let relayer_protobuf_any = vec![
            10, 34, 47, 105, 98, 99, 46, 108, 105, 103, 104, 116, 99, 108, 105, 101, 110, 116, 115,
            46, 112, 97, 114, 108, 105, 97, 46, 118, 49, 46, 72, 101, 97, 100, 101, 114, 18, 190,
            10, 10, 223, 4, 10, 220, 4, 249, 2, 89, 160, 130, 245, 8, 243, 2, 96, 254, 45, 93, 43,
            75, 12, 197, 67, 117, 77, 186, 148, 79, 251, 39, 70, 73, 41, 206, 235, 56, 75, 21, 119,
            92, 32, 160, 29, 204, 77, 232, 222, 199, 93, 122, 171, 133, 181, 103, 182, 204, 212,
            26, 211, 18, 69, 27, 148, 138, 116, 19, 240, 161, 66, 253, 64, 212, 147, 71, 148, 205,
            217, 129, 55, 141, 160, 14, 69, 82, 231, 98, 72, 102, 219, 195, 188, 30, 24, 2, 230,
            160, 65, 213, 142, 196, 99, 241, 245, 221, 60, 109, 122, 138, 236, 82, 196, 4, 79, 151,
            74, 158, 33, 47, 168, 238, 230, 252, 61, 63, 189, 66, 34, 40, 160, 86, 232, 31, 23, 27,
            204, 85, 166, 255, 131, 69, 230, 146, 192, 248, 110, 91, 72, 224, 27, 153, 108, 173,
            192, 1, 98, 47, 181, 227, 99, 180, 33, 160, 86, 232, 31, 23, 27, 204, 85, 166, 255,
            131, 69, 230, 146, 192, 248, 110, 91, 72, 224, 27, 153, 108, 173, 192, 1, 98, 47, 181,
            227, 99, 180, 33, 185, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 2, 130, 5, 78, 132, 2, 98, 90, 0, 128, 132, 100, 58, 156, 18, 184, 97,
            217, 131, 1, 1, 17, 132, 103, 101, 116, 104, 137, 103, 111, 49, 46, 49, 54, 46, 49, 53,
            133, 108, 105, 110, 117, 120, 0, 0, 59, 176, 211, 76, 196, 18, 144, 158, 102, 143, 66,
            180, 172, 212, 130, 176, 1, 186, 202, 202, 148, 242, 232, 178, 202, 246, 236, 139, 227,
            225, 35, 48, 167, 41, 214, 122, 18, 12, 171, 1, 177, 10, 196, 54, 101, 230, 13, 194,
            119, 255, 0, 93, 160, 212, 56, 24, 67, 155, 82, 162, 72, 141, 208, 251, 231, 111, 19,
            205, 1, 160, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 136, 0, 0, 0, 0, 0, 0, 0, 0, 18, 2, 16, 110, 26, 213, 5, 249, 2,
            210, 249, 1, 209, 160, 42, 70, 86, 189, 2, 136, 200, 246, 3, 238, 0, 192, 71, 6, 136,
            198, 103, 155, 254, 167, 238, 95, 136, 91, 140, 56, 47, 180, 254, 139, 222, 75, 160,
            75, 31, 70, 89, 169, 179, 49, 169, 22, 57, 216, 234, 14, 14, 2, 80, 226, 201, 61, 5,
            239, 64, 225, 77, 181, 109, 231, 48, 75, 91, 103, 88, 160, 71, 142, 109, 238, 82, 173,
            122, 207, 36, 235, 38, 111, 220, 44, 63, 33, 254, 113, 82, 62, 125, 175, 12, 144, 185,
            196, 122, 173, 6, 105, 74, 151, 128, 128, 160, 206, 87, 79, 196, 82, 184, 227, 84, 49,
            145, 64, 103, 88, 216, 241, 71, 68, 241, 195, 35, 152, 130, 255, 54, 222, 101, 195, 17,
            163, 16, 50, 200, 160, 34, 207, 80, 162, 76, 230, 150, 39, 195, 238, 209, 71, 25, 189,
            62, 59, 122, 81, 45, 0, 150, 160, 17, 55, 207, 76, 41, 200, 107, 254, 10, 252, 160,
            153, 234, 95, 3, 51, 102, 120, 221, 98, 76, 218, 77, 174, 75, 209, 78, 250, 255, 158,
            66, 80, 103, 8, 213, 183, 21, 245, 169, 39, 128, 202, 247, 160, 192, 49, 184, 170, 165,
            162, 160, 79, 170, 195, 32, 18, 242, 141, 117, 218, 160, 172, 129, 223, 38, 43, 28,
            103, 186, 252, 15, 216, 72, 176, 168, 134, 160, 95, 73, 61, 178, 46, 40, 102, 248, 32,
            30, 37, 113, 195, 33, 213, 203, 198, 144, 34, 17, 158, 186, 213, 150, 250, 10, 147, 60,
            246, 84, 75, 69, 160, 60, 164, 238, 4, 7, 155, 92, 84, 227, 96, 140, 72, 98, 105, 21,
            124, 214, 49, 174, 123, 123, 38, 104, 137, 173, 103, 2, 49, 177, 28, 48, 73, 160, 16,
            17, 192, 82, 68, 23, 128, 202, 112, 180, 106, 27, 138, 255, 190, 140, 214, 184, 166,
            80, 247, 240, 99, 243, 148, 58, 82, 71, 66, 208, 180, 104, 160, 144, 197, 122, 225, 15,
            204, 216, 210, 9, 22, 18, 172, 136, 239, 33, 152, 22, 40, 88, 79, 120, 193, 240, 186,
            1, 97, 222, 99, 42, 190, 66, 240, 160, 65, 238, 228, 77, 124, 253, 117, 35, 82, 150,
            163, 166, 128, 93, 100, 51, 145, 102, 243, 94, 167, 148, 25, 245, 49, 63, 185, 117,
            228, 181, 30, 157, 160, 74, 179, 210, 254, 22, 132, 148, 110, 25, 40, 122, 144, 182,
            161, 108, 66, 170, 37, 139, 252, 61, 133, 254, 204, 46, 6, 201, 18, 53, 73, 140, 43,
            160, 20, 171, 164, 52, 235, 29, 156, 63, 233, 220, 74, 113, 213, 208, 21, 145, 210,
            113, 139, 11, 127, 249, 119, 78, 120, 101, 15, 131, 42, 213, 142, 201, 128, 248, 145,
            128, 128, 128, 128, 128, 128, 128, 128, 160, 98, 83, 21, 101, 201, 254, 118, 167, 28,
            161, 113, 154, 235, 159, 83, 123, 61, 223, 8, 45, 193, 103, 196, 255, 165, 123, 60,
            184, 233, 80, 202, 32, 128, 160, 172, 107, 151, 239, 91, 70, 75, 253, 178, 46, 75, 94,
            103, 140, 200, 0, 132, 46, 71, 121, 207, 239, 12, 35, 76, 255, 49, 12, 220, 181, 159,
            58, 128, 160, 226, 236, 91, 250, 8, 116, 215, 78, 192, 253, 255, 192, 118, 2, 218, 180,
            90, 165, 164, 38, 237, 140, 229, 195, 241, 28, 149, 126, 245, 204, 236, 202, 160, 99,
            187, 218, 1, 124, 204, 165, 156, 9, 241, 27, 239, 206, 74, 131, 38, 90, 162, 66, 45,
            129, 130, 48, 195, 211, 123, 108, 239, 185, 0, 143, 66, 128, 128, 128, 248, 105, 160,
            32, 156, 194, 102, 146, 39, 197, 99, 147, 155, 61, 178, 16, 154, 96, 128, 30, 226, 115,
            245, 13, 234, 105, 41, 210, 100, 111, 172, 183, 10, 210, 52, 184, 70, 248, 68, 1, 128,
            160, 124, 26, 239, 67, 167, 97, 39, 49, 85, 217, 203, 38, 192, 221, 52, 4, 150, 133,
            155, 212, 199, 190, 211, 211, 8, 22, 44, 198, 32, 198, 250, 150, 160, 6, 21, 236, 38,
            131, 128, 77, 181, 83, 7, 54, 3, 200, 108, 196, 158, 131, 214, 45, 104, 205, 52, 149,
            193, 212, 94, 70, 76, 69, 28, 250, 253,
        ];
        let any: lcp_types::Any = relayer_protobuf_any.try_into().unwrap();
        let header: Header = any.try_into().unwrap();
    }
}
