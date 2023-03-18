use alloc::borrow::ToOwned as _;
use alloc::vec::Vec;

use ibc_proto::google::protobuf::Any as IBCAny;
use ibc_proto::protobuf::Protobuf;
use lcp_types::{Any, Height, Time};
use prost::Message as _;
use rlp::Rlp;

use parlia_ibc_proto::ibc::lightclients::parlia::v1::Header as RawHeader;

use crate::misc::{new_height, new_timestamp, ChainId, Hash, ValidatorReader, Validators};

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
    pub fn state_root(&self) -> &Hash {
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
            identifier: alloc::string::String::from("test"),
            headers: raw_eth_headers,
            trusted_height: None,
            account_proof: vec![],
        };

        // Check require trusted height
        match Header::try_from(raw_header.clone()).unwrap_err() {
            Error::MissingTrustedHeight => assert!(true),
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
}
