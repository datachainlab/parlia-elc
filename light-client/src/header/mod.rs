use alloc::borrow::ToOwned as _;
use alloc::vec::Vec;
use ibc::core::ics02_client::error::ClientError;
use ibc::core::ics02_client::header::Header as IBCHeader;
use ibc_proto::google::protobuf::Any;
use ibc_proto::protobuf::Protobuf;

use self::eth_headers::ETHHeaders;
use crate::misc::{new_ibc_height_with_chain_id, ChainId, Hash, ValidatorReader, Validators};
use parlia_ibc_proto::ibc::lightclients::parlia::v1::Header as RawHeader;
use prost::Message as _;

use super::errors::Error;

pub const PARLIA_HEADER_TYPE_URL: &str = "/ibc.lightclients.parlia.v1.Header";

const EPOCH_BLOCK_PERIOD: u64 = 200;

// inner header is module private
mod eth_header;
mod eth_headers;

#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct Header {
    inner: RawHeader,
    headers: ETHHeaders,
    trusted_height: ibc::Height,
}

impl Header {
    pub fn account_proof(&self) -> &[u8] {
        self.inner.account_proof.as_slice()
    }

    pub fn trusted_height(&self) -> ibc::Height {
        self.trusted_height
    }

    pub fn state_root(&self) -> &Hash {
        &self.headers.target.header.root
    }

    pub fn validator_set(&self) -> &Validators {
        &self.headers.target.header.new_validators
    }

    pub fn verify(&self, ctx: impl ValidatorReader, chain_id: &ChainId) -> Result<(), Error> {
        let target = &self.headers.target.header;
        if target.is_epoch {
            if target.number >= EPOCH_BLOCK_PERIOD {
                let previous_epoch_block = target.number - EPOCH_BLOCK_PERIOD;
                let previous_epoch_height =
                    new_ibc_height_with_chain_id(chain_id, previous_epoch_block)?;
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
            let last_epoch_height = new_ibc_height_with_chain_id(chain_id, last_epoch_number)?;
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
                let previous_epoch_height =
                    new_ibc_height_with_chain_id(chain_id, previous_epoch_number)?;
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

impl Protobuf<RawHeader> for Header {}
impl Protobuf<Any> for Header {}

impl TryFrom<RawHeader> for Header {
    type Error = ClientError;

    fn try_from(value: RawHeader) -> Result<Header, Self::Error> {
        let trusted_height = value
            .trusted_height
            .as_ref()
            .ok_or(Error::MissingTrustedHeight)?;
        let trusted_height = ibc::Height::new(
            trusted_height.revision_number,
            trusted_height.revision_height,
        )?;

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

impl IBCHeader for Header {
    fn height(&self) -> ibc::Height {
        self.headers.target.ibc_height.to_owned()
    }

    fn timestamp(&self) -> ibc::timestamp::Timestamp {
        self.headers.target.ibc_timestamp.to_owned()
    }
}

impl TryFrom<Any> for Header {
    type Error = ClientError;

    fn try_from(any: Any) -> Result<Header, Self::Error> {
        if any.type_url != PARLIA_HEADER_TYPE_URL {
            return Err(ClientError::UnknownHeaderType {
                header_type: any.type_url,
            });
        }
        let raw = RawHeader::decode(any.value.as_slice()).map_err(ClientError::Decode)?;
        raw.try_into()
    }
}

impl From<Header> for Any {
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
mod testdata;

#[cfg(test)]
mod test {
    use crate::alloc::string::ToString;
    use crate::errors::Error;
    use crate::errors::Error::MissingTrustedHeight;
    use crate::header::testdata::*;
    use crate::header::Header;
    use crate::misc::{new_ibc_height_with_chain_id, ValidatorReader, Validators};
    use ibc::core::ics02_client::error::ClientError;
    use parlia_ibc_proto::ibc::core::client::v1::Height;
    use parlia_ibc_proto::ibc::lightclients::parlia::v1::Header as RawHeader;
    use std::collections::HashMap;

    #[test]
    fn test_success_try_from_header() {
        let header = create_after_checkpoint_headers();
        assert_eq!(header.headers.all.len(), 11);
        assert_eq!(
            header.headers.target.header, header.headers.all[0],
            "invalid target"
        );
        assert_eq!(
            header.headers.target.ibc_timestamp.nanoseconds() / 1_000_000_000,
            header.headers.target.header.timestamp,
            "invalid timestamp"
        );
        assert_eq!(
            header.headers.target.ibc_height.revision_height(),
            header.headers.target.header.number,
            "invalid revision height"
        );
        assert_eq!(
            header.headers.target.ibc_height.revision_number(),
            header.trusted_height.revision_number(),
            "invalid revision number"
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
        let err = Header::try_from(raw_header.clone()).unwrap_err();
        assert_eq!(
            err.to_string(),
            ClientError::from(MissingTrustedHeight).to_string()
        );

        // Check greater than trusted height
        let trusted_height = Height {
            revision_number: 1,
            revision_height: h1.number,
        };
        raw_header.trusted_height = Some(trusted_height.clone());
        let err = Header::try_from(raw_header.clone()).unwrap_err();
        let expected = Error::UnexpectedTrustedHeight(h1.number, trusted_height.revision_height);
        assert_eq!(err.to_string(), ClientError::from(expected).to_string());

        // Check relation
        let trusted_height = Height {
            revision_number: 1,
            revision_height: 1,
        };
        raw_header.trusted_height = Some(trusted_height);
        let err = Header::try_from(raw_header).unwrap_err();
        let expected = Error::UnexpectedHeaderRelation(h1.number, h1.number);
        assert_eq!(err.to_string(), ClientError::from(expected).to_string());
    }

    struct MockValidatorReader {
        validators: HashMap<ibc::Height, Validators>,
    }
    impl MockValidatorReader {
        fn previous_only() -> Self {
            let mainnet = &mainnet();
            let previous_epoch = fill(create_previous_epoch_block());
            let mut validators = HashMap::<ibc::Height, Validators>::new();
            validators.insert(
                new_ibc_height_with_chain_id(mainnet, previous_epoch.number).unwrap(),
                previous_epoch.new_validators,
            );
            Self { validators }
        }
        fn default() -> Self {
            let mainnet = &mainnet();
            let previous_epoch = fill(create_previous_epoch_block());
            let current_epoch = fill(create_epoch_block());
            let mut validators = HashMap::<ibc::Height, Validators>::new();
            validators.insert(
                new_ibc_height_with_chain_id(mainnet, current_epoch.number).unwrap(),
                current_epoch.new_validators,
            );
            validators.insert(
                new_ibc_height_with_chain_id(mainnet, previous_epoch.number).unwrap(),
                previous_epoch.new_validators,
            );
            Self { validators }
        }
    }
    impl ValidatorReader for MockValidatorReader {
        fn read(&self, height: ibc::Height) -> Result<Validators, Error> {
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
            .remove(&new_ibc_height_with_chain_id(mainnet, epoch.number).unwrap());
        match header.verify(reader, mainnet).unwrap_err() {
            Error::UnexpectedValidatorInEpochBlock(number) => {
                assert_eq!(number, header.headers.target.header.number)
            }
            e => unreachable!("{:?}", e),
        }

        // empty previous validator
        let epoch = create_previous_epoch_block();
        let mut reader = MockValidatorReader::default();
        reader
            .validators
            .remove(&new_ibc_height_with_chain_id(mainnet, epoch.number).unwrap());
        match header.verify(reader, mainnet).unwrap_err() {
            Error::UnexpectedValidatorInEpochBlock(number) => {
                assert_eq!(number, header.headers.target.header.number)
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
            .remove(&new_ibc_height_with_chain_id(mainnet, epoch.number).unwrap());
        match header.verify(reader, mainnet).unwrap_err() {
            Error::UnexpectedValidatorInEpochBlock(number) => {
                assert_eq!(number, header.headers.target.header.number)
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
            .remove(&new_ibc_height_with_chain_id(mainnet, epoch.number).unwrap());
        match header.verify(reader, mainnet).unwrap_err() {
            Error::UnexpectedValidatorInEpochBlock(number) => {
                assert_eq!(number, header.headers.target.header.number)
            }
            e => unreachable!("{:?}", e),
        }

        // empty previous validator
        let epoch = create_previous_epoch_block();
        let mut reader = MockValidatorReader::default();
        reader
            .validators
            .remove(&new_ibc_height_with_chain_id(mainnet, epoch.number).unwrap());
        match header.verify(reader, mainnet).unwrap_err() {
            Error::UnexpectedValidatorInEpochBlock(number) => {
                assert_eq!(number, header.headers.target.header.number)
            }
            e => unreachable!("{:?}", e),
        }
    }
}
