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

    pub fn previous_epoch_validators(&self) -> (Height, &Hash) {
        let height = &self.height().revision_height();
        let mut epoch_count = height / BLOCKS_PER_EPOCH;
        if epoch_count > 0 {
            epoch_count -= 1;
        }
        (
            Height::new(
                self.height().revision_number(),
                epoch_count * BLOCKS_PER_EPOCH,
            ),
            self.previous_validators.hash(),
        )
    }

    pub fn current_epoch_validators(&self) -> (Height, &Hash) {
        let height = &self.height().revision_height();
        let epoch_count = height / BLOCKS_PER_EPOCH;
        let epoch_block = epoch_count * BLOCKS_PER_EPOCH;
        (
            Height::new(self.height().revision_number(), epoch_block),
            self.current_validators.hash(),
        )
    }

    pub fn verify(&self, chain_id: &ChainId, ) -> Result<(), Error> {
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

        let previous_validators: ValidatorSet = value.previous_validators.clone().into();
        if previous_validators.validators().is_empty() {
            return Err(Error::MissingPreviousTrustedValidators(
                headers.target.number,
            ));
        }

        // Epoch header contains validator set
        let current_validators: ValidatorSet = if headers.target.is_epoch {
            headers.target.new_validators.clone().into()
        } else {
            value.current_validators.clone().into()
        };
        if current_validators.validators().is_empty() {
            return Err(Error::MissingCurrentTrustedValidators(
                headers.target.number,
            ));
        }

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
    use parlia_ibc_proto::ibc::lightclients::parlia::v1::Header as RawHeader;

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
            previous_validators: vec![],
            current_validators: vec![],
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
        raw_header.previous_validators = vec![vec![]];
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
        let relayer_protobuf_any= hex!("0a222f6962632e6c69676874636c69656e74732e7061726c69612e76312e48656164657212f4160adf040adc04f90259a0fbd3b94c30e0cde738fb1068689b4f972779bba3250f1858d60c873e24e19e31a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347949e1cb61bd90f224222f09b3e993edf73cceb0e4fa070b83c7438e336b2851fe920cb020ec7a19c9741c3bc3cc7ae402195c39d05f8a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421b9010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000028201088402625a0080846463462db861d983010111846765746889676f312e31362e3135856c696e75780000079a6cd8f1908de07d3c38808769dacdf5bfee24b5f31f8b70463d6b8407b4cad82c94ae0f898f52aa3e9214d306ffdefe9c370cd9366f4e1e98ba9ab13d0ed84417b20a00a000000000000000000000000000000000000000000000000000000000000000008800000000000000000adf040adc04f90259a0a24be12f523faf18fbcd655e294596e0f260242bc8ca43026d43234ee46c7921a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347941a2bf881c9335e9aa1ce43a00894340bfa70dcdaa070b83c7438e336b2851fe920cb020ec7a19c9741c3bc3cc7ae402195c39d05f8a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421b9010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000028201098402625a00808464634630b861d983010111846765746889676f312e31362e3135856c696e75780000079a6cd8e56b4386e27b2b3c1d2c700705b2ce11c5cffc61d7fe62bf5dbbf9db706b76da48001efeeb50efeaef2b0567ab4373da5294ef07507e0ee62f44fd43338a68b700a000000000000000000000000000000000000000000000000000000000000000008800000000000000000ae2040adf04f9025ca00b1cb6df5310082ce188bf2b9471a69f1c31cf3eae5f047a4800cf13635a9ddea01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d493479442897d87959d07b83a924a34e93b613e7f4798c2a051b17b0832a6a94cc36fcf7ea75a81c3cf033413e6ebdfb930e723986b1022dea07b22a41ad5ce87dcc1f8b34a8acd6695c8a405b45cbf0bb2ac62f591b26bbdbaa0e23c409e300f95ca40d75c456696ae7f34ffed09531d025314bb398c7d3ba9d8b90100000000000000000000000040000000000000000000000000000000000000000000001000000000000000000000000000000002000000000000000000000000000000000000000000000000002000000020100000000000000000000000000000000800200002000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000000001040000000000000000000000000000100000000000100000000000000000000000000000000000282010a8402625a00830550738464634633b861d983010111846765746889676f312e31362e3135856c696e75780000079a6cd826227fe7ecdd311192dd440f7078406eb83a651d6e57ce6690e128277cc2406f0b6c206ea1922591651ae10d177288ac8688768920fa04fec5ea2b4f6711d30200a0000000000000000000000000000000000000000000000000000000000000000088000000000000000012031084021ae706f90364f901f1a0f976cf586bd5a6755525a358f798375dda58de9e0acd9a4419d959b34878f0baa0840518e61f1ff71336cb3f06f8e279fafecee685bbb662c86a7bc6c3a4544508a0ef49012499405671c7d41d87f698a2e1f8c71a18506f43e9b72172ad3412e9e8a0ccaff84a535bd0c22286f3312c2f2ceb9905bf9a800ed2d1e47a90077db733e280a0ce574fc452b8e3543191406758d8f14744f1c3239882ff36de65c311a31032c8a0ce3e90fd6a5751569e8c041a9fe514ee2349a0e28d1c32c73dbc69d4ea5280b6a099ea5f03336678dd624cda4dae4bd14efaff9e42506708d5b715f5a92780caf7a0387977db57341099efcaa7c4c9e4a84322a19157544c35e1989c6efe17dad4f1a05f493db22e2866f8201e2571c321d5cbc69022119ebad596fa0a933cf6544b45a03ca4ee04079b5c54e3608c486269157cd631ae7b7b266889ad670231b11c3049a01011c052441780ca70b46a1b8affbe8cd6b8a650f7f063f3943a524742d0b468a0df5caa3e95ccc684184708dcb9080f369fdaa419b0b1c08d9809aeadf0a4f7e0a041eee44d7cfd75235296a3a6805d64339166f35ea79419f5313fb975e4b51e9da04ab3d2fe1684946e19287a90b6a16c42aa258bfc3d85fecc2e06c91235498c2ba014aba434eb1d9c3fe9dc4a71d5d01591d2718b0b7ff9774e78650f832ad58ec980f8b1808080808080a00d9124c72201f582e29b9c0a24125069594c6948fa9456fc6788590ba0b3925e80a062531565c9fe76a71ca1719aeb9f537b3ddf082dc167c4ffa57b3cb8e950ca2080a03a48f75ef9575e4c8c7ec9163def6c7805e5fc99e5e7513e418c3508c48501ec80a0e2ec5bfa0874d74ec0fdffc07602dab45aa5a426ed8ce5c3f11c957ef5cceccaa063bbda017ccca59c09f11befce4a83265aa2422d818230c3d37b6cefb9008f42808080f85180a03548f0b11fbbfd4744ad6e80f11a1f82c9a36922089e3235bfc5214fbb92080380808080808080a0b0f90dabeb623fb56f8f9a7f835eaa23ab89e12c9c50ca6e895e2e2e0394d53780808080808080f8689f3cc2669227c563939b3db2109a60801ee273f50dea6929d2646facb70ad234b846f8440180a0f9f57a8dacbdb91b54b646ffaf6347a46513d93fcb3b0942f49c9a5b57066e7ca00615ec2683804db553073603c86cc49e83d62d68cd3495c1d45e464c451cfafd22141a2bf881c9335e9aa1ce43a00894340bfa70dcda221442897d87959d07b83a924a34e93b613e7f4798c2221492a84b62acf90b6e82e1583da79fa9cb9e0fc0a722149cb4ec6fc8c53e33c67d91563a07dca0140efbf422149e1cb61bd90f224222f09b3e993edf73cceb0e4f2a141a2bf881c9335e9aa1ce43a00894340bfa70dcda2a1442897d87959d07b83a924a34e93b613e7f4798c22a1492a84b62acf90b6e82e1583da79fa9cb9e0fc0a72a149cb4ec6fc8c53e33c67d91563a07dca0140efbf42a149e1cb61bd90f224222f09b3e993edf73cceb0e4f").to_vec();
        let any: lcp_types::Any = relayer_protobuf_any.try_into().unwrap();
        let header: Header = any.try_into().unwrap();
        let localnet = &ChainId::new(9999);
        header.verify(localnet).unwrap();

        // epoch
        let relayer_protobuf_any = hex!("0a222f6962632e6c69676874636c69656e74732e7061726c69612e76312e48656164657212e7160ac2050abf05f902bca027e36c636e0304875e5032431fd1e430cb1c35a64b65a53034778b0668889cd9a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347941a2bf881c9335e9aa1ce43a00894340bfa70dcdaa07a270c25052b62e6217676b9e4acda21e0bdf9427685b17e3c2845d72e3ca145a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421b90100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000281c88402625a0080846463456db8c5d983010111846765746889676f312e31362e3135856c696e75780000079a6cd81a2bf881c9335e9aa1ce43a00894340bfa70dcda42897d87959d07b83a924a34e93b613e7f4798c292a84b62acf90b6e82e1583da79fa9cb9e0fc0a79cb4ec6fc8c53e33c67d91563a07dca0140efbf49e1cb61bd90f224222f09b3e993edf73cceb0e4f42fe74646a8aba5bf71e4df246febc4c3d449d4309ab95a8f46244c71b3e3e853bdc72183e50c76ec3a36a2949628c98f972556d92112cfec67be506f580597001a000000000000000000000000000000000000000000000000000000000000000008800000000000000000ade040adb04f90258a0a7b13c6bfe6c7404c108dc25e743202c236554787016968d8f1eb2ad7acf9b29a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d493479442897d87959d07b83a924a34e93b613e7f4798c2a07a270c25052b62e6217676b9e4acda21e0bdf9427685b17e3c2845d72e3ca145a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421b90100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000281c98402625a00808464634570b861d983010111846765746889676f312e31362e3135856c696e75780000079a6cd817319d1e7a080e13da9b831cf071883d27d097e7c6c334acec4c7ac2390c535711f3ea0926c73aff5cd257367eacf547872dcb2acb723d3ae3959c7d90f5fb4700a000000000000000000000000000000000000000000000000000000000000000008800000000000000000ae1040ade04f9025ba09df17e1383e307dfb3777ebeeb28294f4c5b16b0dd3269514c85e58ec354246ba01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d493479492a84b62acf90b6e82e1583da79fa9cb9e0fc0a7a0076b825081ab80bae42923d4b5734e82d28e54d6590678d3a4139f38417332cda0beed143786ab0f2f6984506bfe47b5d899df9aa13cfe41bb9b5d5a75df682cdda0975d5aa1e8eceb74dfdd8fc76fc89135faeda9583c482c4b341ee667f014cc8fb90100000000000000000000000040000000000000000000000000008000000000000000001000000000000000000010000000000000000000000000000000000000000000000000000000000000000000000020100000000400000000000000000000000800200002000000000000000000000000000010000000000000200000000000000000000000000000000000000000000004000000000000000008000000000000000000000000000000001000000000000040000000000000008000000000000000000000000000000000000000000000000000000000001040000000000000000000000000000100000000000100000000000000000000000000000000000281ca8402625a00830513178464634573b861d983010111846765746889676f312e31362e3135856c696e75780000079a6cd81f915dc559a6b4179b58429967479ba833c2667041279829f3915067a7b9aa6d1e5d7689f91d96470b646af4a1ad1924e5b96c1531d364c59cd8894b58626f0700a00000000000000000000000000000000000000000000000000000000000000000880000000000000000120310b5011ae706f90364f901f1a0b4a252b1dc3db95e90dc46ac919f7b4ac6f0adb533f4d5430c57edb356fc5277a091fea5718ee1b0595a31b07ce41d5e3050df96e3c1963221747780f73dc0fae3a0fad66f93dc9eb6779da55e5dc05132e965c1cde80d87db5a1f48e0ca6c3a85c7a0dfa015424914c6067f332c37b9ba774a171bc96f31e3d62499f5e1ddc26c094c80a0ce574fc452b8e3543191406758d8f14744f1c3239882ff36de65c311a31032c8a0fa157c3269eedf0a9348d23d63b5ef99e4dcc77a5b506e7adaadcd16b2b9d9b2a099ea5f03336678dd624cda4dae4bd14efaff9e42506708d5b715f5a92780caf7a03065af93f8593882d5c6724561c2711f6a8abd5cc32133202f2dd6cf38df670ea05f493db22e2866f8201e2571c321d5cbc69022119ebad596fa0a933cf6544b45a03ca4ee04079b5c54e3608c486269157cd631ae7b7b266889ad670231b11c3049a01011c052441780ca70b46a1b8affbe8cd6b8a650f7f063f3943a524742d0b468a05889dfab95ded6e9dbc44fb60c7891a353bbfd8be896ecf19cfbc36d606bfff6a041eee44d7cfd75235296a3a6805d64339166f35ea79419f5313fb975e4b51e9da04ab3d2fe1684946e19287a90b6a16c42aa258bfc3d85fecc2e06c91235498c2ba014aba434eb1d9c3fe9dc4a71d5d01591d2718b0b7ff9774e78650f832ad58ec980f8b1808080808080a0b8ac6b4622465ef91d066541f9eee3a6dfeba3a3498b32868fba9a148d8653af80a062531565c9fe76a71ca1719aeb9f537b3ddf082dc167c4ffa57b3cb8e950ca2080a0718d997e59514f5bf2de01dfe3ba30bcb6dab85feb69d9d7bdc0836959cdec8280a0e2ec5bfa0874d74ec0fdffc07602dab45aa5a426ed8ce5c3f11c957ef5cceccaa063bbda017ccca59c09f11befce4a83265aa2422d818230c3d37b6cefb9008f42808080f85180a0c9b7ce26c451011917947ebe8b6f76fe43d6e2e19c81e220d373027fecba0bfd80808080808080a050c41fc681bedc6ab0c021bb2ac63d6dbbc4bc8d37979de20912412e63694c5180808080808080f8689f3cc2669227c563939b3db2109a60801ee273f50dea6929d2646facb70ad234b846f8440180a041b9a3c9dae0a6f360fe6ed0e724b0fe4cc6d7f531423065ef5ddd407059df18a00615ec2683804db553073603c86cc49e83d62d68cd3495c1d45e464c451cfafd22141a2bf881c9335e9aa1ce43a00894340bfa70dcda221442897d87959d07b83a924a34e93b613e7f4798c2221492a84b62acf90b6e82e1583da79fa9cb9e0fc0a722149cb4ec6fc8c53e33c67d91563a07dca0140efbf422149e1cb61bd90f224222f09b3e993edf73cceb0e4f").to_vec();
        let any: lcp_types::Any = relayer_protobuf_any.try_into().unwrap();
        let header: Header = any.try_into().unwrap();
        let localnet = &ChainId::new(9999);
        header.verify(localnet).unwrap();
    }
}
