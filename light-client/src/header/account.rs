use crate::commitment::decode_eip1184_rlp_proof;
use crate::errors::Error;
use crate::misc::Hash;
use alloc::vec::Vec;
use parlia_ibc_proto::ibc::lightclients::parlia::v1::AccountUpdateInfo as RawAccountUpdateInfo;

#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AccountUpdateInfo {
    pub account_proof: Vec<Vec<u8>>,
    pub account_storage_root: Hash,
}

impl TryFrom<RawAccountUpdateInfo> for AccountUpdateInfo {
    type Error = Error;
    fn try_from(value: RawAccountUpdateInfo) -> Result<Self, Self::Error> {
        Ok(Self {
            account_proof: decode_eip1184_rlp_proof(value.account_proof.as_slice())?,
            account_storage_root: value
                .account_storage_root
                .try_into()
                .map_err(Error::UnexpectedStorageRoot)?,
        })
    }
}
