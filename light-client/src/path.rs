use hex_literal::hex;
use patricia_merkle_trie::keccak::keccak_256;
use prost::bytes::{BufMut, BytesMut};

use crate::misc::{Address, Hash, StorageKey};

pub trait Path {
    fn storage_key(&self) -> &StorageKey;
}

/// Path implementation for yui-ibc-solidity
pub struct YuiIBCPath(Bytes32Path);

impl From<&[u8]> for YuiIBCPath {
    /// ```ignore
    /// use parlia_ibc_lc::path::YuiIBCPath;
    ///
    /// let path = YuiIBCPath::from("commitments/ports/port-1/channels/channel-1/sequences/1".as_bytes());
    /// ```
    fn from(raw_path: &[u8]) -> Self {
        // https://github.com/hyperledger-labs/yui-ibc-solidity/blob/47b7b1dc9f133817a73e5882edf1e7792b4bb46d/contracts/core/24-host/IBCCommitment.sol#L73
        let key = keccak_256(raw_path);
        // https://github.com/hyperledger-labs/yui-ibc-solidity/blob/47b7b1dc9f133817a73e5882edf1e7792b4bb46d/contracts/core/24-host/IBCStore.sol#L10
        let slot = hex!("0000000000000000000000000000000000000000000000000000000000000000");
        Self(Bytes32Path::new(&key, &slot))
    }
}

impl Path for YuiIBCPath {
    fn storage_key(&self) -> &Hash {
        self.0.storage_key()
    }
}

/// Path implementation for solidity type mapping(string => ...)
/// - https://github.com/ethereum/solidity/issues/1550
/// - https://medium.com/@dariusdev/how-to-read-ethereum-contract-storage-44252c8af925
pub struct StringPath {
    storage_key: Hash,
}

impl StringPath {
    /// key must be hex string.
    /// ```ignore
    /// use hex_literal::hex;
    /// use parlia_ibc_lc::path::StringPath;
    ///
    /// let path = StringPath::new(
    ///     &hex!("737472696e674b6579"),
    ///     &hex!("0000000000000000000000000000000000000000000000000000000000000002")
    /// );
    /// ```
    #[allow(dead_code)]
    pub fn new(key: &[u8], slot: &[u8; 32]) -> Self {
        // string key need not to add any zero padding.
        // key = web3.toHex("abcdefghijabcdefghijabcdefghijabc")
        Self {
            storage_key: get_solidity_mapping_key(key, slot),
        }
    }
}

impl Path for StringPath {
    fn storage_key(&self) -> &StorageKey {
        &self.storage_key
    }
}

pub struct AddressPath {
    storage_key: Hash,
}

impl AddressPath {
    /// ```ignore
    /// use hex_literal::hex;
    /// use parlia_ibc_lc::path::AddressPath;
    ///
    /// let path = AddressPath::new(
    ///     &hex!("18DAd81d93F32575691131E73878E89e20481839"),
    ///     &hex!("0000000000000000000000000000000000000000000000000000000000000001"),
    /// );
    /// ```
    #[allow(dead_code)]
    pub fn new(key: &Address, slot: &[u8; 32]) -> Self {
        // address key needs left zero padding.
        // address = "0x18DAd81d93F32575691131E73878E89e20481839"
        // key = "00000000000000000000000018DAd81d93F32575691131E73878E89e20481839"
        let mut buffer = BytesMut::with_capacity(32);
        buffer.put_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        buffer.put_slice(key);
        Self {
            storage_key: get_solidity_mapping_key(&buffer, slot),
        }
    }
}

impl Path for AddressPath {
    fn storage_key(&self) -> &StorageKey {
        &self.storage_key
    }
}

pub struct Bytes32Path {
    storage_key: Hash,
}

impl Bytes32Path {
    /// ```ignore
    /// use hex_literal::hex;
    /// use parlia_ibc_lc::path::Bytes32Path;
    ///
    /// let mut key = [0 as u8; 32];
    /// key[0] = 99;
    /// let path = Bytes32Path::new(
    ///     &key,
    ///     &hex!("0000000000000000000000000000000000000000000000000000000000000000"),
    /// );
    /// ```
    pub fn new(key: &[u8; 32], slot: &[u8; 32]) -> Self {
        Self {
            storage_key: get_solidity_mapping_key(key, slot),
        }
    }
}

impl Path for Bytes32Path {
    fn storage_key(&self) -> &StorageKey {
        &self.storage_key
    }
}

/// This returns the key for solidity mapping type
///  - key = <key representation per type>
///  - slot0 = "0000000000000000000000000000000000000000000000000000000000000000"
///  - hash = eth.sha3(key + slot0, {"encoding": "hex"})
///  - value = eth.getStorageAt(address, hash);
fn get_solidity_mapping_key(key: &[u8], slot: &[u8; 32]) -> StorageKey {
    let mut buffer = BytesMut::with_capacity(key.len() + slot.len());
    buffer.put_slice(key);
    buffer.put_slice(slot);
    keccak_256(&buffer)
}
