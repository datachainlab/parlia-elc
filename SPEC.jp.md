# Synops

この仕様書では、Parliaコンセンサスを使用したブロックチェーンのクライアント (検証アルゴリズム) について説明します。

# About Parlia
BSC は、コンセンサスのために DPoS と PoA を組み合わせることを提案しています。  
コンセンサスエンジンの実装は、cliqueに似たParliaという名前が付けられています。 
* ブロックは限られたバリデーターのセットによって生成されます
* バリデーターは、イーサリアムのcliqueコンセンサス設計と同様に、PoA 方式で交代でブロックを生成します。 
* バリデーターセットはステーキングベースのガバナンスに基づいて選出されます。
* バリデーターセットの変更は (epoch+N/2) ブロックで発生します。(N はエポック ブロック前のバリデータセットのサイズです)。

参考：https://docs.bnbchain.org/docs/learn/consensus

# Technical Specification

## ClientState

```rust
pub struct ClientState {
    pub chain_id: ChainId,
    pub ibc_store_address: Address,
    pub ibc_commitments_slot: Hash,
    pub trusting_period: Duration,
    pub latest_height: Height,
    pub frozen: bool,
}
```

## ConsensusState

```rust
pub struct ConsensusState {
    /// the storage root of the IBC contract
    pub state_root: Hash,
    /// timestamp from execution payload
    pub timestamp: Time,
    /// finalized header's validator set
    /// only epoch headers contain validator set
    pub validators_hash: Hash,
}
```

## Headers

```rust
pub struct Header {
    /// target header and headers to finalize target header
    headers: ETHHeaders,
    trusted_height: Height,
    /// validator set in previous epoch of target header 
    previous_validators: ValidatorSet,
    /// validator set in current epoch of target header 
    /// if the target header is epoch this must be empty because the header's Extra field contains validator set
    current_validators: ValidatorSet,
}

pub struct ETHHeaders {
    /// target header
    pub target: ETHHeader,
    /// target header and headers to finalize target header
    /// first element is target header
    pub all: Vec<ETHHeader>,
}

pub struct ETHHeader {
    pub parent_hash: Vec<u8>,
    pub uncle_hash: Vec<u8>,
    pub coinbase: Vec<u8>,
    pub root: Hash,
    pub tx_hash: Vec<u8>,
    pub receipt_hash: Vec<u8>,
    pub bloom: Vec<u8>,
    pub difficulty: u64,
    pub number: BlockNumber,
    pub gas_limit: u64,
    pub gas_used: u64,
    pub timestamp: u64,
    pub extra_data: Vec<u8>,
    pub mix_digest: Vec<u8>,
    pub nonce: Vec<u8>,
    pub hash: Hash,
    /// true: if the block is epoch 
    pub is_epoch: bool,
    /// not empty only when the block is epoch
    pub new_validators: Validators,
}
```

## Misbehavior

```rust
pub struct Misbehaviour {
    pub client_id: ClientId,
    pub header_1: Header,
    pub header_2: Header,
}
```

## Client initialisation

```rust
fn create_client(
  client_id: ClientId, 
  client_state: ClientSate, 
  consensus_state: ConsensusState
)
```

ClientStateとConsensusStateを作成します。

## Update client

```rust
fn update_client(
  client_id: ClientId, 
  header: Header
) 
```

検証処理成功後
* 提出対象Headerのstorage root、timestamp、現epochのvalidator setをConsensusStateとして登録します。
* ClientStateのlatest_heightを更新します。

### <a name="update_client_state_validity"></a>ClientState validity predicate
* ClientIdに対応するClientStateが存在すること
* ClientStateがフリーズされていないこと
* 提出対象ヘッダのheightのrevisionとchainIdのversionが一致していること

### <a name="update_consensus_state_validity"></a>ConsensusState validity predicate
* ClientIdとHeaderのtrusted_heightに対応するConsensusStateが存在すること
* 提出対象Headerの現epochのvalidatorSetがConsensusStateに保存されていること
* 提出対象Headerの前epochのvalidatorSetがConsensusStateに保存されていること
* trusted_heightに対応するConsensusStateがtrusting_period期間内に作成されていること

### <a name="update_header_validity"></a>Header validity predicate
* 提出対象Headerが、trusted_heightに対応するConsensusStateのtrusting_period期間内に生成されたものであること
* 提出対象Headerのheightがtrusted_headerよりも高いこと
* 提出対象Headerがfinalizedされたとみなすために十分な数のHeaderが必要である。そのため、以下を満たすこと
  - チェックポイントより前のHeaderは前epochのvalidator setでsealされており重複がないこと
  - チェックポイント以降のHeaderは現epochのvalidator setでsealされており重複がないこと
  - sealされたHeader数の合計は、coinbaseの重複を除いて
    - 提出対象Headerがチェックポイント以降の場合には、「現epochのvalidator set数 * 1/2 + 1」以上であること
    - 提出対象Headerがチェックポイントより前の場合には、「前epochのvalidator set数 * 1/2 + 1」以上であること
* 提出対象Headerとその後続Headerの関係は以下を満たすこと
  - 提出対象のHeaderのblock numberが一番小さく、Header間のblock numberが連続していること
  - Header間のblock hashが連続していること
  - Header間のtimestampの大小関係が正しいこと
  - Header間のgas limitの差が上限以下であること

## Misbehavior predicate

```rust
pub fn submit_misbehaviour(
    client_id: ClientId,
    misbehaviour: Misbehavior,
) 
```

下記全ての検証成功後、ClientStateをフリーズします。

### ClientState validity predicate
* ClientIdに対応するClientStateが存在すること
* ClientStateがフリーズされていないこと
* header_1、header_2のrevisionとchainIdのversionが一致していること

### ConsensusState validity predicate
header_1とheader_2の双方に対して[Update clientのConsensusState validity predicate](#update_consensus_state_validity)と同じ検証結果となること

### Header validity predicate
* header_1とheader_2が同じ高さであること
* header_1とheader_2のblock hashが異なること
* header_1とheader_2の双方に対して[Update clientのHeader validity predicate](#update_header_validity)と同じ検証結果となること

## State verification

```rust
fn verify_membership(
    client_id: ClientId,
    path: String,
    value: Vec<u8>,
    proof_height: Height,
    proof: Vec<u8>,
)
```

以下の検証を行います。
* ClientIdに対応するClientStateが存在すること
* ClientStateがフリーズされていないこと
* ClientStateのlatest_heightがproof_heightと一致すること
* proof_heightに対応するConsensusStateのstorage_rootとproofで、pathに対してvalueが存在すること