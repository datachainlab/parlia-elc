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

# Target Height
このクライアントはBEP126 Fast Finality Mechanismを前提としています。そのため、29020050のブロックのみで利用可能です。

# Technical Specification

## ClientState

ClientStateは、現在のリビジョン、信頼期間、最新の高さ、およびフリーズの有無を追跡します。

```rust
pub struct ClientState {
    pub chain_id: ChainId,
    pub ibc_store_address: Address,
    pub ibc_commitments_slot: Hash,
    pub trusting_period: Duration,
    pub max_clock_drift: Duration,
    pub latest_height: Height,
    pub frozen: bool,
}
```

## ConsensusState

クライアントは、タイムスタンプ (ブロック時間)、次のバリデータセットのハッシュ、および以前に検証されたすべてのコンセンサス状態のコミットメントルートを追跡します。

```rust
pub struct ConsensusState {
    /// the storage root(commitment root) of the IBC contract
    pub state_root: Hash,
    /// timestamp of the Header
    pub timestamp: Time,
    /// finalized header's validator set
    /// only epoch headers contain validator set
    pub validators_hash: Hash
}
```

## Headers

Headerには、提出対象のHeaderとその親のHeader、アカウント証明、信頼できる高さ、検証に使うバリデータセットが含まれます。  

```rust
pub struct Header {
    /// target header
    target: ETHHeader,
    /// parent of the target header
    parent: ETHHeader,
    /// account proof for the ibc handler
    account_proof: Vec<u8>,
    trusted_height: Height,
    /// validator set for target 
    target_validators: Vec<Vec<u8>>,
    /// validator set for parent
    parent_validators: Vec<Vec<u8>>,
    /// previous epoch validator for target
    previous_target_validators: Vec<Vec<u8>>,
}
```

ETHHeaderはBSCオンチェーンで生成したブロックの情報が含まれます。

```rust
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
}
```

## Misbehavior

Misbehaviorは、該当する場合、不正動作を検出し、クライアントをフリーズしてさらなるパケットフローを防ぐために使用されます。  
Misbehaviorは、同じ高さの2つのヘッダーで構成されており、ライトクライアントはどちらも有効であるとみなします。

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
* 提出対象Header(Header.target)のheightに対してConsensusStateを作成し、提出対象Headerのtimestampとstorage rootと、epochの場合にはvalidatorSetのhashを登録します。
* ClientStateのlatest_heightを更新します。

### <a name="update_client_state_validity"></a>ClientState validity predicate
* ClientIdに対応するClientStateが存在すること
* ClientStateがフリーズされていないこと
* 提出対象ヘッダのheightのrevisionとchainIdのversionが一致していること

### <a name="update_consensus_state_validity"></a>ConsensusState validity predicate
* ClientIdとHeaderのtrusted_heightに対応するConsensusStateが存在すること
* 提出対象Headerの検証用のvalidatorSetがConsensusStateに保存されていること
* 親Header(Header.parent)の検証用のvalidatorSetがConsensusStateに保存されていること
* trusted_heightに対応するConsensusStateがtrusting_period期間内に作成されていること

### <a name="update_header_validity"></a>Header validity predicate
* 提出対象Headerが、trusted_heightに対応するConsensusStateのtrusting_period期間内に生成されたものであること
* 提出対象Headerのheightがtrusted_headerよりも高いこと
* 提出対象Headerと親Headerの関係が正しいこと
  - numberとblock hashが連続していること
  - timestampの大小関係が正しいこと
  - gas limitの差が上限以下であること
  - extra_dataから抽出したVoteAttesationの関係が正しいこと
* 提出対象Headerと親Headerの署名とBLS署名が正しいこと

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
* ClientStateのlatest_height >= proof_heightであること
* proof_heightに対応するConsensusStateのstorage_rootとproofで、pathに対してvalueが存在すること

```rust
fn verify_non_membership(
    client_id: ClientId,
    path: String,
    proof_height: Height,
    proof: Vec<u8>,
)
```

以下の検証を行います。
* ClientIdに対応するClientStateが存在すること
* ClientStateがフリーズされていないこと
* ClientStateのlatest_height >= proof_heightであること
* proof_heightに対応するConsensusStateのstorage_rootとproofで、pathに対して値が存在しないこと