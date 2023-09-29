# Parlia Light Client

This specification document describes a client (verification algorithm) for a blockchain using Parlia consensus with a fast finality mechanism.

# About Parlia

Parlia is a consensus proposed by BNB Smart Chain(BSC), combining DPoS and PoA:
- Blocks are produced by a limited set of validators
- Validators take turns to produce blocks in a PoA manner, similar to Ethereum's Clique consensus design
- Validator set are elected in and out based on a staking based governance
- Every epoch block, a validator will query the validator set and fill it in the extra_data field of the block header

Ref. https://docs.bnbchain.org/docs/learn/consensus

## Target Environment

This client spec assumes that [BEP-126](https://github.com/bnb-chain/BEPs/blob/bfe4fdb90b732af2e25c9581c5e5391aa00c8246/BEPs/BEP126.md) is valid and activated on the target blockchain.
It introduces a fast finality mechanism to finalize a block.

# Technical Specification

We have borrowed the basic terms from [ICS-02](https://github.com/cosmos/ibc/tree/main/spec/core/ics-002-client-semantics).

## Client state

The Parlia client state tracks the current revision, the IBC store address, the trusting period, the latest height, and the freeze status.
The IBC store address refers to the contract that stores the commitments.

```typescript
interface ClientState {
    chainId: string,
    ibcStoreAddress: Address,
    ibcCommitmentsSlot: []byte,
    trustingPeriod: uint64,
    maxClockDrift: uin64,
    latestHeight: Height,
    frozen: bool
}
```

## Consensus state

The Parlia client tracks the timestamp (block time), the hashes of the validator sets for the current and previous epochs, and the commitment root for all previously verified consensus states.
The commitment root is a storage root of the account corresponding to the IBC store address in the client state.

```typescript
interface ConsensusState {
    // the storage root(commitment root) of the IBC contract
    stateRoot: []byte,
    timestamp: uint64,
    // the hash of the current epoch validator set
    currentValidatorsHash: []byte,
    // the hash of the previous epoch validator set
    previousValidatorsHash: []byte
}
```

## Height

The height of a Parlia client consists of two `uint64`s: the revision number, and the height in the revision.

```typescript
interface Height {
    revisionNumber: uint64
    revisionNumber: uint64
}
```

Comparison between heights is implemented as follows:

```typescript
function compare(a: Height, b: Height): Ord {
    if (a.revisionNumber < b.revisionNumber)
        return LT
    else if (a.revisionNumber === b.revisionNumber)
        if (a.revisionHeight < b.revisionHeight)
            return LT
        else if (a.revisionHeight === b.revisionHeight)
            return EQ
    return GT
}
```

## Headers

The Header submitted to the on-chain client includes the target header for submission, the descendant headers for finality verification, account proofs, a trusted height, and the validator sets for verification.

The validator sets pertain to the "current" and the "previous" epoch, as seen from the target header.
Each element in the validator set contains a validator's address and its BLS public key.

```typescript
type ETHHeaders = List<ETHHeader>
type Validtors = List<[]byte>

interface Header {
    accountProof: []byte,
    headers: ETHHeaders,
    trustedHeight: Height,
    currentValidators: Validators,
    previousValidators: Validators,
}

function (Header) getHeight(): Height {
    return Height{0, self.headers[0].number}
}

function (Header) getTimestamp(): uint64 {
    return self.headers[0].timestamp
}

function (Header) getHash(): []byte {
    return hash(rlp(self.headers[0]))
}

function (Header) stateRoot(): []byte {
    return self.headers[0].root
}
```

ETHHeader contains information from block headers.

```typescript
interface ETHHeader {
    parentHash: []byte,
    uncleHash: []byte,
    coinbase: []byte,
    root: []byte,
    txHash: []byte,
    receiptHash: []byte,
    bloom: []byte,
    difficulty: uint64,
    number: uint64,
    gasLimit: uint64,
    gasUsed: uint64,
    timestamp: uint64,
    extraData: []byte,
    mixDigest: []byte,
    nonce: []byte,
    baseFee: Maybe<uint64>
}
```

## Misbehavior

The `Misbehaviour` type is used for detecting misbehaviour and freezing the client - to prevent further packet flow - if applicable. Parlia client `Misbehaviour` consists of two headers at the same height both of which the light client would have considered valid.

```typescript
interface Misbehaviour {
    clientId: string,
    header1: Header,
    header2: Header,
}
```

## Client initialisation

The Parlia client initialization requires a (subjectively chosen) latest consensus state, including the validator sets.

```typescript
function createClient(
    clientId: string,
    clientState: ClientSate,
    consensusState: ConsensusState
) {
    assert(clientState.height > 0)
    setClientState(clientState, clientId)
    setConsensusState(consensusState, clientId, height)
}
```

## Validity Predicate

The Parlia client validity checking uses specs described in the [Parlia Consensus](https://docs.bnbchain.org/docs/learn/consensus) and [BEP-126](https://github.com/bnb-chain/BEPs/blob/bfe4fdb90b732af2e25c9581c5e5391aa00c8246/BEPs/BEP126.md).
If the provided header is valid, the client state is updated, and the newly verified storage root, the hashes of the validator sets written to the store.

```typescript
function verifyHeader(
    clientId: string,
    header: Header
) {
    clientState = getClientState(clientId)
    trustedConsensusState = getConsensusState(header.trustedHeight)

    // assert trusting period has not yet passed
    assert(currentTimestamp() - trustedConsensusState.timestamp < clientState.trustingPeriod)
    // assert header timestamp is past latest stored consensus state timestamp
    assert(header.getTimestamp() < currentTimestamp() + clientState.max_clock_drift)
    // trusted height revision must be the same as header revision
    // trusted height must be less than header height
    assert(header.getHeight().revisionNumber == header.trustedHeight.revisionNumber)
    assert(header.getHeight().revisionHeight > header.trustedHeight.revisionHeight)

    // assert header validator sets are valid
    if header.getHeight() % BLOCK_PER_EPOCH == 0 {
        // extractValidtors gets the validator set of the epoch from 'extraData' of the epoch ETHHeader
        assert(hash(header.currentValidators)) == hash(extractValidators(header.headers[0])))
        assert(hash(header.previousValidators)) == trustedConsensusState.currentValidatorsHash)
    } else {
        assert(hash(header.currentValidators) == trustedConsensusState.currentValidatorsHash)
        assert(hash(header.previousValidators) == trustedConsensusState.previousValidatorsHash)
    }

    // verifies all the header fields that are not standalone,
    // rather depend on a batch of previous header:
    // - The number and block hash are consecutive.
    // - The timestamp order is correct.
    // - The difference in gas limit is within the upper limit.
    assert(verifyCascadingFields(header.headers))

    assert(verifySeals(header.headers, header.currentValidators, header.previousValidators))

    // verifies the header adheres to the BEP126 finality rule.
    // Ref. https://github.com/bnb-chain/BEPs/blob/master/BEPs/BEP126.md#413-finality-rules
    assert(verifyFinalized(header.headers, header.currentValidators, header.previousValidators))
}

function verifySeals(
    headers: ETHHeaders,
    currentValidators: Validators,
    previousValidators: Validators
) {
    chainId = getChainId()
    epoch = headers[0].number / BLOCK_PER_EPOCH
    // Validator set changes take place at the (epoch+N/2) blocks. (N is the size of validatorset before epoch block)
    checkpoint = epoch * BLOCK_PER_EPOCH + checkpoint(previousValidators)
    for header in headers {
        // verifySeal checks whether the signature contained in the header satisfies the consensus protocol requirements
        if header.number >= checkpoint {
            verifySeal(header, currentValidators, chainId)
        } else {
            verifySeal(header, previousValidators, chainId)
        }
    }
}
```

Primary verification according to BEP-126's finality rule involves:
- Ensuring the correctness of the BLS signature.
- Verifying the relationships of the VoteAttestation:
  - The `target` of the direct child header should match the submitted header.
  - The `source` of the direct grandchild header should match the submitted header.
  - The `target` of the direct grandchild header should match the direct child header.

However, there may be cases where the VoteAttestation cannot directly determine the finality of the submitted header.
In such cases, a valid descendant header is verified, which is included in the `headers` and can directly confirm its finality through VoteAttestation.

## Misbehavior predicate

The predicate will check if a submission contains evidence of Misbehavior.
If there are two different valid headers for the same height, the client will be frozen, preventing any further state updates.

```typescript
function submitMisbehaviour(
    clientId: ClientId,
    misbehaviour: Misbehavior
): ClientState {
    // assert heights are equal
    assert(misbehaviour.header1.getHeight() == misbehaviour.header2.getHeight())
    // assert target headers are different
    assert(misbehaviour.header1.getHash() != misbehaviour.header2.getHash())

    // assert each header is valid
    verifyHeader(clientId, misbehaviour.header1)
    verifyHeader(clientId, misbehaviour.header2)

    clientState = getClientState(clientId)
    clientState.frozen = true
    return clientState
}
```

## Update state

The function will perform a regular update for the Parlia client.
It will add a consensus state to the client store.
If the header is higher than the latest height on the client state, then the client state will be updated.

```typescript
function updateState(
    clientState: ClientState,
    header: Header) {
    newClientState = clientState.clone()
    if newClientState.latestHeight < header.getHeight() {
        newClientState.latestHeight = header.getHeight()
    }

    newStateRoot = resolve(header.stateRoot(), header.accountProof, clientState.ibcStoreAddress)

    newConsensusState = ConsensusState{
        newStateRoot,
        header.timestamp(),
        hash(header.currentValidators),
        hash(header.previousValidators)
    }

    setClientState(newClientState, clientId)
    setConsensusState(newConsensusState, clientId, header.getHeight())
}
```

## State verification functions

Parlia client state verification functions check a Merkle proof against a previously validated commitment root.

The Merkle proof is based on [Merkle Patricia Trie in Ethereum](https://eth.wiki/en/fundamentals/patricia-tree#main-specification-merkle-patricia-trie).

```typescript
function verifyMembership(
    clientState: ClientState,
    height: Height,
    proof: []byte,
    path: String,
    value: []byte
) {
    // check that the client is at a sufficient height
    assert(clientState.latestHeight >= height)
    // check that the client is unfrozen
    assert(!clientState.frozen)
    // fetch the previously verified commitment root & verify membership
    consensusState = getConsensusState(height)
    // verify that <path, value> has been stored
    assert(verifyMembership(consensusState.stateRoot, proof, path, value))
}

function verifyNonMembership(
    clientState: ClientState,
    height: Height,
    proof: []byte,
    path: String,
) {
    // check that the client is at a sufficient height
    assert(clientState.latestHeight >= height)
    // check that the client is unfrozen
    assert(!clientState.frozen)
    // fetch the previously verified commitment root & verify membership
    consensusState = getConsensusState(height)
    // verify that nothing has been stored
    assert(verifyNonMembership(consensusState.stateRoot, proof, path))
}
```
