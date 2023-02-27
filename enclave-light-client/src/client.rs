use crate::errors::Error;
use alloc::boxed::Box;

use alloc::string::String;
use alloc::vec::Vec;
use commitments::{gen_state_id_from_any, StateCommitment, StateID, UpdateClientCommitment};
use crypto::Keccak256;
use ibc::core::ics02_client::error::{ClientError as ICS02Error, ClientError};

use ibc::core::ics02_client::client_state::ClientState as _;

use alloc::str::FromStr;
use ibc::core::ics02_client::consensus_state::ConsensusState as _;
use ibc::core::ics02_client::header::Header as _;

use ibc::core::ics23_commitment::commitment::CommitmentPrefix;
use ibc::core::ics24_host::identifier::ClientId;
use ibc::core::ics24_host::Path;

use ibc_proto::google::protobuf::Any as IBCAny;
use lcp_types::{Any, Height};
use light_client::{
    ClientReader, CreateClientResult, Error as LightClientError, LightClient,
    StateVerificationResult, UpdateClientResult,
};
use light_client_registry::LightClientRegistry;
use parlia_ibc_lc::client_def::ParliaClient;
use parlia_ibc_lc::client_state::{ClientState, PARLIA_CLIENT_STATE_TYPE_URL};
use parlia_ibc_lc::client_type::CLIENT_TYPE;
use parlia_ibc_lc::consensus_state::ConsensusState;
use parlia_ibc_lc::header::Header;
use parlia_ibc_lc::misc::{ValidatorReader, Validators};
use validation_context::ValidationParams;

#[derive(Default)]
pub struct ParliaLightClient(ParliaClient);

pub fn register_implementations(registry: &mut dyn LightClientRegistry) {
    registry
        .put_light_client(
            String::from(PARLIA_CLIENT_STATE_TYPE_URL),
            Box::new(ParliaLightClient(ParliaClient)),
        )
        .unwrap()
}

impl LightClient for ParliaLightClient {
    fn client_type(&self) -> String {
        String::from(CLIENT_TYPE)
    }

    fn latest_height(
        &self,
        ctx: &dyn ClientReader,
        client_id: &ClientId,
    ) -> Result<Height, LightClientError> {
        let any_client_state = read_client_state(ctx, client_id)?;
        let client_state: ClientState = try_from_any(any_client_state)?;
        Ok(client_state.latest_height().into())
    }

    fn create_client(
        &self,
        _ctx: &dyn ClientReader,
        any_client_state: Any,
        any_consensus_state: Any,
    ) -> Result<CreateClientResult, LightClientError> {
        let new_state_id = state_id(&any_client_state, &any_consensus_state)?;
        let client_state: ClientState = try_from_any(any_client_state.clone())?;
        let consensus_state: ConsensusState = try_from_any(any_consensus_state)?;

        let height = client_state.latest_height().into();
        let timestamp = consensus_state.timestamp().into();

        Ok(CreateClientResult {
            height,
            commitment: UpdateClientCommitment {
                prev_state_id: None,
                new_state_id,
                new_state: Some(any_client_state),
                prev_height: None,
                new_height: height,
                timestamp,
                validation_params: ValidationParams::Empty,
            },
            prove: false,
        })
    }

    fn update_client(
        &self,
        ctx: &dyn ClientReader,
        client_id: ClientId,
        any_header: Any,
    ) -> Result<UpdateClientResult, LightClientError> {
        //Ensure header can be verified.
        let header: Header = try_from_any(any_header)?;

        let trusted_height = header.trusted_height();
        let any_client_state = read_client_state(ctx, &client_id)?;
        let any_consensus_state = read_consensus_state(ctx, &client_id, trusted_height.into())?;
        let prev_state_id = state_id(&any_client_state, &any_consensus_state)?;

        //Ensure client is not frozen
        let client_state: ClientState = try_from_any(any_client_state)?;
        if client_state.is_frozen() {
            return Err(LightClientError::ics02(ICS02Error::ClientFrozen {
                client_id,
            }));
        }

        // Create new state and ensure header is valid
        let consensus_state: ConsensusState = try_from_any(any_consensus_state)?;
        let (new_client_state, new_consensus_state) =
            self.verify_header(ctx, &client_id, &client_state, &consensus_state, &header)?;

        let new_height = new_client_state.latest_height.into();
        let new_any_client_state = into_any(new_client_state);
        let new_any_consensus_state = into_any(new_consensus_state);
        let new_state_id = state_id(&new_any_client_state, &new_any_consensus_state)?;

        Ok(UpdateClientResult {
            new_any_client_state,
            new_any_consensus_state,
            height: header.height().into(),
            commitment: UpdateClientCommitment {
                prev_state_id: Some(prev_state_id),
                new_state_id,
                new_state: None,
                prev_height: Some(header.trusted_height().into()),
                new_height,
                timestamp: header.timestamp().into(),
                validation_params: ValidationParams::Empty,
            },
            prove: true,
        })
    }

    fn verify_membership(
        &self,
        ctx: &dyn ClientReader,
        client_id: ClientId,
        prefix: Vec<u8>,
        path: String,
        value: Vec<u8>,
        proof_height: Height,
        proof: Vec<u8>,
    ) -> Result<StateVerificationResult, LightClientError> {
        self.verify_proof(
            ctx,
            client_id,
            prefix,
            path,
            Some(value),
            proof_height,
            proof,
        )
    }

    fn verify_non_membership(
        &self,
        ctx: &dyn ClientReader,
        client_id: ClientId,
        prefix: Vec<u8>,
        path: String,
        proof_height: Height,
        proof: Vec<u8>,
    ) -> Result<StateVerificationResult, LightClientError> {
        self.verify_proof(ctx, client_id, prefix, path, None, proof_height, proof)
    }
}

impl ParliaLightClient {
    fn verify_header(
        &self,
        ctx: &dyn ClientReader,
        client_id: &ClientId,
        client_state: &ClientState,
        consensus_state: &ConsensusState,
        header: &Header,
    ) -> Result<(ClientState, ConsensusState), Error> {
        let now = ctx.host_timestamp();
        let ctx = DefaultValidatorReader { ctx, client_id };
        self.0
            .check_header_and_update_state(ctx, now, client_state, consensus_state, header)
            .map_err(Error::ParliaIBCLC)
    }

    #[allow(clippy::too_many_arguments)]
    fn verify_proof(
        &self,
        ctx: &dyn ClientReader,
        client_id: ClientId,
        prefix: Vec<u8>,
        path: String,
        value: Option<Vec<u8>>,
        proof_height: Height,
        proof: Vec<u8>,
    ) -> Result<StateVerificationResult, LightClientError> {
        let any_client_state = read_client_state(ctx, &client_id)?;
        let client_state: ClientState = try_from_any(any_client_state.clone())?;
        if client_state.is_frozen() {
            return Err(LightClientError::ics02(ICS02Error::ClientFrozen {
                client_id,
            }));
        }
        if Height::from(client_state.latest_height()) == proof_height {
            return Err(Error::UnexpectedHeight(proof_height).into());
        }

        let any_consensus_state = read_consensus_state(ctx, &client_id, proof_height)?;

        let (commitment_prefix, commitment_path) = apply_prefix(prefix, &path)?;
        let consensus_state: ConsensusState = try_from_any(any_consensus_state.clone())?;
        let state_root = &consensus_state.state_root().map_err(Error::ParliaIBCLC)?;
        let path = path.as_bytes().keccak256();
        self.0
            .verify_proof(state_root, &proof, &path, &value)
            .map_err(Error::ParliaIBCLC)?;

        let state_id = state_id(&any_client_state, &any_consensus_state)?;

        Ok(StateVerificationResult {
            state_commitment: StateCommitment::new(
                commitment_prefix,
                commitment_path,
                value.map(|e| e.keccak256()),
                proof_height,
                state_id,
            ),
        })
    }
}

fn state_id(client_state: &Any, consensus_state: &Any) -> Result<StateID, LightClientError> {
    gen_state_id_from_any(client_state, consensus_state).map_err(LightClientError::commitment)
}

fn read_client_state(
    ctx: &dyn ClientReader,
    client_id: &ClientId,
) -> Result<Any, LightClientError> {
    ctx.client_state(client_id).map_err(LightClientError::ics02)
}

fn read_consensus_state(
    ctx: &dyn ClientReader,
    client_id: &ClientId,
    height: Height,
) -> Result<Any, LightClientError> {
    ctx.consensus_state(client_id, height)
        .map_err(LightClientError::ics02)
}

fn try_from_any<T: TryFrom<IBCAny, Error = ClientError>>(any: Any) -> Result<T, LightClientError> {
    let any: IBCAny = any.into();
    any.try_into().map_err(LightClientError::ics02)
}

fn into_any<T: Into<IBCAny>>(src: T) -> Any {
    let any: IBCAny = src.into();
    any.into()
}

fn apply_prefix(prefix: Vec<u8>, path: &str) -> Result<(CommitmentPrefix, Path), Error> {
    let prefix = prefix.try_into().map_err(Error::ICS23)?;
    //TODO apply prefix if needed
    let path = Path::from_str(path).map_err(Error::Path)?;
    Ok((prefix, path))
}

struct DefaultValidatorReader<'a> {
    ctx: &'a dyn ClientReader,
    client_id: &'a ClientId,
}

impl<'a> ValidatorReader for DefaultValidatorReader<'a> {
    fn read(&self, ibc_height: ibc::Height) -> Result<Validators, parlia_ibc_lc::errors::Error> {
        let height = Height::new(ibc_height.revision_number(), ibc_height.revision_height());
        let consensus_state = self
            .ctx
            .consensus_state(self.client_id, height)
            .map_err(parlia_ibc_lc::errors::Error::ICS02Error)?;
        let consensus_state: ConsensusState = try_from_any(consensus_state)
            .map_err(|_e| parlia_ibc_lc::errors::Error::UnexpectedAnyConsensusState(ibc_height))?;
        Ok(consensus_state.validator_set)
    }
}
