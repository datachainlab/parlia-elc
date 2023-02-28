use alloc::boxed::Box;
use alloc::vec::Vec;
use core::time::Duration;
use ibc::core::ics02_client::client_state::ClientState as IBCClientState;
use ibc::core::ics02_client::error::ClientError;
use ibc::core::ics03_connection::error::ConnectionError;
use ibc::core::ics04_channel::channel::ChannelEnd;
use ibc::core::ics04_channel::commitment::{AcknowledgementCommitment, PacketCommitment};
use ibc::core::ics04_channel::packet::{Receipt, Sequence};
use ibc::core::ics23_commitment::commitment::CommitmentPrefix;
use ibc::core::ics24_host::identifier::{ChannelId, ClientId, ConnectionId, PortId};
use ibc::core::ics24_host::path::{
    AckPath, ChannelEndPath, ClientConsensusStatePath, CommitmentPath, ReceiptPath, SeqAckPath,
    SeqRecvPath, SeqSendPath,
};
use ibc::core::ics26_routing::context::{Module, ModuleId};
use ibc::core::ContextError;
use ibc::core::{
    context::Router, ics02_client::consensus_state::ConsensusState as IBCConsensusState,
    ValidationContext,
};
use ibc::core::ics03_connection::connection::ConnectionEnd;
use ibc_proto::google::protobuf::Any as IBCAny;
use lcp_types::{Any, Height};
use light_client::ClientReader;
use parlia_ibc_lc::client_state::ClientState;
use parlia_ibc_lc::consensus_state::ConsensusState;
use parlia_ibc_lc::errors::Error;

pub struct Context<'a> {
    parent: &'a dyn ClientReader,
}

impl<'a> Context<'a> {
    pub fn new(parent: &'a dyn ClientReader) -> Self {
        Self { parent }
    }
}

#[allow(unused_variables)]
impl<'a> ValidationContext for Context<'a> {
    fn client_state(
        &self,
        client_id: &ClientId,
    ) -> Result<Box<dyn IBCClientState<Error = ClientError>>, ContextError> {
        let client_state: IBCAny = self.parent.client_state(client_id)?.into();
        let client_state = ClientState::try_from(client_state)?;
        Ok(Box::new(client_state))
    }

    fn decode_client_state(
        &self,
        client_state: IBCAny,
    ) -> Result<Box<dyn IBCClientState<Error = ClientError>>, ContextError> {
        let client_state = ClientState::try_from(client_state)?;
        Ok(Box::new(client_state))
    }

    fn consensus_state(
        &self,
        client_cons_state_path: &ClientConsensusStatePath,
    ) -> Result<Box<dyn IBCConsensusState<Error = ClientError>>, ContextError> {
        let height = Height::new(client_cons_state_path.epoch, client_cons_state_path.height);
        let consensus_state : IBCAny = self
            .parent
            .consensus_state(&client_cons_state_path.client_id, height)?.into();
        let consensus_state = ConsensusState::try_from(consensus_state)?;
        Ok(Box::new(consensus_state))
    }

    fn next_consensus_state(
        &self,
        client_id: &ClientId,
        height: &ibc::Height,
    ) -> Result<Option<Box<dyn IBCConsensusState<Error = ClientError>>>, ContextError> {
        Ok(None)
    }

    fn prev_consensus_state(
        &self,
        client_id: &ClientId,
        height: &ibc::Height,
    ) -> Result<Option<Box<dyn IBCConsensusState<Error = ClientError>>>, ContextError> {
        Ok(None)
    }

    fn host_height(&self) -> Result<ibc::Height, ContextError> {
        let height = self.parent.host_height();
        let height = ibc::Height::new(height.revision_number(), height.revision_height())?;
        Ok(height)
    }

    fn host_timestamp(&self) -> Result<ibc::timestamp::Timestamp, ContextError> {
        Ok(self.parent.host_timestamp())
    }

    fn host_consensus_state(
        &self,
        height: &ibc::Height,
    ) -> Result<Box<dyn IBCConsensusState<Error = ClientError>>, ContextError> {
        unimplemented!()
    }

    fn client_counter(&self) -> Result<u64, ContextError> {
        Ok(self.parent.client_counter()?)
    }

    fn connection_end(&self, conn_id: &ConnectionId) -> Result<ConnectionEnd, ContextError> {
        unimplemented!()
    }

    fn validate_self_client(
        &self,
        client_state_of_host_on_counterparty: IBCAny,
    ) -> Result<(), ConnectionError> {
        unimplemented!()
    }

    fn commitment_prefix(&self) -> CommitmentPrefix {
        unimplemented!()
    }

    fn connection_counter(&self) -> Result<u64, ContextError> {
        unimplemented!()
    }

    fn channel_end(&self, channel_end_path: &ChannelEndPath) -> Result<ChannelEnd, ContextError> {
        unimplemented!()
    }

    fn connection_channels(
        &self,
        cid: &ConnectionId,
    ) -> Result<alloc::vec::Vec<(PortId, ChannelId)>, ContextError> {
        unimplemented!()
    }

    fn get_next_sequence_send(
        &self,
        seq_send_path: &SeqSendPath,
    ) -> Result<Sequence, ContextError> {
        unimplemented!()
    }

    fn get_next_sequence_recv(
        &self,
        seq_recv_path: &SeqRecvPath,
    ) -> Result<Sequence, ContextError> {
        unimplemented!()
    }

    fn get_next_sequence_ack(&self, seq_ack_path: &SeqAckPath) -> Result<Sequence, ContextError> {
        unimplemented!()
    }

    fn get_packet_commitment(
        &self,
        commitment_path: &CommitmentPath,
    ) -> Result<PacketCommitment, ContextError> {
        unimplemented!()
    }

    fn get_packet_receipt(&self, receipt_path: &ReceiptPath) -> Result<Receipt, ContextError> {
        unimplemented!()
    }

    fn get_packet_acknowledgement(
        &self,
        ack_path: &AckPath,
    ) -> Result<AcknowledgementCommitment, ContextError> {
        unimplemented!()
    }

    fn hash(&self, value: &[u8]) -> Vec<u8> {
        unimplemented!()
    }

    fn client_update_time(
        &self,
        client_id: &ClientId,
        height: &ibc::Height,
    ) -> Result<ibc::timestamp::Timestamp, ContextError> {
        unimplemented!()
    }

    fn client_update_height(
        &self,
        client_id: &ClientId,
        height: &ibc::Height,
    ) -> Result<ibc::Height, ContextError> {
        unimplemented!()
    }

    fn channel_counter(&self) -> Result<u64, ContextError> {
        unimplemented!()
    }

    fn max_expected_time_per_block(&self) -> Duration {
        unimplemented!()
    }
}

#[allow(unused_variables)]
impl<'a> Router for Context<'a> {
    fn get_route(&self, module_id: &ModuleId) -> Option<&dyn Module> {
        unimplemented!()
    }

    fn get_route_mut(&mut self, module_id: &ModuleId) -> Option<&mut dyn Module> {
        unimplemented!()
    }

    fn has_route(&self, module_id: &ModuleId) -> bool {
        unimplemented!()
    }

    fn lookup_module_by_port(&self, port_id: &PortId) -> Option<ModuleId> {
        unimplemented!()
    }
}
