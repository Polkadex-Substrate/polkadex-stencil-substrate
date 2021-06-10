// Copyright (C) 2020-2021 Polkadex OU
// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

// This is file is modified from beefy-gadget from Parity Technologies (UK) Ltd.
use std::{
    convert::{TryFrom, TryInto},
    fmt::Debug,
    marker::PhantomData,
    sync::Arc,
};

use codec::{Codec, Decode, Encode};
use curv::elliptic::curves::secp256_k1::GE;
use futures::{future, FutureExt, StreamExt};
use hex::ToHex;
use log::{debug, error, trace, warn};
use parking_lot::Mutex;
use round_based::{IsCritical, Msg, StateMachine};
use sc_client_api::{Backend, FinalityNotification, FinalityNotifications};
use sc_network_gossip::GossipEngine;
use sp_api::BlockId;
use sp_application_crypto::{AppPublic, Public};
use sp_arithmetic::traits::AtLeast32Bit;
use sp_core::Pair;
use sp_keystore::{SyncCryptoStore, SyncCryptoStorePtr};
use sp_runtime::{
    generic::OpaqueDigestItemId,
    SaturatedConversion,
    traits::{Block, Header, NumberFor},
};

use thea_primitives::{
    ConsensusLog, GENESIS_AUTHORITY_SET_ID, KEY_TYPE, THEA_ENGINE_ID, TheaApi, ValidatorSet,
};

use crate::{
    Client,
    gossip::{TheaGossipValidator, topic}, metric_inc,
    metric_set,
    metrics::Metrics,
    mpc::ProtocolMessage, round,
};
use crate::mpc::Keygen;

pub(crate) struct WorkerParams<B, P, BE, C>
    where
        B: Block,
        P: sp_core::Pair,
        P::Signature: Clone + Codec + Debug + PartialEq + TryFrom<Vec<u8>>,
{
    pub client: Arc<C>,
    pub backend: Arc<BE>,
    pub key_store: Option<SyncCryptoStorePtr>,
    pub gossip_engine: GossipEngine<B>,
    pub gossip_validator: Arc<TheaGossipValidator<B, P>>,
    pub party_idx: usize,
    pub threshold: usize,
    pub party_count: usize,
    pub metrics: Option<Metrics>,
}

/// A THEA worker plays the BEEFY protocol
pub(crate) struct TheaWorker<B, C, BE, P>
    where
        B: Block,
        BE: Backend<B>,
        P: Pair,
        P::Public: AppPublic + Codec,
        P::Signature: Clone + Codec + Debug + PartialEq + TryFrom<Vec<u8>>,
        C: Client<B, BE, P>,
{
    client: Arc<C>,
    backend: Arc<BE>,
    key_store: Option<SyncCryptoStorePtr>,
    gossip_engine: Arc<Mutex<GossipEngine<B>>>,
    gossip_validator: Arc<TheaGossipValidator<B, P>>,
    /// Index of this worker
    party_idx: usize,
    /// Threshold of the protocol for signing
    threshold: usize,
    /// Total number of parties
    party_count: usize,
    metrics: Option<Metrics>,
    rounds: round::Rounds<NumberFor<B>, P::Public, P::Signature>,
    finality_notifications: FinalityNotifications<B>,
    /// Best block we received a GRANDPA notification for
    best_grandpa_block: NumberFor<B>,
    last_thea_round: Option<NumberFor<B>>,
    /// Validator set id for the last signed commitment
    last_signed_id: u64,
    /// Local party instance of t-ECDSA
    local_party: Option<Keygen>,
    /// Status of the protocol
    protocol_status: bool,
    /// Public Key of the system
    public_key: Option<GE>,
    // keep rustc happy
    _backend: PhantomData<BE>,
    _pair: PhantomData<P>,
}

impl<B, C, BE, P> TheaWorker<B, C, BE, P>
    where
        B: Block,
        BE: Backend<B>,
        P: Pair,
        P::Public: AppPublic,
        P::Signature: Clone + Codec + Debug + PartialEq + TryFrom<Vec<u8>>,
        C: Client<B, BE, P>,
        C::Api: TheaApi<B, P::Public>,
{
    /// Return a new Thea worker instance.
    ///
    /// Note that a Thea worker is only fully functional if a corresponding
    /// Thea pallet has been deployed on-chain.
    ///
    /// The Thea pallet is needed in order to keep track of the Thea authority set.
    pub(crate) fn new(worker_params: WorkerParams<B, P, BE, C>) -> Self {
        let WorkerParams {
            client,
            backend,
            key_store,
            gossip_engine,
            gossip_validator,
            party_idx,
            threshold,
            party_count,
            metrics,
        } = worker_params;

        TheaWorker {
            client: client.clone(),
            backend,
            key_store,
            gossip_engine: Arc::new(Mutex::new(gossip_engine)),
            gossip_validator,
            party_idx,
            threshold,
            party_count,
            metrics,
            rounds: round::Rounds::new(ValidatorSet::empty()),
            finality_notifications: client.finality_notification_stream(),
            best_grandpa_block: client.info().finalized_number,
            last_thea_round: None,
            last_signed_id: 0,
            local_party: None,
            protocol_status: false,
            public_key: None,
            _backend: PhantomData,
            _pair: PhantomData,
        }
    }
}

impl<B, C, BE, P> TheaWorker<B, C, BE, P>
    where
        B: Block,
        BE: Backend<B>,
        P: Pair,
        P::Public: AppPublic,
        P::Signature: Clone + Codec + Debug + PartialEq + TryFrom<Vec<u8>>,
        C: Client<B, BE, P>,
        C::Api: TheaApi<B, P::Public>,
{
    // TODO: Implement the threshold ecdsa logic here
    fn set_status(&mut self, status: bool) {
        self.protocol_status = status
    }

    fn set_public_key(&mut self, public_key: GE) {
        self.public_key = Some(public_key)
    }

    /// Return the current active validator set at header `header`.
    ///
    /// Note that the validator set could be `None`. This is the case if we don't find
    /// a THEA authority set change and we can't fetch the authority set from the
    /// THEA on-chain state.
    ///
    /// Such a failure is usually an indication that the THEA pallet has not been deployed (yet).
    fn validator_set(&self, header: &B::Header) -> Option<ValidatorSet<P::Public>> {
        if let Some(new) = find_authorities_change::<B, P::Public>(header) {
            Some(new)
        } else {
            let at = BlockId::hash(header.hash());
            self.client.runtime_api().validator_set(&at).ok()
        }
    }

    /// It queries on-chain storage to check whether we can start the protocol or not
    fn can_start(&self, header: &B::Header) -> bool {
        let at = BlockId::Hash(header.hash());
        if let Some(can_start) = self.client.runtime_api().can_start(&at).ok() {
            can_start
        } else {
            error!(target: "thea", "call to runtime for checking can_start failed");
            false
        }
    }

    /// Return the local authority id.
    ///
    /// `None` is returned, if we are not permitted to participate
    fn local_id(&self) -> Option<P::Public> {
        let key_store = self.key_store.clone()?;

        self.rounds
            .validators()
            .iter()
            .find(|id| SyncCryptoStore::has_keys(&*key_store, &[(id.to_raw_vec(), KEY_TYPE)]))
            .cloned()
    }

    pub fn handle_finality_notification(&mut self, notification: FinalityNotification<B>) {
        trace!(target: "thea", "🥩 Got New Finality notification: {:?}", notification.header.number());

        // update best GRANDPA finalized block we have seen
        self.best_grandpa_block = *notification.header.number();

        if !self.can_start(&notification.header) {
            warn!(target: "thea", "Thea Protocol is paused, flag not set on-chain");
            return;
        }

        if self.local_id().is_none() {
            warn!(target: "thea", "Thea Authority Key is not configured in this node");
            return;
        }
        if self.local_party.is_some() {
            debug!(target: "thea", "Local Party Status {:?}", self.local_party.as_ref().unwrap());
        }
        if let Some(public_key) = self.public_key {
            trace!(target: "thea", "Protocol Completed ==> t-ECDSA Public key: {:?}", public_key)
        }

        if let Some(active) = self.validator_set(&notification.header) {
            // Authority set change or genesis set id triggers new voting rounds
            //
            // TODO: (adoerr) Enacting a new authority set will also implicitly 'conclude'
            // the currently active BEEFY voting round by starting a new one. This is
            // temporary and needs to be replaced by proper round life cycle handling.
            if active.id != self.rounds.validator_set_id()
                || ((active.id == GENESIS_AUTHORITY_SET_ID && self.last_thea_round.is_none())
                && self.can_start(&notification.header))
            {
                debug!(target: "thea", "🥩 New active validator set id: {:?}", active);
                metric_set!(self, thea_validator_set_id, active.id);

                self.rounds = round::Rounds::new(active.clone());

                debug!(target: "thea", "🥩 New Rounds for id: {:?}", active.id);

                self.last_thea_round = Some(*notification.header.number());

                self.party_count = active.validators.len();
                self.threshold = round::threshold(self.party_count) - 1; // FIXME: Better Threshold calculation
                // round::threshold(3) returns 3, which is not correc
                let local_id = self.local_id().expect(" Unable to get local authority id");
                self.party_idx = active
                    .validators
                    .iter()
                    .position(|authority_id| authority_id == &local_id)
                    .expect(" Unable to find local party index")
                    + 1; // TODO: Maybe local party might not be eligible to participate

                self.gossip_validator.set_party_idx(self.party_idx as u16);
                debug!(target: "thea", "t-ECDSA Config: t: {:?}, N: {:?}, party index: {:?}", self.threshold, self.party_count, self.party_idx);

                if self.local_party.is_none() {
                    // Creates a t-ECDSA local party
                    self.local_party = Keygen::new(
                        self.party_idx as u16,
                        self.threshold as u16,
                        self.party_count as u16,
                    )
                        .map_err(|err| error!(target: "thea", "{:?}", err))
                        .ok();
                }

                if self.local_party.is_some() {
                    debug!(target: "thea", "Local Party Created: {:?}", self.local_party);
                    let local_party = self.local_party.as_mut().unwrap();
                    // local_party.current_round();
                    if local_party.wants_to_proceed() {
                        debug!(target: "thea", "Local Party wants to proceed");
                        match local_party.proceed() {
                            Ok(()) => (),
                            Err(err) if err.is_critical() => {
                                error!(target: "thea", "Critical Error in t-ECDSA: {:?}", err);
                                return;
                            }
                            Err(err) => {
                                warn!(target: "thea", "Non-critical error encountered: {:?}", err);
                            }
                        }

                        self.gossip_validator
                            .set_protocol_status(local_party.is_finished());
                    }
                    debug!(target: "thea", "Local Party gossiping {:?} protocol messages", local_party.message_queue().len());
                    let mut message_iter = local_party.message_queue().iter();
                    loop {
                        if let Some(message) = message_iter.next() {
                            // TODO: use send_message instead which will send the message to addressed peers of
                            // 100 validator shard and reduces the communication overhead
                            let encoded_message = serde_json::to_string(message)
                                .expect(" Unable to serialize thea message");
                            self.gossip_engine.lock().gossip_message(
                                topic::<B>(),
                                encoded_message.into_bytes(),
                                false,
                            );
                        } else {
                            break;
                        }
                    }
                    local_party.message_queue().clear();
                }
            }
        } else {
            trace!(target: "thea", "🥩 Thea Validator Set returned None");
        }
    }

    pub fn handle_protocol_message(&mut self, message: Msg<ProtocolMessage>) {
        trace!(target: "thea", "🥩 Got New Protocol Message: Sender {:?}, Receiver: {:?}", message.sender, message.receiver);
        if let Some(reciever) = message.receiver {
            if reciever != self.party_idx as u16 {
                warn!(target: "thea", "Rejecting message as message is not for me");
                return;
            }
        }
        let mut status = false;
        let mut public_key: Option<GE> = None;
        if self.local_party.is_some() {
            let local_party = self.local_party.as_mut().unwrap();
            match local_party.handle_incoming(message) {
                Ok(()) => (),
                Err(err) if err.is_critical() => {
                    error!(target: "thea", "Critical Error in t-ECDSA while handling incoming message: {:?}", err);
                    return;
                }
                Err(err) => {
                    warn!(target: "thea", "Non-critical error encountered: {:?}", err);
                }
            }
            let mut message_iter = local_party.message_queue().iter();
            loop {
                if let Some(message) = message_iter.next() {
                    // TODO: use send_message instead which will send the message to addressed peers of
                    // 100 validator shard and reduces the communication overhead
                    let encoded_message =
                        serde_json::to_string(message).expect(" Unable to serialize thea message");
                    self.gossip_engine.lock().gossip_message(
                        topic::<B>(),
                        encoded_message.into_bytes(),
                        false,
                    );
                } else {
                    break;
                }
            }
            local_party.message_queue().clear();
            if local_party.wants_to_proceed() {
                match local_party.proceed() {
                    Ok(()) => (),
                    Err(err) if err.is_critical() => {
                        error!(target: "thea", "Critical Error in t-ECDSA while proceeding: {:?}", err);
                        return;
                    }
                    Err(err) => {
                        warn!(target: "thea", "Non-critical error encountered: {:?}", err);
                    }
                }
                let mut message_iter = local_party.message_queue().iter();
                loop {
                    if let Some(message) = message_iter.next() {
                        // TODO: use send_message instead which will send the message to addressed peers of
                        // 100 validator shard and reduces the communication overhead
                        let encoded_message = serde_json::to_string(message)
                            .expect(" Unable to serialize thea message");
                        self.gossip_engine.lock().gossip_message(
                            topic::<B>(),
                            encoded_message.into_bytes(),
                            false,
                        );
                    } else {
                        break;
                    }
                }
            }
            self.gossip_validator
                .set_protocol_status(local_party.is_finished());
            status = local_party.is_finished();
            if local_party.is_finished() {
                public_key = Some(local_party.pick_output().unwrap().unwrap().public_key());
            }
        } else {
            error!(target: "thea", " Local Party is not initialized yet");
        }

        self.set_status(status);

        trace!(target: "thea", "Protocol Status: {:?}", status);
        if status && public_key.is_some() {
            self.set_public_key(public_key.unwrap())
        }
    }
    pub(crate) async fn run(mut self) {
        let mut thea_protocol_messages = Box::pin(
            self.gossip_engine
                .lock()
                .messages_for(topic::<B>())
                .filter_map(|notification| async move {
                    match String::from_utf8(notification.message[..].to_vec()) {
                        Ok(json_str) => {
                            let message: Msg<ProtocolMessage> =
                                serde_json::from_str(&*json_str).unwrap();
                            Some(message)
                        }
                        Err(err) => {
                            error!(target: "thea", "Unable to convert bytes to string for incoming message");
                            None
                        }
                    }
                }),
        );

        loop {
            let engine = self.gossip_engine.clone();
            let gossip_engine = future::poll_fn(|cx| engine.lock().poll_unpin(cx));

            futures::select! {
                notification = self.finality_notifications.next().fuse() => {
                    if let Some(notification) = notification {
                        self.handle_finality_notification(notification);
                    } else {
                        return;
                    }
                },
                thea_protocol_message = thea_protocol_messages.next().fuse() => {
                    if let Some(message) = thea_protocol_message {
                        self.handle_protocol_message(message);
                    } else {
                        return;
                    }
                },
                _ = gossip_engine.fuse() => {
                    error!(target: "thea", "🥩 Gossip engine has terminated.");
                    return;
                }
            }
        }
    }
}

/// Scan the `header` digest log for a THEA validator set change. Return either the new
/// validator set or `None` in case no validator set change has been signaled.
fn find_authorities_change<B, Id>(header: &B::Header) -> Option<ValidatorSet<Id>>
    where
        B: Block,
        Id: Codec,
{
    let id = OpaqueDigestItemId::Consensus(&THEA_ENGINE_ID);

    let filter = |log: ConsensusLog<Id>| match log {
        ConsensusLog::AuthoritiesChange(validator_set) => Some(validator_set),
        _ => None,
    };

    header
        .digest()
        .convert_first(|l| l.try_to(id).and_then(filter))
}
