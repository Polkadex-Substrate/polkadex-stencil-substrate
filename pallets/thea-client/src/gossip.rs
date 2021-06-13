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

use std::collections::BTreeMap;
use std::fmt::Debug;
// This is file is modified from beefy-gadget from Parity Technologies (UK) Ltd.
use std::marker::PhantomData;

use codec::{Decode, Encode};
use log::{debug, error, trace, warn};
use parking_lot::RwLock;
use round_based::Msg;
use sc_network::{ObservedRole, PeerId};
use sc_network_gossip::{
    MessageIntent, ValidationResult as GossipValidationResult, ValidationResult,
    Validator as GossipValidator, ValidatorContext as GossipValidatorContext, ValidatorContext,
};
use sp_core::Pair;
use sp_runtime::traits::{Block, Hash, Header, NumberFor};

use crate::communication::TheaGossipMessages;
use crate::mpc::M::{Round1, Round2, Round3, Round4};
use crate::mpc::ProtocolMessage;

// Limit THEA gossip by keeping only a bound number of voting rounds alive.
// It means that  protocol messages will be gossipped for maximum of MAX_LIVE_GOSSIP_ROUNDS
const MAX_LIVE_GOSSIP_ROUNDS: usize = 5;

const MAX_ROUND_DELAY: u16 = 1; // Note this cannot be greater than 1

/// Gossip engine messages topic
pub(crate) fn topic<B: Block>() -> B::Hash
    where
        B: Block,
{
    <<B::Header as Header>::Hashing as Hash>::hash(b"thea")
}

/// THEA gossip validator
///
/// Validate THEA gossip messages and limit the number of live BEEFY voting rounds.
///
/// If the messages are intended for the local validator then expire/discard it after processing.
/// If the messages are intended for someone else re-gossip it for MAX_ROUND_DELAY after the current round
/// times then expire further messages.
/// All messages are expired if the protocol is completed
///
/// Messages are gossiped for when they are created in this node,
/// Every node keeps track of messages they received in cache, which is send back when they receive a catch request
///
/// All messaging is handled in a single THEA global topic.
/// QUESTION: Should we need different messaging for keygen, reshare and signgen?
pub(crate) struct TheaGossipValidator<B, P>
    where
        B: Block,
{
    topic: B::Hash,
    live_rounds: RwLock<Vec<NumberFor<B>>>,
    protocol_finished: RwLock<bool>,
    current_round: RwLock<u16>,
    party_idx: RwLock<u16>,
    /// Round 1 messages are broadcast messages so every party sends a common protocol message
    /// where key is receiver
    round1_msgs: RwLock<BTreeMap<u16, Vec<u8>>>,
    /// Round 2 messages are also broadcast messages
    /// where key is receiver
    round2_msgs: RwLock<BTreeMap<u16, Vec<u8>>>,
    /// In round 3 every party generates a unique message for each other party
    /// Hence key is (sender,receiver)
    round3_msgs: RwLock<BTreeMap<(u16, u16), Vec<u8>>>,
    /// In round 4, messages are broadcast
    round4_msgs: RwLock<BTreeMap<u16, Vec<u8>>>,
    /// Round Blame's key is the round number and value is a vector of peers from which we are expecting messages
    round_blame: RwLock<BTreeMap<u16, Vec<u16>>>,
    _pair: PhantomData<P>,
}

impl<B, P> TheaGossipValidator<B, P>
    where
        B: Block,
{
    pub fn new() -> TheaGossipValidator<B, P> {
        TheaGossipValidator {
            topic: topic::<B>(),
            live_rounds: RwLock::new(Vec::new()),
            protocol_finished: RwLock::from(false),
            current_round: RwLock::from(0),
            party_idx: RwLock::from(0),
            round1_msgs: RwLock::from(BTreeMap::new()),
            round2_msgs: RwLock::from(BTreeMap::new()),
            round3_msgs: RwLock::from(BTreeMap::new()),
            round4_msgs: RwLock::from(BTreeMap::new()),
            round_blame: RwLock::from(BTreeMap::new()),
            _pair: PhantomData,
        }
    }

    pub(crate) fn note_round(&self, round: NumberFor<B>) {
        let mut live_rounds = self.live_rounds.write();

        // NOTE: ideally we'd use a VecDeque here, but currently binary search is only available on
        // nightly for `VecDeque`.
        while live_rounds.len() > MAX_LIVE_GOSSIP_ROUNDS {
            let _ = live_rounds.remove(0);
        }

        if let Some(idx) = live_rounds.binary_search(&round).err() {
            live_rounds.insert(idx, round);
        }
    }

    fn is_live(live_rounds: &[NumberFor<B>], round: NumberFor<B>) -> bool {
        live_rounds.binary_search(&round).is_ok()
    }

    fn is_protocol_finished(&self) -> bool {
        *self.protocol_finished.read()
    }

    pub(crate) fn cache_protocol_message(&self, round_number: u16,
                                         sender: Option<u16>,
                                         receiver: Option<u16>,
                                         msg: Vec<u8>) {
        match round_number {
            1 => {
                let mut round1 = self.round1_msgs.write();
                round1.insert(sender.expect("Sender is expected for Round 1 messages"), msg);
            }
            2 => {
                let mut round2 = self.round2_msgs.write();
                round2.insert(sender.expect("Sender is expected for Round 2 messages"), msg);
            }
            3 => {
                let mut round3 = self.round3_msgs.write();
                round3.insert((sender.expect("Sender is expected for Round 3 messages"),
                               receiver.expect("Receiver is expected for Round 3 messages")), msg);
            }
            4 => {
                let mut round4 = self.round4_msgs.write();
                round4.insert(sender.expect("Sender is expected for Round 4 messages"), msg);
            }
            _ => {}
        }
    }

    pub(crate) fn set_blame(&self, round_number: u16, peers: Vec<u16>) {
        let mut blames = self.round_blame.write();
        blames.insert(round_number, peers);
    }

    pub(crate) fn set_party_idx(&self, index: u16) {
        let mut prev_index = self.party_idx.write();
        *prev_index = index;
    }

    pub(crate) fn set_protocol_status(&self, status: bool) {
        let mut prev_status = self.protocol_finished.write();
        *prev_status = status;
    }

    pub(crate) fn set_current_round(&self, round: u16) {
        let mut prev_round = self.current_round.write();
        *prev_round = round;
    }
    pub(crate) fn store_round1_message(&self, sender: u16, message: Vec<u8>) -> Option<Vec<u8>> {
        let mut round1_msgs = self.round1_msgs.write();
        round1_msgs.insert(sender, message)
    }
    pub(crate) fn store_round2_message(&self, sender: u16, message: Vec<u8>) -> Option<Vec<u8>> {
        let mut round2_msgs = self.round2_msgs.write();
        round2_msgs.insert(sender, message)
    }
    pub(crate) fn store_round3_message(&self, sender: u16, receiver: u16, message: Vec<u8>) -> Option<Vec<u8>> {
        let mut round3_msgs = self.round3_msgs.write();
        round3_msgs.insert((sender, receiver), message)
    }
    pub(crate) fn store_round4_message(&self, sender: u16, message: Vec<u8>) -> Option<Vec<u8>> {
        let mut round4_msgs = self.round4_msgs.write();
        round4_msgs.insert(sender, message)
    }
}

/// validate() -> When a new message comes in it is first validated using the validate function below before it is
/// passed to the upper layers
///
/// message_expired() -> It is executed on a periodic basis for maintenance of stored known messages,
/// non expired messages are rebroadcasted on every tick
///
/// message_allowed() -> when we call gossip_message(), the messages are checked against this closure before
/// it is send over the wire.
impl<B, P> GossipValidator<B> for TheaGossipValidator<B, P>
    where
        B: Block,
        P: Pair,
        P::Public: Debug + Decode,
        P::Signature: Debug + Decode,
{
    fn new_peer(&self, context: &mut dyn GossipValidatorContext<B>, who: &PeerId, roles: ObservedRole) {
        // TODO: Record PeerId and it's role in Peerset
    }

    fn validate(
        &self,
        context: &mut dyn GossipValidatorContext<B>,
        sender: &PeerId,
        mut data: &[u8],
    ) -> GossipValidationResult<<B as Block>::Hash> {
        let party_idx = self.party_idx.read();
        if let Ok(msg) = TheaGossipMessages::decode(&mut data) {
            match msg {
                // CatchUpRequests are handled in the current layer and never forwarded to upper layers
                TheaGossipMessages::CatchUpRequest(round, blame, sender_idx) => {
                    // TODO: Check if we have messages from peers in blame for the given round and send it back
                    let mut protocol_msgs: Vec<Vec<u8>> = vec![];
                    match round {
                        1 => {
                            let round1_cache = self.round1_msgs.read();
                            for receiver in blame {
                                match round1_cache.get(&receiver) {
                                    Some(msg) => {
                                        protocol_msgs.push(msg.clone())
                                    }
                                    None => {
                                        continue;
                                    }
                                }
                            }
                            if !protocol_msgs.is_empty() {
                                let encoded_response = TheaGossipMessages::CatchUpResponse(round, protocol_msgs.clone()).encode();
                                context.send_message(sender, encoded_response);
                                debug!(target: "thea", "Sending CatchUpResponse to {} for round {}, no of msgs: {}", sender_idx, round, protocol_msgs.len());
                            }
                            GossipValidationResult::Discard
                        }
                        2 => {
                            let round2_cache = self.round2_msgs.read();
                            for receiver in blame {
                                match round2_cache.get(&receiver) {
                                    Some(msg) => {
                                        protocol_msgs.push(msg.clone())
                                    }
                                    None => {
                                        continue;
                                    }
                                }
                            }
                            if !protocol_msgs.is_empty() {
                                let encoded_response = TheaGossipMessages::CatchUpResponse(round, protocol_msgs.clone()).encode();
                                context.send_message(sender, encoded_response);
                                debug!(target: "thea", "Sending CatchUpResponse to {} for round {}, no of msgs: {}", sender_idx, round, protocol_msgs.len());
                            }
                            GossipValidationResult::Discard
                        }
                        3 => {
                            let round3_cache = self.round3_msgs.read();
                            for receiver in blame {
                                match round3_cache.get(&(receiver, sender_idx)) {
                                    Some(msg) => {
                                        protocol_msgs.push(msg.clone())
                                    }
                                    None => {
                                        continue;
                                    }
                                }
                            }
                            if !protocol_msgs.is_empty() {
                                let encoded_response = TheaGossipMessages::CatchUpResponse(round, protocol_msgs.clone()).encode();
                                debug!(target: "thea", "Sending CatchUpResponse to {} for round {}, no of msgs: {}", sender_idx, round, protocol_msgs.len());
                                context.send_message(sender, encoded_response);
                            }
                            GossipValidationResult::Discard
                        }
                        4 => {
                            let round4_cache = self.round4_msgs.read();
                            for receiver in blame {
                                match round4_cache.get(&receiver) {
                                    Some(msg) => {
                                        protocol_msgs.push(msg.clone())
                                    }
                                    None => {
                                        continue;
                                    }
                                }
                            }
                            if !protocol_msgs.is_empty() {
                                let encoded_response = TheaGossipMessages::CatchUpResponse(round, protocol_msgs.clone()).encode();
                                context.send_message(sender, encoded_response); // This doesn't undergo expiration and egress message checks
                                // Check here: C:\Users\Gautham\.cargo\git\checkouts\substrate-7e08433d4c370a21\e5437ef\client\network-gossip\src\state_machine.rs
                                debug!(target: "thea", "Sending CatchUpResponse to {} for round {}, no of msgs: {}", sender_idx, round, protocol_msgs.len());
                            }
                            GossipValidationResult::Discard
                        }
                        _ => {
                            GossipValidationResult::Discard
                        }
                    }
                }
                // CatchUpResponses are forwarded to upper layers for handling
                TheaGossipMessages::CatchUpResponse(_, _) => {
                    GossipValidationResult::ProcessAndDiscard(self.topic)
                }
                // Stores the incoming messages and if the message is already present then it is not forwarded to upper layer
                // if not, it is stored in the cache and forwarded to upper layer
                TheaGossipMessages::TheaMessage(protocol_msg) => {
                    match String::from_utf8(protocol_msg.clone()) {
                        Ok(json_str) => {
                            let message: Msg<ProtocolMessage> = serde_json::from_str(&*json_str).unwrap();
                            if let ProtocolMessage(round) = message.body {
                                match round {
                                    Round1(_) => {
                                        match self.store_round1_message(message.sender, protocol_msg) {
                                            Some(_) => {
                                                GossipValidationResult::Discard
                                            }
                                            None => {
                                                GossipValidationResult::ProcessAndKeep(self.topic)
                                            }
                                        }
                                    }
                                    Round2(_) => {
                                        match self.store_round2_message(message.sender, protocol_msg) {
                                            Some(_) => {
                                                GossipValidationResult::Discard
                                            }
                                            None => {
                                                GossipValidationResult::ProcessAndKeep(self.topic)
                                            }
                                        }
                                    }
                                    Round3(_) if message.receiver.is_some() => {
                                        match self.store_round3_message(message.sender, message.receiver.unwrap(), protocol_msg) {
                                            Some(_) => {
                                                GossipValidationResult::Discard
                                            }
                                            None => {
                                                if message.receiver == Some(*party_idx) {
                                                    GossipValidationResult::ProcessAndDiscard(self.topic)
                                                } else {
                                                    GossipValidationResult::ProcessAndKeep(self.topic)
                                                }
                                            }
                                        }
                                    }
                                    Round4(_) => {
                                        match self.store_round4_message(message.sender, protocol_msg) {
                                            Some(_) => {
                                                GossipValidationResult::Discard
                                            }
                                            None => {
                                                GossipValidationResult::ProcessAndKeep(self.topic)
                                            }
                                        }
                                    }
                                    _ => {
                                        trace!(target: "thea", "Received a Round3 message with None for receiver");
                                        GossipValidationResult::Discard
                                    }
                                }
                            } else {
                                return GossipValidationResult::Discard;
                            }
                        }
                        Err(err) => {
                            error!(target: "thea", "Unable to convert bytes to string for incoming message {}", err);
                            GossipValidationResult::Discard
                        }
                    }
                }
            }
        } else {
            // TODO: report the peer
            GossipValidationResult::Discard
        }
    }

    fn message_expired<'a>(&'a self) -> Box<dyn FnMut(<B as Block>::Hash, &[u8]) -> bool + 'a> {
        // let live_rounds = self.live_rounds.read();
        let status = self.protocol_finished.read();
        let current_round = self.current_round.read();
        let party_idx = self.party_idx.read();
        Box::new(move |_topic, mut data| {
            if *status {
                trace!(target: "thea", "Message expired as protocol is complete");
                return true;
            }

            if let Ok(msg) = TheaGossipMessages::decode(&mut data) {
                match msg {
                    TheaGossipMessages::CatchUpRequest(round, blame, sender_idx) => {
                        // TODO: Check if we have messages from peers in blame for the given round and send it back
                        if *status {
                            true
                        } else {
                            false // Should this be true?
                        }
                    }
                    TheaGossipMessages::CatchUpResponse(round, result) => {
                        // TODO: Check if we already go the messages we need, if not process and discard
                        true
                    }
                    TheaGossipMessages::TheaMessage(protocol_msg) => {
                        match String::from_utf8(protocol_msg) {
                            Ok(json_str) => {
                                let message: Msg<ProtocolMessage> = serde_json::from_str(&*json_str).unwrap();
                                if let ProtocolMessage(round) = message.body {
                                    match round {
                                        Round1(_) => {
                                            // Number of messages in this round = 100 ( 1 from each validator)
                                            if *current_round > 1 + MAX_ROUND_DELAY {
                                                debug!(target: "thea", " Expiring Round 1 messages");
                                                return true;
                                            }
                                        }
                                        Round2(_) => {
                                            // Number of messages in this round = 100 ( 1 from each validator)
                                            if *current_round > 2 + MAX_ROUND_DELAY {
                                                debug!(target: "thea", " Expiring Round 2 messages");
                                                return true;
                                            }
                                        }
                                        Round3(_) => {
                                            // Number of messages in this round = 100*100 (100 from each validator)
                                            // TODO: Collect P2P messages here, register own message but do not
                                            // relay the p2p message more than once
                                            return true; // we are purpose fully expiring p2p messages to prevent rebroadcast on every tick
                                            // p2p messages are stored by every nodes so for it will reissued on new catchup request
                                        }
                                        Round4(_) => {
                                            if *current_round >= 4 + MAX_ROUND_DELAY {
                                                debug!(target: "thea", " Expiring Round 4 messages");
                                                return true;
                                            }
                                        }
                                    }
                                }
                            }
                            Err(err) => {
                                error!(target: "thea", "Unable to convert bytes to string for incoming message {}", err);
                                return true;
                            }
                        };
                        false
                    }
                }
            } else {
                // TODO: report the peer
                true
            }
        })
    }

    fn message_allowed<'a>(
        &'a self,
    ) -> Box<dyn FnMut(&PeerId, MessageIntent, &<B as Block>::Hash, &[u8]) -> bool + 'a> {
        let status = self.protocol_finished.read();
        let party_idx = self.party_idx.read();
        Box::new(move |who, intent, topic, mut data| {

            // TODO: Implement checks for egress thea gossip messages
            // trace!(target: "thea", "🥩 Sending message out: Topic :{:?}, Who: {:?}", topic,who);
            if *status {
                trace!(target: "thea", "Message expired as protocol is complete");
                return false;
            }
            if let Ok(msg) = TheaGossipMessages::decode(&mut data) {
                match msg {
                    TheaGossipMessages::CatchUpRequest(_, _, _) | TheaGossipMessages::CatchUpResponse(_, _) => {
                        error!(target: "thea", " CatchUpRequest and CatchUpResponse are checked with message_allowed closures");
                        true // CatchUpRequest and CatchUpResponse are not checked with message_allowed closures
                    }
                    TheaGossipMessages::TheaMessage(protocol_msg) => {
                        match String::from_utf8(protocol_msg.clone()) {
                            Ok(json_str) => {
                                let message: Msg<ProtocolMessage> = serde_json::from_str(&*json_str).unwrap();
                                // For rounds 1,2 and 4 the receiver will be none for protocol messages
                                match message.body {
                                    ProtocolMessage(Round1(_)) => {
                                        // FIXME: For each message send to each peer message_allowed is invoked which results in only one of the
                                        // connected peers receiving it and other not receiving it
                                        return match self.store_round1_message(message.sender, protocol_msg) {
                                            Some(_) => {
                                                if message.sender == *party_idx {
                                                    true
                                                } else {
                                                    warn!(target: "thea", "Blocking Egress Round 1 message: sender: {}", message.sender);
                                                    false
                                                }
                                            }
                                            None => {
                                                debug!(target: "thea", " Allowed Egress Round 1 message: sender: {}", message.sender);
                                                true
                                            }
                                        };
                                    }
                                    ProtocolMessage(Round2(_)) => {
                                        return match self.store_round2_message(message.sender, protocol_msg) {
                                            Some(_) => {
                                                if message.sender == *party_idx {
                                                    true
                                                } else {
                                                    warn!(target: "thea", "Blocking Egress Round 2 message: sender: {}", message.sender);
                                                    false
                                                }
                                            }
                                            None => {
                                                true
                                            }
                                        };
                                    }
                                    ProtocolMessage(Round3(_)) => {
                                        return match self.store_round3_message(message.sender, message.receiver.unwrap(), protocol_msg) {
                                            Some(_) => {
                                                if message.sender == *party_idx {
                                                    true
                                                } else {
                                                    warn!(target: "thea", "Blocking Egress Round 3 message: sender: {}", message.sender);
                                                    false
                                                }
                                            }
                                            None => {
                                                if message.receiver == Some(*party_idx) {
                                                    warn!(target: "thea", "Blocking Egress Round 3 message addressed to us");
                                                    false
                                                } else {
                                                    true
                                                }
                                            }
                                        };
                                    }
                                    ProtocolMessage(Round4(_)) => {
                                        return match self.store_round4_message(message.sender, protocol_msg) {
                                            Some(_) => {
                                                if message.sender == *party_idx {
                                                    true
                                                } else {
                                                    warn!(target: "thea", "Blocking Egress Round 4 message: sender: {}", message.sender);
                                                    false
                                                }
                                            }
                                            None => {
                                                true
                                            }
                                        };
                                    }
                                }
                            }
                            Err(err) => {
                                error!(target: "thea", "Unable to convert bytes to string for incoming message {}", err);
                                false
                            }
                        }
                    }
                }
            } else {
                error!(target: "thea", "Unable to decode Thea messages, blocking egress message");
                // TODO: report the peer
                false
            }
        })
    }
}
