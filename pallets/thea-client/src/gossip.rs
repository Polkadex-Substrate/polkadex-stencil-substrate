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

use std::fmt::Debug;
// This is file is modified from beefy-gadget from Parity Technologies (UK) Ltd.
use std::marker::PhantomData;

use codec::Decode;
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

use crate::mpc::ProtocolMessage;

// Limit THEA gossip by keeping only a bound number of voting rounds alive.
// It means that  protocol messages will be gossipped for maximum of MAX_LIVE_GOSSIP_ROUNDS
const MAX_LIVE_GOSSIP_ROUNDS: usize = 5;

const MAX_OTHER_GOSSIP_ROUNDS: usize = 3;

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
/// If the messages are intended for someone else re-gossip it for MAX_OTHER_GOSSIP_ROUNDS times then expire further messages.
/// All messages are expired if the protocol is completed
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
    // protocol_state: RwLock<ProtocolMessage>>,
    party_idx: RwLock<u16>,
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
            // protocol_state: RwLock::from(ProtocolMessag),
            party_idx: RwLock::from(0),
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

    pub(crate) fn set_party_idx(&self, index: u16) {
        let mut prev_index = self.party_idx.write();
        *prev_index = index;
    }
    pub(crate) fn set_protocol_status(&self, status: bool) {
        let mut prev_status = self.protocol_finished.write();
        *prev_status = status;
    }
}

impl<B, P> GossipValidator<B> for TheaGossipValidator<B, P>
    where
        B: Block,
        P: Pair,
        P::Public: Debug + Decode,
        P::Signature: Debug + Decode,
{
    fn validate(
        &self,
        _context: &mut dyn GossipValidatorContext<B>,
        _sender: &PeerId,
        data: &[u8],
    ) -> GossipValidationResult<<B as Block>::Hash> {
        let party_idx = self.party_idx.read();
        match String::from_utf8(data.to_vec()) {
            Ok(json_str) => {
                let message: Msg<ProtocolMessage> = serde_json::from_str(&*json_str).unwrap();

                if message.receiver == Some(*party_idx) {
                    GossipValidationResult::ProcessAndDiscard(self.topic)
                } else {
                    GossipValidationResult::ProcessAndKeep(self.topic)
                }
            }
            Err(err) => {
                error!(target: "thea", "Unable to convert bytes to string for incoming message {}", err);
                GossipValidationResult::Discard
            }
        }
    }

    fn message_expired<'a>(&'a self) -> Box<dyn FnMut(<B as Block>::Hash, &[u8]) -> bool + 'a> {
        // let live_rounds = self.live_rounds.read();
        let status = self.protocol_finished.read();
        Box::new(move |_topic, mut data| {
            if *status {
                trace!(target: "thea", "Message expired as protocol is complete");
                return true;
            }
            let _message = match String::from_utf8(data.to_vec()) {
                Ok(json_str) => {
                    let message: Msg<ProtocolMessage> = serde_json::from_str(&*json_str).unwrap();
                    message
                }
                Err(err) => {
                    error!(target: "thea", "Unable to convert bytes to string for incoming message {}", err);
                    return true;
                }
            };
            // TODO: In future, we want to have a mechanism that maps keygen rounds, signature rounds and
            // selectively expiring messages whose protocols are complete.
            true
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
            match String::from_utf8(data.to_vec()) {
                Ok(json_str) => {
                    let message: Msg<ProtocolMessage> = serde_json::from_str(&*json_str).unwrap();

                    if message.receiver == Some(*party_idx) {
                        false
                    } else {
                        true
                    }
                }
                Err(err) => {
                    error!(target: "thea", "Unable to convert bytes to string for incoming message {}", err);
                    false
                }
            }
        })
    }
}
