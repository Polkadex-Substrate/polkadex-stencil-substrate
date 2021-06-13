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

use std::collections::BTreeMap;

use parking_lot::RwLock;

use thea_primitives::{ValidatorSet, ValidatorSetId};

struct KeyGenTracker<Id, Signature> {
    votes: Vec<(Id, Signature)>,
}

impl<Id, Signature> Default for KeyGenTracker<Id, Signature> {
    fn default() -> Self {
        KeyGenTracker {
            votes: Vec::new(),
        }
    }
}

impl<Id, Signature> KeyGenTracker<Id, Signature>
    where
        Id: PartialEq,
        Signature: PartialEq,
{
    fn is_done(&self, threshold: usize) -> bool {
        self.votes.len() >= threshold
    }
}

pub fn threshold(authorities: usize) -> usize {
    // let faulty = authorities.saturating_sub(1) / 3;
    // authorities - faulty
    authorities.saturating_sub(1) / 3
}

pub(crate) struct KeyGenRounds<Number, Id, Signature> {
    rounds: BTreeMap<Number, KeyGenTracker<Id, Signature>>,
    validator_set: ValidatorSet<Id>,
}

impl<Number, Id, Signature> KeyGenRounds<Number, Id, Signature>
    where
        Number: Ord,
{
    pub(crate) fn new(validator_set: ValidatorSet<Id>) -> Self {
        KeyGenRounds {
            rounds: BTreeMap::new(),
            validator_set,
        }
    }
}

impl<Number, Id, Signature> KeyGenRounds<Number, Id, Signature>
    where
        Number: Ord,
        Id: PartialEq + Clone,
        Signature: Clone + PartialEq,
{
    pub(crate) fn validator_set_id(&self) -> ValidatorSetId {
        self.validator_set.id
    }

    pub(crate) fn validators(&self) -> Vec<Id> {
        self.validator_set.validators.clone()
    }

}
