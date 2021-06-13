/// Define the root type of Gossip Messages used by Thea Pallet
///
/// CatchUpRequest - This message requests the reciever to send some messages
///
/// CatchUpResponse - Contains the response for a CatchUpRequest
///
/// TheaMessage - contains peer's state and message

use codec::{Decode, Encode};

#[derive(Decode, Encode)]
pub enum TheaGossipMessages {
    /// first item is the round in which requester is in
    /// and second item is list of parties from which the requester expects a protocol message
    /// third item is the sender's party_idx
    CatchUpRequest(u16,Vec<u16>,u16),
    /// first item is the round number
    /// second item is the list of encoded protocol messages
    CatchUpResponse(u16, Vec<Vec<u8>>),
    /// Normal Protocol Message
    TheaMessage(Vec<u8>),
}
