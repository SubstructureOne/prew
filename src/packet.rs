use std::fmt::Debug;
use std::sync::Arc;
use anyhow::Result;
use futures::lock::Mutex;
use postgres_types::ToSql;

#[derive(Clone, Debug, PartialEq)]
pub struct Packet {
    pub bytes: Vec<u8>,
}

impl Packet {
    pub fn new(bytes: Vec<u8>) -> Packet {
        Packet { bytes }
    }
}

pub trait PacketProcessor {
    fn start_session(&self) -> Arc<Mutex<dyn PacketProcessingSession + Send>>;
}

pub trait OtherTrait {}

// #[async_trait]
pub trait PacketProcessingSession {
    fn parse(&self, packet_buf: &mut Vec<u8>) -> Result<Option<Packet>>;
    fn process_incoming(&mut self, packet: &Packet) -> Result<Option<Packet>>;
    fn process_outgoing(&mut self, packet: &Packet) -> Result<Option<Packet>>;
}


#[derive(Debug, ToSql)]
#[postgres(name="pktdirection")]
pub enum Direction {
    Forward,  // corresponds to process_incoming
    Backward, // corresponds to process_outgoing
}

