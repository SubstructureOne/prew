use std::fmt::Debug;
use anyhow::Result;
use async_trait::async_trait;
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

pub trait SessionContext: Debug {
    // fn new() -> Box<dyn SessionContext>;
}

#[async_trait]
pub trait PacketProcessor {
    fn start_session(&self) -> Box<dyn SessionContext>;
    fn parse(&self, packet_buf: &mut Vec<u8>) -> Result<Option<Packet>>;
    async fn process_incoming(&self, packet: &Packet, context: &dyn SessionContext) -> Result<Option<Packet>>;
    async fn process_outgoing(&self, packet: &Packet, context: &Box<dyn SessionContext>) -> Result<Option<Packet>>;
}


#[derive(Debug, ToSql)]
#[postgres(name="pktdirection")]
pub enum Direction {
    Forward,  // corresponds to handle_request
    Backward, // corresponds to handle_response
}

