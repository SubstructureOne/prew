use anyhow::Result;
use async_trait::async_trait;

#[derive(Clone, Debug, PartialEq)]
pub struct Packet {
    pub bytes: Vec<u8>,
}

impl Packet {
    pub fn new(bytes: Vec<u8>) -> Packet {
        Packet { bytes }
    }
}

#[async_trait]
pub trait PacketProcessor {
    fn parse(&self, packet_buf: &mut Vec<u8>) -> Result<Option<Packet>>;
    async fn process_incoming(&self, packet: &Packet) -> Result<Option<Packet>>;
    async fn process_outgoing(&self, packet: &Packet) -> Result<Option<Packet>>;
}


#[derive(Debug)]
pub enum Direction {
    Forward,  // corresponds to handle_request
    Backward, // corresponds to handle_response
}

