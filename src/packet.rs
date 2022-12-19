use anyhow::Result;

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
    fn parse(&self, packet_buf: &mut Vec<u8>) -> Result<Option<Packet>>;
    fn process_incoming(&self, packet: &Packet) -> Result<Option<Packet>>;
    fn process_outgoing(&self, packet: &Packet) -> Result<Option<Packet>>;
}


#[derive(Debug)]
pub enum Direction {
    Forward,  // corresponds to handle_request
    Backward, // corresponds to handle_response
}

