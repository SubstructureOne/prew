use byteorder::{BigEndian, ByteOrder};
use log::{trace};

use crate::{
    packet::{Packet, PacketProcessor},
    rule::PrewRuleSet
};

pub const POSTGRES_IDS: [char; 31] = [
    'R', 'K', 'B', '2', '3', 'C', 'd', 'c', 'f', 'G', 'H', 'W', 'D', 'I', 'E', 'F', 'V', 'p', 'v',
    'n', 'N', 'A', 't', 'S', 'P', '1', 's', 'Q', 'Z', 'T', 'X',
];

pub fn read_postgresql_packet(packet_buf: &mut Vec <u8>) -> Option<Packet> {
    if packet_buf.is_empty() {
        trace!(
            "parse_postgresql_packet: FAIL packet_buf(size={}) trying to read first byte",
            packet_buf.len()
        );
        return None;
    }
    let id = packet_buf[0] as char;
    let mut size = 0;
    if POSTGRES_IDS.contains(&id) {
        size += 1;
    }

    // Check if I can read the length field
    if packet_buf.len() < (size + 4) {
        trace!(
            "parse_postgresql_packet: FAIL packet_buf(size={}) trying to read length, firstbyte={:#04x}={}, size={}",
            packet_buf.len(), packet_buf[0], id, size+4
        );
        return None;
    }
    let length = BigEndian::read_u32(&packet_buf[size..(size + 4)]) as usize; // read length
    size += length;

    // Check if don't have entire packet
    if packet_buf.len() < size {
        trace!(
            "FAIL packet_buf(size={}) too small, firstbyte={:#04x}={}, size={}, length={}",
            packet_buf.len(), packet_buf[0], id, size, length
        );
        return None;
    }
    trace!(
        "get_packet(PostgresSQL): SUCCESS firstbyte={:#04x}={}, size={}, length={}",
        packet_buf[0],
        id,
        size,
        length
    );

    Some(Packet::new(
        packet_buf.drain(0..size).collect(),
    ))
}

pub fn parse_postgresql_packet(packet: &Packet) -> PostgresqlPacket {
    let mut offset = 0;
    let packet_type = packet.bytes[offset] as char;
    offset += 1;
    let length: Option<u32>;
    let query: Option<String>;
    if packet_type == 'Q' {
        length = Some(BigEndian::read_u32(&packet.bytes[offset..(offset+4)]));
        offset += 4;
        query = Some(String::from_utf8_lossy(
            &packet.bytes[offset..packet.bytes.len()]
        ).into_owned());
    } else {
        length = None;
        query = None;
    }
    PostgresqlPacket {
        packet_type,
        length,
        query,
        bytes: packet.bytes.clone(),
    }
}

pub fn encode_postgresql_packet(pgpacket: &PostgresqlPacket) -> Packet {
    Packet::new(pgpacket.bytes.clone())
}

#[derive(Clone)]
pub struct PostgresqlProcessor {
    rules: PrewRuleSet<PostgresqlPacket>
}

#[derive(Clone)]
pub struct PostgresqlPacket {
    packet_type: char,
    length: Option<u32>,
    query: Option<String>,
    bytes: Vec<u8>,
}

impl PostgresqlProcessor {
    pub fn new(rules: PrewRuleSet<PostgresqlPacket>) -> PostgresqlProcessor {
        PostgresqlProcessor { rules }
    }

    pub fn passthru() -> PostgresqlProcessor {
        PostgresqlProcessor::new(
            PrewRuleSet::new(
                    parse_postgresql_packet,
                    |pkt| true,
                    |pkt| pkt.clone(),
                    encode_postgresql_packet,
            )
        )
    }
}

impl PacketProcessor for PostgresqlProcessor {
    fn parse(&self, packet_buf: &mut Vec<u8>) -> Option<Packet> {
        return read_postgresql_packet(packet_buf);
    }

    fn process_incoming(&self, packet: &Packet) -> Option<Packet> {
        return Some(packet.clone());
    }

    fn process_outgoing(&self, packet: &Packet) -> Option<Packet> {
        return Some(packet.clone());
    }
}
