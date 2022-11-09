use byteorder::{BigEndian, ByteOrder};
use log::{trace};

use crate::packet::{Packet, PacketProcessor};

pub const POSTGRES_IDS: [char; 31] = [
    'R', 'K', 'B', '2', '3', 'C', 'd', 'c', 'f', 'G', 'H', 'W', 'D', 'I', 'E', 'F', 'V', 'p', 'v',
    'n', 'N', 'A', 't', 'S', 'P', '1', 's', 'Q', 'Z', 'T', 'X',
];

struct PostgresqlProcessor {

}

impl PacketProcessor for PostgresqlProcessor {
    fn parse(&self, packet_buf: &mut Vec<u8>) -> Option<Packet> {
        // Nothing in packet_buf
        if packet_buf.is_empty() {
            trace!(
                    "get_packet(PostgresSQL): FAIL packet_buf(size={}) trying to read first byte",
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
                    "get_packet(PostgresSQL): FAIL packet_buf(size={}) trying to read length, firstbyte={:#04x}={}, size={}",
                    packet_buf.len(), packet_buf[0], id, size+4
                );
            return None;
        }
        let length = BigEndian::read_u32(&packet_buf[size..(size + 4)]) as usize; // read length
        size += length;

        // Check if don't have entire packet
        if packet_buf.len() < size {
            trace!(
                    "get_packet(PostgresSQL): FAIL packet_buf(size={}) too small, firstbyte={:#04x}={}, size={}, length={}",
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

    fn process_incoming(&self, packet: &Packet) -> Option<Packet> {
        todo!()
    }

    fn process_outgoing(&self, packet: &Packet) -> Option<Packet> {
        todo!()
    }
}