use byteorder::{BigEndian, ByteOrder};
use log::{trace};

use crate::{
    packet::{Packet, PacketProcessor},
    rule::PrewRuleSet
};
use crate::postgresql::PostgresqlPacket::Query;

pub const POSTGRES_IDS: [char; 31] = [
    'R', 'K', 'B', '2', '3', 'C', 'd', 'c', 'f', 'G', 'H', 'W', 'D', 'I', 'E', 'F', 'V', 'p', 'v',
    'n', 'N', 'A', 't', 'S', 'P', '1', 's', 'Q', 'Z', 'T', 'X',
];

pub trait Encodable {
    fn encode(&self) -> Packet;
}

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



pub fn encode_postgresql_packet(pgpacket: &PostgresqlPacket) -> Packet {
    pgpacket.encode()
}

#[derive(Clone)]
pub struct PostgresqlProcessor {
    rules: PrewRuleSet<PostgresqlPacket>
}


#[derive(Clone)]
pub struct StartupMessage {
    // username: String,
    // database: String,
    length: u32,
    protocol_version: u32,
    parameters: Vec<(String, String)>,
}

impl Encodable for StartupMessage {
    fn encode(&self) -> Packet {
        let mut bytes = vec![];
        bytes.extend(self.length.to_be_bytes());
        bytes.extend(self.protocol_version.to_be_bytes());
        for (key, val) in self.parameters.iter() {
            bytes.extend(key.clone().into_bytes());
            bytes.push(0);
            bytes.extend(val.clone().into_bytes());
            bytes.push(0);
        }
        bytes.push(0);
        Packet {
            bytes
        }
    }
}

#[derive(Clone)]
pub struct QueryMessage {
    query: String,
}

impl StartupMessage {
    pub fn new(bytes: &Vec<u8>) -> StartupMessage {
        let length = BigEndian::read_u32(&bytes[0..4]);
        let protocol_version = BigEndian::read_u32(&bytes[4..8]);
        let strings: Vec<&[u8]> = bytes[8..bytes.len()].split(|chr| *chr == 0).collect();
        if strings.len() % 2 != 0 || strings[strings.len()-1].len() != 0 {
            panic!(
                "Bad parameter values: {:?}",
                strings
                    .iter()
                    .map(|chars| String::from_utf8_lossy(chars).into())
                    .collect::<Vec<String>>()
            );
        }
        let mut string_ind = 0;
        let mut parameters: Vec<(String, String)> = vec![];
        loop {
            let key = strings[string_ind];
            if key.len() == 0 {
                break;
            }
            let val = strings[string_ind + 1];
            parameters.push((
                String::from_utf8_lossy(key).into(),
                String::from_utf8_lossy(val).into()
            ));
            string_ind += 2;
        }
        StartupMessage {
            length,
            protocol_version,
            parameters
        }
    }
}

impl QueryMessage {
    pub fn new(bytes: &Vec<u8>) -> QueryMessage {
        let message_type = bytes[0] as char;
        if message_type != 'Q' {
            panic!("Message type Q expected for query");
        }
        // let length = BigEndian::read_u32(&bytes[1..5]);
        let query = String::from_utf8_lossy(&bytes[5..bytes.len()]).into_owned();
        QueryMessage {
            query,
        }
    }

    pub fn encode(&self) -> Packet {
        let mut bytes = vec![];
        let mut sqlbytes = self.query.as_bytes().to_vec();
        if sqlbytes[sqlbytes.len()-1] != 0 {
            sqlbytes.push(0);
        }
        // length = length of sql query
        //          +4 for the packet length (u32)
        //          +1 for the message type ('Q' for query)
        //          -1 to not include the null terminator
        let length = (sqlbytes.len() + 4) as u32;
        bytes.push('Q' as u8);
        bytes.extend(length.to_be_bytes());
        bytes.extend(sqlbytes);
        Packet {
            bytes
        }
    }
}

#[derive(Clone)]
pub struct OtherMessage {
    bytes: Vec<u8>
}


impl OtherMessage {
    pub fn new(bytes: &Vec<u8>) -> OtherMessage {
        OtherMessage {
            bytes: bytes.clone()
        }
    }

    pub fn encode(&self) -> Packet {
        Packet {
            bytes: self.bytes.clone(),
        }
    }
}

// #[derive(Clone)]
// pub struct PostgresqlPacket {
//     packet_type: char,
//     length: Option<u32>,
//     query: Option<String>,
//     bytes: Vec<u8>,
// }

#[derive(Clone)]
pub enum PostgresqlPacket {
    Startup(StartupMessage),
    Query(QueryMessage),
    Other(OtherMessage),
}


impl PostgresqlPacket {
    pub fn encode(&self) -> Packet {
        match self {
            PostgresqlPacket::Startup(message) => message.encode(),
            PostgresqlPacket::Query(message) => message.encode(),
            PostgresqlPacket::Other(message) => message.encode(),
        }
    }
}


impl PostgresqlProcessor {
    pub fn new(rules: PrewRuleSet<PostgresqlPacket>) -> PostgresqlProcessor {
        PostgresqlProcessor { rules }
    }

    pub fn passthru() -> PostgresqlProcessor {
        PostgresqlProcessor::new(
            PrewRuleSet::new(
                    PostgresqlProcessor::parse_postgresql_packet,
                    |_pkt| true,
                    |pkt| pkt.clone(),
                    encode_postgresql_packet,
            )
        )
    }

    pub fn parse_postgresql_packet(packet: &Packet) -> PostgresqlPacket {
        let packet_type = packet.bytes[0] as char;
        if POSTGRES_IDS.contains(&packet_type) {
            if packet_type == 'Q' {
                Query(QueryMessage::new(&packet.bytes))
            } else {
                PostgresqlPacket::Other(OtherMessage::new(&packet.bytes))
            }
        } else {
            if packet.bytes.len() >= 8
                && BigEndian::read_u32(&packet.bytes[4..8]) == 196_608
            {
                // startup message
                PostgresqlPacket::Startup(StartupMessage::new(&packet.bytes))
            } else {
                PostgresqlPacket::Other(OtherMessage::new(&packet.bytes))
            }
        }
    }
}

impl PacketProcessor for PostgresqlProcessor {
    fn parse(&self, packet_buf: &mut Vec<u8>) -> Option<Packet> {
        return read_postgresql_packet(packet_buf);
    }

    fn process_incoming(&self, packet: &Packet) -> Option<Packet> {
        let rules = &self.rules;
        let parsed = (rules.parser)(packet);
        if (rules.filter)(&parsed) {
            let transformed = (rules.transformer)(&parsed);
            let encoded = (rules.encoder)(&transformed);
            Some(encoded)
        } else {
            None
        }
    }

    fn process_outgoing(&self, packet: &Packet) -> Option<Packet> {
        return Some(packet.clone());
    }
}
