use std::marker::PhantomData;
use std::ops::Deref;

use anyhow::{Result, anyhow};
use async_trait::async_trait;
use byteorder::{BigEndian, ByteOrder};
use log::{trace};
use serde::{Serialize};

use crate::{
    packet::{Packet},
    rule::PrewRuleSet,
    rule::PacketTransformer,
};
use crate::packet::PacketProcessor;
use crate::rule::{NoFilter, NoTransform, Parser, Encodable, MessageEncoder, Transformer};
use crate::rule::{Encoder, Filter, Reporter};

pub const POSTGRES_IDS: [char; 31] = [
    'R', 'K', 'B', '2', '3', 'C', 'd', 'c', 'f', 'G', 'H', 'W', 'D', 'I', 'E', 'F', 'V', 'p', 'v',
    'n', 'N', 'A', 't', 'S', 'P', '1', 's', 'Q', 'Z', 'T', 'X',
];


#[derive(Clone)]
pub struct PostgresParser {}
impl Parser<PostgresqlPacket> for PostgresParser {
    fn parse(&self, packet: &Packet) -> Result<PostgresqlPacket> {
        let packet_type = packet.bytes[0] as char;
        let info;
        if POSTGRES_IDS.contains(&packet_type) {
            if packet_type == 'Q' {
                info = PostgresqlPacketInfo::Query(QueryMessage::new(&packet.bytes))
            } else {
                info = PostgresqlPacketInfo::Other
            }
        } else {
            if packet.bytes.len() >= 8
                && BigEndian::read_u32(&packet.bytes[4..8]) == 196_608
            {
                // startup message
                info = PostgresqlPacketInfo::Startup(StartupMessage::new(&packet.bytes))
            } else {
                info = PostgresqlPacketInfo::Other
            }
        }
        Ok(PostgresqlPacket::new(info, Some(packet.bytes.clone())))
    }
}

pub fn read_postgresql_packet(packet_buf: &mut Vec<u8>) -> Result<Option<Packet>> {
    // FIXME: Return Err instead of Ok if unable to parse
    if packet_buf.is_empty() {
        trace!(
                "parse_postgresql_packet: FAIL packet_buf(size={}) trying to read first byte",
                packet_buf.len()
            );
        return Ok(None);
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
        return Ok(None);
    }
    let length = BigEndian::read_u32(&packet_buf[size..(size + 4)]) as usize; // read length
    size += length;

    // Check if don't have entire packet
    if packet_buf.len() < size {
        trace!(
                "FAIL packet_buf(size={}) too small, firstbyte={:#04x}={}, size={}, length={}",
                packet_buf.len(), packet_buf[0], id, size, length
            );
        return Ok(None);
    }
    trace!(
        "get_packet(PostgresSQL): SUCCESS firstbyte={:#04x}={}, size={}, length={}",
        packet_buf[0],
        id,
        size,
        length
    );

    Ok(Some(Packet::new(
        packet_buf.drain(0..size).collect(),
    )))
}


#[derive(Clone)]
pub struct PostgresqlProcessor<
    F: Filter<PostgresqlPacket> + Clone,
    X: Transformer<PostgresqlPacket> + Clone,
    E: Encoder<PostgresqlPacket> + Clone
> {
    rules: PrewRuleSet<PostgresqlPacket,PostgresParser,F,X,E>
}


#[derive(Clone, Debug, Serialize)]
pub struct StartupMessage {
    // username: String,
    // database: String,
    // length: u32,
    protocol_version: u32,
    parameters: Vec<(String, String)>,
}

impl Encodable for StartupMessage {
    fn encode(&self) -> Result<Packet> {
        let mut bytes = vec![];
        // Length =
        //      4 bytes for length
        //      4 bytes for protocol version
        //      length of each parameter name, +1 for null terminator
        //      length of each paramter value, +1 for null terminator
        //      +1 for final (additional) null terminator
        let length: usize = 9 + self.parameters
            .iter()
            .map(|(key, val)| key.len() + val.len() + 2)
            .sum::<usize>();
        bytes.extend((length as u32).to_be_bytes());
        bytes.extend(self.protocol_version.to_be_bytes());
        for (key, val) in self.parameters.iter() {
            bytes.extend(key.clone().into_bytes());
            bytes.push(0);
            bytes.extend(val.clone().into_bytes());
            bytes.push(0);
        }
        bytes.push(0);
        trace!("Newly encoded startup message: size {} ({}): {:?}", length, bytes.len(), bytes);
        Ok(Packet { bytes })
    }
}


impl StartupMessage {
    pub fn new(bytes: &Vec<u8>) -> StartupMessage {
        let length = BigEndian::read_u32(&bytes[0..4]);
        trace!("Startup message length: {}", length);
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
            protocol_version,
            parameters
        }
    }

    pub fn get_parameter(&self, name: &str) -> Option<String> {
        let mut found: Option<String> = None;
        for (key, val) in self.parameters.iter() {
            if key.eq(name) {
                found = Some(val.clone());
                break;
            }
        }
        found
    }

    pub fn set_parameter(&mut self, name: &str, value: String) {
        let mut update_ind: Option<usize> = None;
        for (index, (key, _val)) in self.parameters.iter().enumerate() {
            if key.eq(&name) {
                update_ind = Some(index);
                break;
            }
        }
        if let Some(index) = update_ind {
            self.parameters[index].1 = value;
        } else {
            self.parameters.push((name.to_string(), value));
        }
    }
}

#[derive(Clone)]
pub struct AppendDbNameTransformer {
    append: String
}

impl Transformer<PostgresqlPacket> for AppendDbNameTransformer {
    fn transform(&self, packet: &PostgresqlPacket) -> Result<PostgresqlPacket> {
        if let PostgresqlPacketInfo::Startup(message) = &packet.info {
            if let Some(mut newdbname) = message.get_parameter("database") {
                newdbname.push_str(self.append.deref());
                let mut message = message.clone();
                message.set_parameter("database", newdbname);
                Ok(PostgresqlPacket { info: PostgresqlPacketInfo::Startup(message), bytes: None })
            } else {
                Err(anyhow!("No database defined in startup message"))
            }
        } else {
            Ok(packet.clone())
        }
    }
}

#[derive(Clone)]
pub struct IdentityTransformer<T> {
    packet_type: PhantomData<T>
}

impl<T> PacketTransformer for IdentityTransformer<T> where T : Clone {
    type PacketType = T;

    fn transform(&self, packet: &Self::PacketType) -> Self::PacketType {
        return packet.clone();
    }
}


#[derive(Clone, Debug, Serialize)]
pub struct QueryMessage {
    query: String,
}

impl QueryMessage {
    pub fn new(bytes: &Vec<u8>) -> QueryMessage {
        let message_type = bytes[0] as char;
        if message_type != 'Q' {
            panic!("Message type Q expected for query");
        }
        let query = String::from_utf8_lossy(&bytes[5..bytes.len()]).into_owned();
        QueryMessage {
            query,
        }
    }
}


impl Encodable for QueryMessage {
    fn encode(&self) -> Result<Packet> {
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
        Ok(Packet {
            bytes
        })
    }
}


#[derive(Clone, Debug, Serialize)]
pub enum PostgresqlPacketInfo {
    Startup(StartupMessage),
    Query(QueryMessage),
    Other,
}

#[derive(Clone, Debug)]
pub struct PostgresqlPacket {
    info: PostgresqlPacketInfo,
    bytes: Option<Vec<u8>>
}

impl PostgresqlPacket {
    pub fn new(info: PostgresqlPacketInfo, bytes: Option<Vec<u8>>) -> PostgresqlPacket {
        PostgresqlPacket { info, bytes }
    }
}

impl Encodable for PostgresqlPacket {
    fn encode(&self) -> Result<Packet> {
        if let Some(bytes) = &self.bytes {
            Ok(Packet::new(bytes.clone()))
        } else {
            match &self.info {
                PostgresqlPacketInfo::Startup(message) => message.encode(),
                PostgresqlPacketInfo::Query(message) => message.encode(),
                PostgresqlPacketInfo::Other => Err(anyhow!("Cannot encode 'other' messages"))
            }
        }
    }
}



impl<F,X,E> PostgresqlProcessor<F,X,E> where
        F : Filter<PostgresqlPacket> + Clone,
        X : Transformer<PostgresqlPacket> + Clone,
        E : Encoder<PostgresqlPacket> + Clone
{
    pub fn new(rules: PrewRuleSet<PostgresqlPacket, PostgresParser, F, X, E>) -> PostgresqlProcessor<F, X, E> {
        PostgresqlProcessor { rules }
    }
}

impl PostgresqlProcessor<
        NoFilter<PostgresqlPacket>,
        NoTransform<PostgresqlPacket>,
        MessageEncoder<PostgresqlPacket>
> {
    pub fn passthru() -> PostgresqlProcessor<
        NoFilter<PostgresqlPacket>,
        NoTransform<PostgresqlPacket>,
        MessageEncoder<PostgresqlPacket>,
    > {
        let transformer = NoTransform::new();
        let parser = PostgresParser {};
        let filter = NoFilter::new();
        let encoder = MessageEncoder::<PostgresqlPacket>::new();
        PostgresqlProcessor::new(
            PrewRuleSet::new(
                &parser,
                &filter,
                &transformer,
                &encoder,
            )
        )
    }
}

impl PostgresqlProcessor<NoFilter<PostgresqlPacket>, AppendDbNameTransformer, MessageEncoder<PostgresqlPacket>> {
    pub fn appenddbname<S: Into<String>>(append: S) -> PostgresqlProcessor<
        NoFilter<PostgresqlPacket>,
        AppendDbNameTransformer,
        MessageEncoder<PostgresqlPacket>
    > {
        let appender = AppendDbNameTransformer { append: append.into() };
        let parser = PostgresParser {};
        let filter = NoFilter::new();
        let encoder = MessageEncoder::new();
        PostgresqlProcessor::new(
            PrewRuleSet::new(
                &parser,
                &filter,
                &appender,
                &encoder,
            )
        )
    }
}

impl<F,X,E> PacketProcessor for PostgresqlProcessor<F,X,E> where
    F : Filter<PostgresqlPacket> + Clone,
    X : Transformer<PostgresqlPacket> + Clone,
    E : Encoder<PostgresqlPacket> + Clone
{

    fn parse(&self, packet_buf: &mut Vec<u8>) -> Result<Option<Packet>> {
        return read_postgresql_packet(packet_buf);
    }

    fn process_incoming(&self, packet: &Packet) -> Result<Option<Packet>> {
        let rules = &self.rules;
        let parsed = rules.parser.parse(packet)?;
        if rules.filter.filter(&parsed) {
            let transformed = rules.transformer.transform(&parsed)?;
            let encoded = rules.encoder.encode(&transformed)?;
            Ok(Some(encoded))
        } else {
            Ok(None)
        }
    }

    fn process_outgoing(&self, packet: &Packet) -> Result<Option<Packet>> {
        Ok(Some(packet.clone()))
    }
}


pub struct PostgreSQLReporter {
    config: String
}

impl PostgreSQLReporter {
    pub fn new<S: Into<String>>(config: S) -> PostgreSQLReporter {
        PostgreSQLReporter { config: config.into() }
    }
}

#[async_trait]
impl Reporter<PostgresqlPacket> for PostgreSQLReporter {
    async fn report(&self, message: &PostgresqlPacket) -> Result<()> {
        let (client, conn) = tokio_postgres::connect(
            &self.config,
            tokio_postgres::NoTls
        ).await?;
        tokio::spawn(async move {
            if let Err(e) = conn.await {
                println!("Connection error: {}", e);
            }
        });
        let packet_info = serde_json::to_string(&message.info).unwrap();
        let rowcount = client.execute(
            "INSERT INTO reports
             (packet_type, packet_info, packet_bytes)
             VALUES ($1, $2, $3)",
            &[&"Startup", &packet_info, &message.bytes]
        ).await?;
        Ok(())
    }
}
