use std::marker::PhantomData;
use std::ops::Deref;

use anyhow::{Result, anyhow};
use async_trait::async_trait;
use byteorder::{BigEndian, ByteOrder};
use log::{debug, trace};
use pg_query::NodeMut;
use postgres_types::ToSql;
use serde::{Serialize};

use crate::{
    packet::{Packet},
    rule::PrewRuleSet,
    rule::PacketTransformer,
};
use crate::rule::{NoFilter, NoTransform, Parser, Encodable, MessageEncoder, Transformer, NoReport, WithAuthenticationContext, DefaultContext};
use crate::rule::{Encoder, Filter, Reporter};

pub const POSTGRES_IDS: [char; 31] = [
    'R', 'K', 'B', '2', '3', 'C', 'd', 'c', 'f', 'G', 'H', 'W', 'D', 'I', 'E', 'F', 'V', 'p', 'v',
    'n', 'N', 'A', 't', 'S', 'P', '1', 's', 'Q', 'Z', 'T', 'X',
];


#[derive(Clone)]
pub struct PostgresParser {
}
impl PostgresParser {
    pub fn new() -> PostgresParser {
        PostgresParser {
        }
    }
}
#[async_trait]
impl<C> Parser<PostgresqlPacket,C> for PostgresParser where C : WithAuthenticationContext + Sync + Send {
    async fn parse(&self, packet: &Packet, context: &C) -> Result<PostgresqlPacket> {
        let packet_type = packet.bytes[0] as char;
        let info;
        if POSTGRES_IDS.contains(&packet_type) {
            if packet_type == 'Q' {
                info = PostgresqlPacketInfo::Query(QueryMessage::new(&packet.bytes))
            } else if packet_type == 'R' {
                if packet.bytes.len() == 8 && BigEndian::read_u32(&packet.bytes[5..9]) == 0 {
                    info = PostgresqlPacketInfo::Authentication(AuthenticationMessage::AuthenticationOk);
                    let mut auth_guard = context.authinfo().write().await;
                    (*auth_guard).authenticated = true;
                } else {
                    info = PostgresqlPacketInfo::Authentication(AuthenticationMessage::Other);
                }
            } else {
                info = PostgresqlPacketInfo::Other;
            }
        } else {
            if packet.bytes.len() >= 8
                && BigEndian::read_u32(&packet.bytes[4..8]) == 196_608
            {
                let msg = StartupMessage::new(&packet.bytes);
                if let Some(username) = msg.get_parameter("user") {
                    let mut auth_guard = context.authinfo().write().await;
                    (*auth_guard).username = Some(username);
                }
                info = PostgresqlPacketInfo::Startup(msg);
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
    E: Encoder<PostgresqlPacket> + Clone,
    R: Reporter<PostgresqlPacket, C> + Clone,
    C: WithAuthenticationContext + Sync + Send,
    CC: Fn() -> C,
> {
    rules: PrewRuleSet<PostgresqlPacket,PostgresParser,F,X,E,R,C,CC>
}


#[derive(Clone, Debug, Serialize)]
pub struct StartupMessage {
    // username: String,
    // database: String,
    // length: u32,
    protocol_version: u32,
    parameters: Vec<(String, String)>,
}

#[derive(Clone, Debug, Serialize)]
pub enum AuthenticationMessage {
    AuthenticationOk,
    Other,
}
impl Encodable for AuthenticationMessage {
    fn encode(&self) -> Result<Packet> {
        Err(anyhow!("Encoding not supported for authentication packets"))
    }
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
impl AppendDbNameTransformer {
    pub fn new<S: Into<String>>(append: S) -> AppendDbNameTransformer {
        AppendDbNameTransformer { append: append.into() }
    }
}
impl Transformer<PostgresqlPacket> for AppendDbNameTransformer {
    fn transform(&self, packet: &PostgresqlPacket) -> Result<PostgresqlPacket> {
        if let PostgresqlPacketInfo::Startup(message) = &packet.info {
            let dbname = message.get_parameter("database")
                .ok_or_else(|| anyhow!("Database name missing from startup message"))?;
            let username = message.get_parameter("user")
                .ok_or_else(|| anyhow!("Username missing from startup message"))?;
            if dbname.eq(&username) {
                // don't append anything if the user is attempting to connect
                // to their own database
                Ok(packet.clone())
            } else {
                let mut newdbname = dbname.clone();
                newdbname.push_str(self.append.deref());
                let mut message = message.clone();
                message.set_parameter("database", newdbname);
                Ok(PostgresqlPacket { info: PostgresqlPacketInfo::Startup(message), bytes: None })
            }
        } else if let PostgresqlPacketInfo::Query(message) = &packet.info {
            let mut modified = false;
            if let Ok(mut parsed) = pg_query::parse(&message.query) {
                unsafe {
                    for (node, _depth, _context) in parsed.protobuf.nodes_mut().into_iter() {
                        match node {
                            NodeMut::CreatedbStmt(dbinfo) => {
                                let new_dbname = format!("{}{}", (*dbinfo).dbname, &self.append);
                                debug!(
                                    "Modifying '{}' to '{}' in '{}'",
                                    (*dbinfo).dbname,
                                    &new_dbname,
                                    &message.query,
                                );
                                (*dbinfo).dbname = new_dbname;
                                modified = true;
                            },
                            NodeMut::DropdbStmt(dbinfo) => {
                                let new_dbname = format!("{}{}", (*dbinfo).dbname, &self.append);
                                debug!(
                                    "Modifying '{}' to '{}' in '{}'",
                                    (*dbinfo).dbname,
                                    &new_dbname,
                                    &message.query,
                                );
                                (*dbinfo).dbname = new_dbname;
                                modified = true;
                            }
                            _ => {}
                        }
                    }
                }
                if modified {
                    let new_query = parsed.deparse()?;
                    debug!("New query: {}", &new_query);
                    Ok(PostgresqlPacket {
                        info: PostgresqlPacketInfo::Query(QueryMessage::from_query(new_query)),
                        bytes: None,
                    })
                } else {
                    Ok(packet.clone())
                }
            } else {
                Ok(packet.clone())
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
            query: query.trim_end_matches("\0").to_owned()
        }
    }

    pub fn from_query(query: String) -> QueryMessage {
        QueryMessage { query }
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
    Authentication(AuthenticationMessage),
    Other,
}


// only for SQL conversion
#[derive(Debug, ToSql)]
#[postgres(name="pgpkttype")]
pub enum PostgresqlPacketType {
    Startup,
    Query,
    Auth,
    Other
}
impl PostgresqlPacketType {
    pub fn from_info(info: &PostgresqlPacketInfo) -> PostgresqlPacketType {
        match info {
            PostgresqlPacketInfo::Startup(_) => PostgresqlPacketType::Startup,
            PostgresqlPacketInfo::Query(_) => PostgresqlPacketType::Query,
            PostgresqlPacketInfo::Authentication(_) => PostgresqlPacketType::Auth,
            PostgresqlPacketInfo::Other => PostgresqlPacketType::Other,
        }
    }
}

#[derive(Clone, Debug)]
pub struct PostgresqlPacket {
    pub info: PostgresqlPacketInfo,
    pub bytes: Option<Vec<u8>>
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
                PostgresqlPacketInfo::Authentication(message) => message.encode(),
                PostgresqlPacketInfo::Other => Err(anyhow!("Cannot encode 'other' messages"))
            }
        }
    }
}



impl<F,X,E,R,C,CC> PostgresqlProcessor<F,X,E,R,C,CC> where
        F : Filter<PostgresqlPacket> + Clone,
        X : Transformer<PostgresqlPacket> + Clone,
        E : Encoder<PostgresqlPacket> + Clone,
        R : Reporter<PostgresqlPacket, C> + Clone,
        C : WithAuthenticationContext + Sync + Send,
        CC : Fn() -> C,
{
    pub fn new(rules: PrewRuleSet<PostgresqlPacket, PostgresParser, F, X, E, R, C, CC>) -> PostgresqlProcessor<F, X, E, R, C, CC> {
        PostgresqlProcessor { rules }
    }
}

impl<CC> PostgresqlProcessor<
        NoFilter<PostgresqlPacket>,
        NoTransform<PostgresqlPacket>,
        MessageEncoder<PostgresqlPacket>,
        NoReport<PostgresqlPacket>,
        DefaultContext,
        CC
> where CC : Fn() -> DefaultContext {
    pub fn passthru() -> PostgresqlProcessor<
        NoFilter<PostgresqlPacket>,
        NoTransform<PostgresqlPacket>,
        MessageEncoder<PostgresqlPacket>,
        NoReport<PostgresqlPacket>,
        DefaultContext,
        impl Fn() -> DefaultContext,
    > {
        let transformer = NoTransform::new();
        let parser = PostgresParser::new();
        let filter = NoFilter::new();
        let encoder = MessageEncoder::<PostgresqlPacket>::new();
        let reporter = NoReport::new();
        PostgresqlProcessor::new(
            PrewRuleSet::new(
                &parser,
                &filter,
                &transformer,
                &encoder,
                &reporter,
                DefaultContext::new,
            )
        )
    }
}

impl<CC> PostgresqlProcessor<
    NoFilter<PostgresqlPacket>,
    AppendDbNameTransformer,
    MessageEncoder<PostgresqlPacket>,
    NoReport<PostgresqlPacket>,
    DefaultContext,
    CC,
> where CC: Fn() -> DefaultContext {
    pub fn appenddbname<S: Into<String>>(append: S) -> PostgresqlProcessor<
        NoFilter<PostgresqlPacket>,
        AppendDbNameTransformer,
        MessageEncoder<PostgresqlPacket>,
        NoReport<PostgresqlPacket>,
        DefaultContext,
        impl Fn() -> DefaultContext,
    > {
        let appender = AppendDbNameTransformer { append: append.into() };
        let parser = PostgresParser::new();
        let filter = NoFilter::new();
        let encoder = MessageEncoder::new();
        // let reporter = PostgreSQLReporter::new("FIXME");
        let reporter = NoReport::new();
        PostgresqlProcessor::new(
            PrewRuleSet::new(
                &parser,
                &filter,
                &appender,
                &encoder,
                &reporter,
                DefaultContext::new,
            )
        )
    }
}

// #[async_trait]
// impl<F,X,E,R> PacketProcessor for PostgresqlProcessor<F,X,E,R> where
//     F : Filter<PostgresqlPacket> + Clone + Sync + Send,
//     X : Transformer<PostgresqlPacket> + Clone + Sync + Send,
//     E : Encoder<PostgresqlPacket> + Clone + Sync + Send,
//     R : Reporter<PostgresqlPacket> + Clone + Sync + Send,
// {
//     fn parse(&self, packet_buf: &mut Vec<u8>) -> Result<Option<Packet>> {
//         return read_postgresql_packet(packet_buf);
//     }
//
//     async fn process_incoming(&self, packet: &Packet, context: &mut Context) -> Result<Option<Packet>> {
//         let rules = &self.rules;
//         let parsed = rules.parser.parse(packet, context)?;
//         rules.reporter.report(&parsed, Direction::Forward, context).await?;
//         if rules.filter.filter(&parsed) {
//             let transformed = rules.transformer.transform(&parsed)?;
//             let encoded = rules.encoder.encode(&transformed)?;
//             Ok(Some(encoded))
//         } else {
//             Ok(None)
//         }
//     }
//
//     async fn process_outgoing(&self, packet: &Packet, context: &mut Context) -> Result<Option<Packet>> {
//         self.rules.reporter.report(
//             &PostgresqlPacket::new(PostgresqlPacketInfo::Other, Some(packet.bytes.clone())),
//             Direction::Backward,
//             context
//         ).await?;
//         Ok(Some(packet.clone()))
//     }
// }


// #[derive(Clone)]
// pub struct PostgresqlReporter {
//     config: String
// }
//
// impl PostgresqlReporter {
//     pub fn new<S: Into<String>>(config: S) -> PostgresqlReporter {
//         PostgresqlReporter { config: config.into() }
//     }
// }
// #[async_trait]
// impl Reporter<PostgresqlPacket> for PostgresqlReporter {
//     async fn report(
//             &self,
//             message: &PostgresqlPacket,
//             direction: Direction,
//             context: &Context,
//     ) -> Result<()> {
//         // let (client, conn) = tokio_postgres::connect(
//         //     &self.config,
//         //     tokio_postgres::NoTls
//         // ).await?;
//         // tokio::spawn(async move {
//         //     if let Err(e) = conn.await {
//         //         println!("Connection error: {}", e);
//         //     }
//         // });
//         // let packet_info = serde_json::to_string(&message.info).unwrap();
//         let packet_info = serde_json::to_value(&message.info)?;
//         let bytes = message.bytes.clone();
//         let packet_type = PostgresqlPacketType::from_info(&message.info);
//         let authinfo = context.authinfo.read().await;
//         let username;
//         if authinfo.authenticated {
//             username = authinfo.username.clone();
//         } else {
//             username = None;
//         }
//         let client = context.client.clone();
//         let handle = tokio::spawn(async move {
//             let rowcount = client.execute(
//                 "INSERT INTO reports
//              (username, packet_type, direction, packet_info, packet_bytes)
//              VALUES ($1, $2, $3, $4, $5)",
//                 &[
//                     &username,
//                     &packet_type,
//                     &direction,
//                     &packet_info,
//                     &bytes
//                 ]
//             ).await;
//             if let Err(error) = rowcount {
//                 error!("Unable to report on packet: {:?} - {:?}", &packet_info, &error);
//             }
//         });
//         Ok(())
//     }
// }
