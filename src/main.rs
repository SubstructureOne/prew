mod pipe;
mod packet;
mod postgresql;
mod rule;

use std::error::Error;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::sync::Arc;
use futures::{
    FutureExt,
    select,
};
use futures::lock::Mutex;
use log::{debug, info, trace, warn};
use serde::{Serialize, Deserialize};
use tokio::net::{TcpListener, TcpStream};

use pipe::Pipe;
use packet::{Direction, PacketProcessor};
use crate::postgresql::{PostgresqlPacket, PostgresqlProcessor};
use crate::rule::PacketTransformer;


pub struct PacketRules<X> where X : PacketTransformer {
    bind_addr: String,
    server_addr: String,
    processor: PostgresqlProcessor<X>,
}

#[derive(Debug, Serialize, Deserialize)]
struct AppendInfo {
    append: String
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag="mode")]
enum ProxyMode {
    Passthru,
    DbAppend(AppendInfo),
}


#[derive(Debug, Serialize, Deserialize)]
struct PrewConfig {
    bind_addr: String,
    server_addr: String,
    mode: ProxyMode,
}

impl Default for PrewConfig {
    fn default() -> Self {
        Self {
            bind_addr: "0.0.0.0:6432".to_string(),
            server_addr: "0.0.0.0:5432".to_string(),
            mode: ProxyMode::DbAppend(AppendInfo{append: "_abcd".to_string()}),
        }
    }
}

pub struct ProtocolProxy<X> where X : PacketTransformer {
    server_addr: String,
    listener: TcpListener,
    processor: PostgresqlProcessor<X>,
}


pub struct RewriteReverseProxy<X>  where X : PacketTransformer {
    proxies: Vec<Box<ProtocolProxy<X>>>,
}


impl<X> RewriteReverseProxy<X> where X : PacketTransformer<PacketType=PostgresqlPacket> + Send + Sync + Clone  + 'static {
    pub fn new() -> RewriteReverseProxy<X> {
        RewriteReverseProxy {
            proxies: vec![]
        }
    }

    pub async fn add_proxy(&mut self, rules: Box<PacketRules<X>>) {
        let proxy = ProtocolProxy {
            server_addr: rules.server_addr,
            processor: rules.processor,
            listener: TcpListener::bind(rules.bind_addr)
                .await
                .expect("Unable to bind to bind_addr"),
        };
        self.proxies.push(Box::new(proxy));
    }

    async fn create_pipes<T: PacketProcessor + Send + Sync + 'static>(
        db_addr: String,
        mut client_socket: TcpStream,
        handler_ref: Arc<Mutex<T>>,
        // kill_switch_receiver: oneshot::Receiver<()>,
    ) {
        let client_addr = match client_socket.peer_addr() {
            Ok(addr) => addr.to_string(),
            Err(_e) => String::from("Unknown"),
        };
        tokio::spawn(async move {
            debug!(
                "Server.create_pipes: Spawning new task to manage connection from {}",
                client_addr
            );
            // Create new connections to the server for each client socket
            let mut server_socket = TcpStream::connect(db_addr.clone())
                .await
                .unwrap_or_else(|_| panic!("Connecting to SQL database ({}) failed", db_addr));
            let (server_reader, server_writer) = server_socket.split();
            let (client_reader, client_writer) = client_socket.split();
            let mut forward_pipe = Pipe::new(
                client_addr.clone(),
                handler_ref.clone(),
                Direction::Forward,
                client_reader,
                server_writer,
            );
            let mut backward_pipe = Pipe::new(
                client_addr.clone(),
                handler_ref.clone(),
                Direction::Backward,
                server_reader,
                client_writer,
            );

            trace!("Server.create_pipes: starting forward/backwards pipes");
            // select! will continuously run all futures until one returns
            // - pipes are infinite loops, and never expect to exit unless error
            // - any return will close this connection
            select! {
                _ = forward_pipe.run().fuse() => {
                    trace!("Pipe closed via forward pipe");
                },
                _ = backward_pipe.run().fuse() => {
                    trace!("Pipe closed via backward pipe");
                },
                // msg = kill_switch_receiver.fuse() => {
                //     trace!("Pipe closed via kill switch: {:?}", msg);
                // }
            }
            debug!("Closing connection from {:?}", client_socket.peer_addr());
        });
    }

    pub async fn run(
        &mut self,
        // processor: T,
        // kill_switch_receiver: oneshot::Receiver<()>,
    ) {
        trace!("RewriteReverseProxy.run - enter");
        let proxy = &self.proxies[0];
        let listener = &proxy.listener;
        let packet_handler = Arc::new(Mutex::new(proxy.processor.clone()));
        // let packet_handler = Arc::new(Mutex::new(processor));

        // let incoming = self.proxies
        //     .iter()
        //     .map(|proxy| proxy.listener.accept().fuse())
        //     .collect();
        loop {
            trace!("RewriteReverseProxy.run - loop");
            match listener.accept().await {
                Ok((socket, _addr)) => {
                    // let (tx, rx) = oneshot::channel();
                    RewriteReverseProxy::<X>::create_pipes(
                        proxy.server_addr.clone(),
                        socket,
                        packet_handler.clone(),
                        // rx,
                    ).await;
                    info!("new client")
                },
                Err(e) => info!("couldn't get client: {}", e),
            }
        }
    }
}

fn write_default_config() -> Result<PrewConfig, Box<dyn Error>> {
    let config = PrewConfig::default();
    let s = toml::to_string_pretty(&config)?;
    let mut f = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open("prew.toml")?;
    f.write_all(s.as_bytes())?;
    Ok(config)
}


fn read_config() -> Result<PrewConfig, Box<dyn Error>> {
    let path = "prew.toml";
    let cfg_data: PrewConfig;
    match File::open(path) {
        Ok(mut cfg_file) => {
            let mut cfg_string = String::new();
            cfg_file.read_to_string(&mut cfg_string)?;
            cfg_data = toml::from_str(&cfg_string)?;
        }
        Err(e)=> {
            warn!("Couldn't find config file; writing out default: {}", e);
            cfg_data = write_default_config()?;
        }
    }
    Ok(cfg_data)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>>{
    env_logger::init();
    let config = read_config()?;
    // let (_tx, rx) = oneshot::channel();
    // let processor = PostgresqlProcessor::passthru();
    if let ProxyMode::DbAppend(appendinfo) = config.mode {
        let mut proxy = RewriteReverseProxy::new();
        let processor = PostgresqlProcessor::appenddbname(appendinfo.append);
        let rules = PacketRules {
            bind_addr: config.bind_addr,
            server_addr: config.server_addr,
            processor,
        };
        proxy.add_proxy(Box::new(rules)).await;
        proxy.run().await;
    } else if let ProxyMode::Passthru = config.mode {
        let mut proxy = RewriteReverseProxy::new();
        let processor = PostgresqlProcessor::passthru();
        let rules = PacketRules {
            bind_addr: config.bind_addr,
            server_addr: config.server_addr,
            processor,
        };
        proxy.add_proxy(Box::new(rules)).await;
        proxy.run().await;
    }
    Ok(())
}
