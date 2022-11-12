mod pipe;
mod packet;
mod postgresql;
mod rule;

use std::ops::Deref;
use std::sync::Arc;
use futures::{
    FutureExt,
    select,
};
use futures::lock::Mutex;
use log::{debug, info, trace};
use serde::{Serialize, Deserialize};
use tokio::net::{TcpListener, TcpStream};

use pipe::Pipe;
use packet::{Direction, PacketProcessor};
use crate::postgresql::PostgresqlProcessor;


pub struct PacketRules {
    bind_addr: String,
    server_addr: String,
    // processor: Box<dyn PacketProcessor>,
    processor: Box<PostgresqlProcessor>,
}



#[derive(Default, Debug, Serialize, Deserialize)]
struct PrewConfig {
    version: u8,
    api_key: String,
}

// #[derive(Debug)]
pub struct ProtocolProxy {
    server_addr: String,
    listener: TcpListener,
    // processor: Box<dyn PacketProcessor>,
    processor: Box<PostgresqlProcessor>,
}


pub struct RewriteReverseProxy {
    proxies: Vec<Box<ProtocolProxy>>,
}


impl RewriteReverseProxy {
    pub fn new() -> RewriteReverseProxy {
        RewriteReverseProxy {
            proxies: vec![]
        }
    }

    pub async fn add_proxy(&mut self, rules: Box<PacketRules>) {
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
        let packet_handler = Arc::new(Mutex::new(proxy.processor.deref().clone()));
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
                    RewriteReverseProxy::create_pipes(
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

#[tokio::main]
async fn main() {
    env_logger::init();
    // let (_tx, rx) = oneshot::channel();
    let mut proxy = RewriteReverseProxy::new();
    // let processor = PassthruPacketProcessor {};
    let processor = Box::new(PostgresqlProcessor::passthru());
    let rules = PacketRules {
        bind_addr: "0.0.0.0:6432".to_string(),
        server_addr: "0.0.0.0:5432".to_string(),
        processor,
    };
    proxy.add_proxy(Box::new(rules)).await;
    proxy.run().await;
}
