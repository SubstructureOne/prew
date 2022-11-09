mod pipe;
mod packet;
mod postgresql;

use std::sync::Arc;
use futures::{
    FutureExt,
    StreamExt,
    channel::mpsc::{Receiver, Sender},
    select,
};
use futures::channel::{mpsc, oneshot};
use futures::lock::Mutex;
use tokio::io::{AsyncWriteExt, AsyncReadExt};
use log::{debug, info, trace};
use serde::{Serialize, Deserialize};
use tokio::net::{TcpListener, TcpStream};

use pipe::Pipe;
use packet::{Direction, PacketProcessor, Packet};



pub struct ServerInfo {
    server_addr: String
}

pub struct BindInfo {
    bind_addr: String
}

pub struct PacketRules {
    bind_addr: String,
    server_addr: String,
    processor: Box<dyn PacketProcessor>,
}

type Parser<T> = fn(Packet) -> T;
type Filter<T> = fn (T) -> bool;
type Transformer<T> = fn(T) -> T;
type Encoder<T> = fn(T) -> Packet;
// type Router = fn(Packet) -> ServerInfo;


struct PrewRuleSet<T> {
    parser: Parser<T>,
    filter: Filter<T>,
    transformer: Transformer<T>,
    encoder: Encoder<T>,
    // router: Router<T>
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
    processor: Box<dyn PacketProcessor>,
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
        kill_switch_receiver: oneshot::Receiver<()>,
    ) {
        let client_addr = match client_socket.peer_addr() {
            Ok(addr) => addr.to_string(),
            Err(_e) => String::from("Unknown"),
        };
        // tokio::spawn(async move {
        //         let mut server_socket = TcpStream::connect(db_addr.clone())
        //             .await
        //             .unwrap_or_else(|_| panic!("Connecting to SQL database ({}) failed", db_addr));
        //     let (server_reader, server_writer) = server_socket.split();
        //     let (client_reader, client_writer) = client_socket.split();
        //     let mut forward_pipe = Pipe::new(
        //             client_addr.clone(),
        //             handler_ref.clone(),
        //             Direction::Forward,
        //             client_reader,
        //             server_writer,
        //         );
        //     let (fb_tx, fb_rx) = mpsc::channel::<Packet>(128);
        //     let (bf_tx, bf_rx) = mpsc::channel::<Packet>(128);
        //     forward_pipe.run(fb_tx, bf_rx).await;
        //     // forward_pipe.run(fb_tx, bf_rx).await;
        // });
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

            // Create channels to short-circuit at the proxy
            // - tx: use to send directly to other's sink
            // - rx: receive and directly dump into sink
            let (fb_tx, fb_rx) = mpsc::channel::<Packet>(128);
            let (bf_tx, bf_rx) = mpsc::channel::<Packet>(128);
            trace!("Server.create_pipes: starting forward/backwards pipes");
            // select! will continuously run all futures until one returns
            // - pipes are infinite loops, and never expect to exit unless error
            // - any return will close this connection
            select! {
                _ = forward_pipe.run(fb_tx, bf_rx).fuse() => {
                    trace!("Pipe closed via forward pipe");
                },
                _ = backward_pipe.run(bf_tx, fb_rx).fuse() => {
                    trace!("Pipe closed via backward pipe");
                },
                _ = kill_switch_receiver.fuse() => {
                    trace!("Pipe closed via kill switch");
                }
            }
            debug!("Closing connection from {:?}", client_socket.peer_addr());
        });
    }

    pub async fn run(&self) {
        trace!("RewriteReverseProxy.run - enter");
        let listener = &self.proxies[0].listener;
        // let incoming = self.proxies
        //     .iter()
        //     .map(|proxy| proxy.listener.accept().fuse())
        //     .collect();
        loop {
            trace!("RewriteReverseProxy.run - loop");
            match listener.accept().await {
                Ok((socket, addr)) => info!("new client"),
                Err(e) => info!("couldn't get client: {}", e),
            }
        }
    }
}

struct PassthruPacketProcessor {

}

impl PacketProcessor for PassthruPacketProcessor {
    fn process_incoming(&self, packet: &Packet) -> Option<Packet> {
        Some(packet.clone())
    }

    fn process_outgoing(&self, packet: &Packet) -> Option<Packet> {
        Some(packet.clone())
    }

    fn parse(&self, packet_buf: &mut Vec<u8>) -> Option<Packet> {
        todo!()
    }
}

#[tokio::main]
async fn main() {
    env_logger::init();
    let mut proxy = RewriteReverseProxy::new();
    let processor = PassthruPacketProcessor {};
    let rules = PacketRules {
        bind_addr: "0.0.0.0:11111".to_string(),
        server_addr: "0.0.0.0:3304".to_string(),
        processor: Box::new(processor)
    };
    proxy.add_proxy(Box::new(rules)).await;
    proxy.run().await;
    println!("Hello, world!");
}
