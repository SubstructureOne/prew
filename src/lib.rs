mod pipe;
pub mod packet;
pub mod postgresql;
pub mod rule;

use std::sync::Arc;

use futures::{
    FutureExt,
    select,
};
use futures::future::select_all;
use futures::lock::Mutex;
use log::{debug, info, trace};
use tokio::net::{TcpListener, TcpStream};

use crate::pipe::Pipe;
use packet::{Direction};

pub use crate::postgresql::{PostgresqlPacket, PostgresqlProcessor, read_postgresql_packet};
pub use crate::postgresql::{PostgresParser, AppendDbNameTransformer};
pub use crate::rule::{PrewRuleSet, NoFilter, NoReport, MessageEncoder, NoTransform};
pub use crate::rule::{Parser, Filter, Transformer, Encoder, Reporter};
pub use crate::packet::{PacketProcessor};

pub struct PacketRules {
    pub bind_addr: String,
    pub server_addr: String,
    pub processor: Arc<Mutex<dyn PacketProcessor + Send>>,
}



pub struct ProtocolProxy {
    server_addr: String,
    listener: TcpListener,
    processor: Arc<Mutex<dyn PacketProcessor + Send>>,
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

    async fn create_pipes(
        db_addr: String,
        mut client_socket: TcpStream,
        handler_ref: Arc<Mutex<dyn PacketProcessor + Send>>,
        // connstr: String,
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
                result = forward_pipe.run().fuse() => {
                    trace!("Pipe closed via forward pipe: {:?}", result);
                },
                result = backward_pipe.run().fuse() => {
                    trace!("Pipe closed via backward pipe: {:?}", result);
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
        reporter_connstr: String,
        // kill_switch_receiver: oneshot::Receiver<()>,
    ) {
        trace!("RewriteReverseProxy.run - enter");
        let listeners = self.proxies.iter()
            .map(|proxy| &proxy.listener)
            .collect::<Vec<_>>();
        let mut futures = listeners.iter()
            .map(|listener| listener.accept().boxed())
            .collect::<Vec<_>>();
        loop {
            trace!("RewriteReverseProxy.run - loop");
            let (res, idx, remaining) = select_all(futures).await;
            match res {
                Ok((socket, _addr)) => {
                    // let (tx, rx) = oneshot::channel();
                    RewriteReverseProxy::create_pipes(
                        self.proxies[idx].server_addr.clone(),
                        socket,
                        self.proxies[idx].processor.clone(),
                        // rx,
                    ).await;
                    info!("new client")
                },
                Err(e) => info!("couldn't get client: {}", e),
            }
            futures = remaining;
            futures.push(listeners[idx].accept().boxed());
        }
    }
}