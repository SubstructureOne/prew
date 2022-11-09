use byteorder::{BigEndian, ByteOrder};
use futures::{
    channel::mpsc::{Receiver, Sender},
    lock::Mutex,
    select,
    sink::SinkExt,
    FutureExt, StreamExt,
};
use std::{
    io::{Error, ErrorKind},
    sync::Arc,
};
use log::{debug, trace, warn};
use tokio::io::{AsyncReadExt, AsyncWriteExt, Result};
use crate::packet::{Direction, Packet, PacketProcessor};


pub struct Pipe<T: AsyncReadExt, U: AsyncWriteExt> {
    name: String,
    packet_handler: Arc<Mutex<dyn PacketProcessor + Send>>,
    direction: Direction,
    source: T,
    sink: U,
}

impl<T: AsyncReadExt + Unpin, U: AsyncWriteExt + Unpin> Pipe<T, U> {
    pub fn new(
        name: String,
        packet_handler: Arc<Mutex<dyn PacketProcessor + Send>>,
        direction: Direction,
        reader: T,
        writer: U,
    ) -> Pipe<T, U> {
        Pipe {
            name,
            packet_handler,
            direction,
            source: reader,
            sink: writer,
        }
    }

    pub async fn run(
        &mut self,
        mut other_pipe_sender: Sender<Packet>,
        other_pipe_receiver: Receiver<Packet>,
    ) -> Result<()> {
        trace!("[{}]: Running {:?} pipe loop...", self.name, self.direction);
        //let source = Arc::get_mut(&mut self.source).unwrap();
        //let sink = Arc::get_mut(&mut self.sink).unwrap();
        let mut other_pipe_receiver = other_pipe_receiver.into_future().fuse();
        let mut read_buf: Vec<u8> = vec![0_u8; 4096];
        let mut packet_buf: Vec<u8> = Vec::with_capacity(4096);
        let mut write_buf: Vec<u8> = Vec::with_capacity(4096);

        loop {
            select! {
                // Read from the source to read_buf, append to packet_buf
                read_result = self.source.read(&mut read_buf[..]).fuse() => {
                    //let n = self.source.read(&mut read_buf[..]).await?;
                    self.process_read_buf(read_result, &read_buf, &mut packet_buf, &mut write_buf, &mut other_pipe_sender).await?;
                },
                // Support short-circuit
                (packet, recv) = other_pipe_receiver => {
                    self.process_short_circuit(packet, &mut write_buf)?;
                    other_pipe_receiver = recv.into_future().fuse();
                },
            } // end select!

            // Write all to sink
            while !write_buf.is_empty() {
                let n = self.sink.write(&write_buf[..]).await?;
                let _: Vec<u8> = write_buf.drain(0..n).collect();
                self.trace(format!("{} bytes written to sink", n));
            }
        } // end loop
    } // end fn run

    async fn process_read_buf(
        &self,
        read_result: Result<usize>,
        read_buf: &[u8],
        mut packet_buf: &mut Vec<u8>,
        write_buf: &mut Vec<u8>,
        other_pipe_sender: &mut Sender<Packet>,
    ) -> Result<()> {
        if let Ok(n) = read_result {
            if n == 0 {
                let e = self.create_error(format!("Read {} bytes, closing pipe.", n));
                warn!("{}", e.to_string());
                return Err(e);
            }
            packet_buf.extend_from_slice(&read_buf[0..n]);
            self.trace(format!(
                "{} bytes read from source, {} bytes in packet_buf",
                n,
                packet_buf.len()
            ));

            // Process all packets in packet_buf, put into write_buf
            loop {
                let transformed_packet: Option<Packet> = None;
                {
                    // Scope for self.packet_handler Mutex
                    let h = self.packet_handler.lock().await;
                    if let Some(packet) = h.parse(&mut packet_buf) {
                        self.trace("Processing packet".to_string());
                        let transformed_packet: Option<Packet>;
                        transformed_packet = match self.direction {
                            Direction::Forward => h.process_incoming(&packet),
                            Direction::Backward => h.process_outgoing(&packet),
                        };
                    } else {
                        break;
                    }
                }
                match transformed_packet {
                    Some(packet) => write_buf.extend_from_slice(&packet.bytes),
                    None => {}
                }
            }
            Ok(())
        } else if let Err(e) = read_result {
            warn!(
                "[{}:{:?}]: Error reading from source",
                self.name, self.direction
            );
            Err(e)
        } else {
            Err(Error::new(ErrorKind::Other, "This should never happen"))
        }
    }

    fn process_short_circuit(&self, packet: Option<Packet>, write_buf: &mut Vec<u8>) -> Result<()> {
        if let Some(p) = packet {
            self.trace(format!(
                "Got short circuit packet of {} bytes",
                p.get_size()
            ));
            write_buf.extend_from_slice(&p.bytes);
            Ok(())
        } else {
            let e = self.create_error("other_pipe_receiver prematurely closed".to_string());
            warn!("{}", e.to_string());
            Err(e)
        }
    }

    fn debug(&self, string: String) {
        debug!("[{}:{:?}]: {}", self.name, self.direction, string);
    }

    fn trace(&self, string: String) {
        trace!("[{}:{:?}]: {}", self.name, self.direction, string);
    }

    fn create_error(&self, string: String) -> Error {
        Error::new(
            ErrorKind::Other,
            format!("[{}:{:?}]: {}", self.name, self.direction, string),
        )
    }
}
