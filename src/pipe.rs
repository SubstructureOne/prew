use std::{
    // io::{Error, ErrorKind},
    sync::Arc,
};

use anyhow::{Result, anyhow};
use futures::lock::Mutex;
use log::{trace};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::packet::{Direction, Packet, PacketProcessingSession, PacketProcessor};


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
        session: &Arc<Mutex<dyn PacketProcessingSession + Send>>,
    ) -> Result<()> {
        trace!("[{}]: Running {:?} pipe loop...", self.name, self.direction);
        //let source = Arc::get_mut(&mut self.source).unwrap();
        //let sink = Arc::get_mut(&mut self.sink).unwrap();
        let mut read_buf: Vec<u8> = vec![0_u8; 4096];
        let mut packet_buf: Vec<u8> = Vec::with_capacity(4096);
        let mut write_buf: Vec<u8> = Vec::with_capacity(4096);

        loop {
            let read_result = self.source.read(&mut read_buf[..]).await?;
            self.process_read_buf(
                &session,
                read_result,
                &read_buf,
                &mut packet_buf,
                &mut write_buf,
                // &mut other_pipe_sender
            ).await?;

            // Write all to sink
            while !write_buf.is_empty() {
                let n = self.sink.write(&write_buf[..]).await?;
                let _: Vec<u8> = write_buf.drain(0..n).collect();
                self.trace(format!("{} bytes written to sink", n));
            }
        }
    }

    async fn process_read_buf(
        &self,
        session: &Arc<Mutex<dyn PacketProcessingSession + Send>>,
        n: usize,
        read_buf: &[u8],
        mut packet_buf: &mut Vec<u8>,
        write_buf: &mut Vec<u8>,
    ) -> Result<()> {
        if n == 0 {
            return Err(anyhow!("Read {} bytes, closing pipe.", n));
        }
        packet_buf.extend_from_slice(&read_buf[0..n]);
        self.trace(format!(
            "{} bytes read from source, {} bytes in packet_buf",
            n,
            packet_buf.len()
        ));



        // Process all packets in packet_buf, put into write_buf
        loop {
            let transformed_packet: Option<Packet>;
            {
                // Scope for self.packet_handler Mutex
                let mut h = session.lock().await;
                if let Ok(Some(packet)) = h.parse(&mut packet_buf) {
                    self.trace("Processing packet".to_string());
                    transformed_packet = match self.direction {
                        Direction::Forward => h.process_incoming(&packet)?,
                        Direction::Backward => h.process_outgoing(&packet)?,
                    };
                    self.trace(format!("Transformed packet: {:?}", transformed_packet));
                } else {
                    break;
                }
            }
            match transformed_packet {
                Some(packet) => {
                    self.trace(format!("Adding {} bytes to write buffer", packet.bytes.len()));
                    write_buf.extend_from_slice(&packet.bytes)
                },
                None => {
                    self.trace(format!("No packet found"));
                }
            }
        }
        Ok(())
    }

    // fn debug(&self, string: String) {
    //     debug!("[{}:{:?}]: {}", self.name, self.direction, string);
    // }

    fn trace(&self, string: String) {
        trace!("[{}:{:?}]: {}", self.name, self.direction, string);
    }
}
