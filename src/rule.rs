use std::marker::PhantomData;

use anyhow::Result;

use async_trait::async_trait;

use crate::packet::{Direction, Packet};

pub trait Parser<T> {
    fn parse(&self, packet: &Packet) -> Result<T>;
}

pub trait Filter<T> {
    fn filter(&self, message: &T) -> bool;
}

pub trait Transformer<T> {
    fn transform(&self, message: &T) -> Result<T>;
}

pub trait Encoder<T> {
    fn encode(&self, message: &T) -> Result<Packet>;
}

#[async_trait]
pub trait Reporter<T> {
    async fn report(&self, message: &T, direction: Direction) -> Result<()>;
}

#[derive(Clone)]
pub struct PrewRuleSet<
        T,
        P : Parser<T> + Clone,
        F : Filter<T> + Clone,
        X : Transformer<T> + Clone,
        E : Encoder<T> + Clone,
        R : Reporter<T> + Clone,
> {
    pub parser: Box<P>,
    pub filter: Box<F>,
    pub transformer: Box<X>,
    pub encoder: Box<E>,
    pub reporter: Box<R>,
    packet_type: PhantomData<T>
    // router: Router<T>
}

pub trait PacketTransformer {
    type PacketType;
    fn transform(&self, packet: &Self::PacketType) -> Self::PacketType;
}

impl<T,P,F,X,E,R> PrewRuleSet<T,P,F,X,E,R> where
    T : Clone,
    P : Parser<T> + Clone,
    F : Filter<T> + Clone,
    X : Transformer<T> + Clone,
    E : Encoder<T> + Clone,
    R : Reporter<T> + Clone,
{
    pub fn new(
        parser: &P,
        filter: &F,
        transformer: &X,
        encoder: &E,
        reporter: &R,
    ) -> PrewRuleSet<T,P,F,X,E,R> {
        PrewRuleSet {
            parser: Box::new(parser.clone()),
            filter: Box::new(filter.clone()),
            transformer: Box::new(transformer.clone()),
            encoder: Box::new(encoder.clone()),
            reporter: Box::new(reporter.clone()),
            packet_type: PhantomData,
        }
    }
}

#[derive(Clone)]
pub struct NoFilter<T> {
    message_type: PhantomData<T>
}
impl<T> Filter<T> for NoFilter<T> {
    fn filter(&self, _message: &T) -> bool {
        return true;
    }
}
impl<T> NoFilter<T> {
    pub fn new() -> NoFilter<T> {
        NoFilter { message_type: PhantomData }
    }
}

#[derive(Clone)]
pub struct NoTransform<T> {
    message_type: PhantomData<T>
}
impl<T> Transformer<T> for NoTransform<T> where T : Clone {
    fn transform(&self, message: &T) -> Result<T> {
        Ok(message.clone())
    }
}
impl<T> NoTransform<T> {
    pub fn new() -> NoTransform<T> {
        NoTransform { message_type: PhantomData }
    }
}

#[derive(Clone)]
pub struct NoReport<T: Sync> {
    message_type: PhantomData<T>
}
#[async_trait]
impl<T: Sync> Reporter<T> for NoReport<T> {
    async fn report(&self, _message: &T, _direction: Direction) -> Result<()> {
        Ok(())
    }
}
impl<T: Sync> NoReport<T> {
    pub fn new() -> NoReport<T> {
        NoReport { message_type: PhantomData }
    }
}


pub trait Encodable {
    fn encode(&self) -> Result<Packet>;
}

#[derive(Clone)]
pub struct MessageEncoder<T: Encodable> {
    message_type: PhantomData<T>
}
impl<T> Encoder<T> for MessageEncoder<T> where T : Encodable {
    fn encode(&self, message: &T) -> Result<Packet> {
        message.encode()
    }
}
impl<T> MessageEncoder<T> where T : Encodable {
    pub fn new() -> MessageEncoder<T> {
        MessageEncoder { message_type: PhantomData }
    }
}


