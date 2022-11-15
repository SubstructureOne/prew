use std::marker::PhantomData;
use crate::packet::{Packet, PacketProcessor};

pub trait Parser<T> {
    fn parse(&self, packet: &Packet) -> T;
}

pub trait Filter<T> {
    fn filter(&self, message: &T) -> bool;
}

pub trait Transformer<T> {
    fn transform(&self, message: &T) -> T;
}

pub trait Encoder<T> {
    fn encode(&self, message: &T) -> Packet;
}

#[derive(Clone)]
pub struct PrewRuleSet<
        T,
        P : Parser<T> + Clone,
        F : Filter<T> + Clone,
        X : Transformer<T> + Clone,
        E : Encoder<T> + Clone
> {
    pub parser: Box<P>,
    pub filter: Box<F>,
    pub transformer: Box<X>,
    pub encoder: Box<E>,
    packet_type: PhantomData<T>
    // router: Router<T>
}

pub trait PacketTransformer {
    type PacketType;
    fn transform(&self, packet: &Self::PacketType) -> Self::PacketType;
}

impl<T,P,F,X,E> PrewRuleSet<T,P,F,X,E> where
    T : Clone,
    P : Parser<T> + Clone,
    F : Filter<T> + Clone,
    X : Transformer<T> + Clone,
    E : Encoder<T> + Clone
{
    pub fn new(
        parser: &P,
        filter: &F,
        transformer: &X,
        encoder: &E,
    ) -> PrewRuleSet<T,P,F,X,E> {
        PrewRuleSet {
            parser: Box::new(parser.clone()),
            filter: Box::new(filter.clone()),
            transformer: Box::new(transformer.clone()),
            encoder: Box::new(encoder.clone()),
            packet_type: PhantomData,
        }
    }
}
// impl<T,P,F,X,E> PacketProcessor for PrewRuleSet<T,P,F,X,E> where
//     T : Clone,
//     P : Parser<T> + Clone,
//     F : Filter<T> + Clone,
//     X : Transformer<T> + Clone,
//     E : Encoder<T> + Clone
// {
//     fn parse(&self, packet_buf: &mut Vec<u8>) -> Option<Packet> {
//         Some(self.parser.parse(packet_buf))
//     }
//
//     fn process_incoming(&self, packet: &Packet) -> Option<Packet> {
//         todo!()
//     }
//
//     fn process_outgoing(&self, packet: &Packet) -> Option<Packet> {
//         todo!()
//     }
// }

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
    fn transform(&self, message: &T) -> T {
        message.clone()
    }
}
impl<T> NoTransform<T> {
    pub fn new() -> NoTransform<T> {
        NoTransform { message_type: PhantomData }
    }
}


pub trait Encodable {
    fn encode(&self) -> Packet;
}

#[derive(Clone)]
pub struct MessageEncoder<T: Encodable> {
    message_type: PhantomData<T>
}
impl<T> Encoder<T> for MessageEncoder<T> where T : Encodable {
    fn encode(&self, message: &T) -> Packet {
        return message.encode();
    }
}
impl<T> MessageEncoder<T> where T : Encodable {
    pub fn new() -> MessageEncoder<T> {
        MessageEncoder { message_type: PhantomData }
    }
}


