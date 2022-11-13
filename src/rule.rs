use crate::packet::Packet;

pub type Parser<T> = fn(&Packet) -> T;
pub type Filter<T> = fn (&T) -> bool;
// pub type Transformer<T> = fn(&T) -> T;
pub type Encoder<T> = fn(&T) -> Packet;
// type Router = fn(Packet) -> ServerInfo;


#[derive(Clone)]
pub struct PrewRuleSet<T, X> where T : Clone, X : PacketTransformer {
    pub parser: Parser<T>,
    pub filter: Filter<T>,
    pub transformer: X,
    pub encoder: Encoder<T>,
    // router: Router<T>
}

pub trait PacketTransformer {
    type PacketType;
    fn transform(&self, packet: &Self::PacketType) -> Self::PacketType;
}

impl<T, X> PrewRuleSet<T, X> where T : Clone, X : PacketTransformer {
    pub fn new(
        parser: Parser<T>,
        filter: Filter<T>,
        transformer: X,
        encoder: Encoder<T>
    ) -> PrewRuleSet<T, X> {
        PrewRuleSet {
            parser,
            filter,
            transformer,
            encoder
        }
    }
}
