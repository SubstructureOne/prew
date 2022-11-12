use crate::packet::Packet;

type Parser<T> = fn(&Packet) -> T;
type Filter<T> = fn (&T) -> bool;
type Transformer<T> = fn(&T) -> T;
type Encoder<T> = fn(&T) -> Packet;
// type Router = fn(Packet) -> ServerInfo;


#[derive(Clone)]
pub struct PrewRuleSet<T> {
    parser: Parser<T>,
    filter: Filter<T>,
    transformer: Transformer<T>,
    encoder: Encoder<T>,
    // router: Router<T>
}

impl<T> PrewRuleSet<T> {
    pub fn new(
        parser: Parser<T>,
        filter: Filter<T>,
        transformer: Transformer<T>,
        encoder: Encoder<T>
    ) -> PrewRuleSet<T> {
        PrewRuleSet {
            parser,
            filter,
            transformer,
            encoder
        }
    }
}
