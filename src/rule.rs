use std::marker::PhantomData;

use anyhow::Result;
use async_trait::async_trait;
use tokio::sync::RwLock;

use crate::packet::{Direction, Packet, PacketProcessor, SessionContext};
use crate::read_postgresql_packet;


#[derive(Debug)]
pub struct AuthenticationContext {
    pub username: Option<String>,
    pub authenticated: bool,
}
impl AuthenticationContext {
    pub fn new() -> AuthenticationContext {
        AuthenticationContext { username: None, authenticated: false }
    }
}

pub trait WithAuthenticationContext {
    fn authinfo(&self) -> &RwLock<AuthenticationContext>;
}

#[derive(Debug, Clone)]
pub struct DefaultContext {
    pub authinfo: RwLock<AuthenticationContext>,
    // pub client: Arc<Client>,
}
impl WithAuthenticationContext for DefaultContext {
    fn authinfo(&self) -> &RwLock<AuthenticationContext> {
        &self.authinfo
    }
}
impl SessionContext for DefaultContext {
    fn new() -> Self {
        DefaultContext {
            authinfo: RwLock::new(AuthenticationContext::new()),
            // client: Arc::new(client),
        }
    }
}

#[async_trait]
pub trait Parser<T, C> {
    async fn parse(&self, packet: &Packet, context: &C) -> Result<T>;
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
pub trait Reporter<T, C> {
    async fn report(&self, message: &T, direction: Direction, context: &C) -> Result<()>;
}

#[derive(Clone)]
pub struct PrewRuleSet<
        T,
        P : Parser<T,C> + Clone,
        F : Filter<T> + Clone,
        X : Transformer<T> + Clone,
        E : Encoder<T> + Clone,
        R : Reporter<T, C> + Clone,
        C : SessionContext + Clone,
> {
    pub parser: Box<P>,
    pub filter: Box<F>,
    pub transformer: Box<X>,
    pub encoder: Box<E>,
    pub reporter: Box<R>,
    packet_type: PhantomData<T>,
    context_type: PhantomData<C>,
    // router: Router<T>
}

pub trait PacketTransformer {
    type PacketType;
    fn transform(&self, packet: &Self::PacketType) -> Self::PacketType;
}

impl<T,P,F,X,E,R,C> PrewRuleSet<T,P,F,X,E,R,C> where
    T : Clone,
    P : Parser<T,C> + Clone,
    F : Filter<T> + Clone,
    X : Transformer<T> + Clone,
    E : Encoder<T> + Clone,
    R : Reporter<T, C> + Clone,
    C : SessionContext + Clone,
{
    pub fn new(
        parser: &P,
        filter: &F,
        transformer: &X,
        encoder: &E,
        reporter: &R,
    ) -> PrewRuleSet<T,P,F,X,E,R,C> {
        PrewRuleSet {
            parser: Box::new(parser.clone()),
            filter: Box::new(filter.clone()),
            transformer: Box::new(transformer.clone()),
            encoder: Box::new(encoder.clone()),
            reporter: Box::new(reporter.clone()),
            packet_type: PhantomData,
            context_type: PhantomData,
        }
    }

    pub fn with_reporter<RN>(&self, new_reporter: &RN) -> PrewRuleSet<T, P, F, X, E, RN, C>
        where RN : Reporter<T, C> + Clone
    {
        PrewRuleSet::new(
            &self.parser.clone(),
            &self.filter.clone(),
            &self.transformer.clone(),
            &self.encoder.clone(),
            new_reporter
        )
    }

    pub fn with_filter<FN>(&self, new_filter: &FN) -> PrewRuleSet<T, P, FN, X, E, R, C>
        where FN : Filter<T> + Clone
    {
        PrewRuleSet::new(
            &self.parser.clone(),
            new_filter,
            &self.transformer.clone(),
            &self.encoder.clone(),
            &self.reporter.clone()
        )
    }

    pub fn with_transformer<XN>(&self, new_transformer: &XN) -> PrewRuleSet<T, P, F, XN, E, R, C>
        where XN : Transformer<T> + Clone
    {
        PrewRuleSet::new(
            &self.parser.clone(),
            &self.filter.clone(),
            new_transformer,
            &self.encoder.clone(),
            &self.reporter.clone()
        )
    }
}

#[async_trait]
impl<T,P,F,X,E,R,C> PacketProcessor for PrewRuleSet<T, P, F, X, E, R, C> where
    T : Clone + Sync + Send,
    P : Parser<T,C> + Clone + Sync + Send,
    F : Filter<T> + Clone + Sync + Send,
    X : Transformer<T> + Clone + Sync + Send,
    E : Encoder<T> + Clone + Sync + Send,
    R : Reporter<T, C> + Clone + Sync + Send,
    C : SessionContext + Clone + Sync + Send,
{
    fn start_session(&self) -> Box<&dyn SessionContext> {
        Box::new(C::new())
    }

    fn parse(&self, packet_buf: &mut Vec<u8>) -> Result<Option<Packet>> {
        // FIXME: assuming Postgres type packets
        read_postgresql_packet(packet_buf)
    }

    async fn process_incoming(&self, packet: &Packet, context: &C) -> Result<Option<Packet>> {
        let parsed = self.parser.parse(packet, context).await?;
        self.reporter.report(&parsed, Direction::Forward, context).await?;
        if self.filter.filter(&parsed) {
            let transformed = self.transformer.transform(&parsed)?;
            let encoded = self.encoder.encode(&transformed)?;
            Ok(Some(encoded))
        } else {
            Ok(None)
        }
    }

    async fn process_outgoing(&self, packet: &Packet, context: &C) -> Result<Option<Packet>> {
        self.reporter.report(
            &self.parser.parse(packet, context).await?,
            Direction::Backward,
            context
        ).await?;
        Ok(Some(packet.clone()))
    }
}

#[derive(Debug, Clone)]
pub struct NoContext {}
impl SessionContext for NoContext {
    fn new() -> Self {
        NoContext {}
    }
}

impl<T,P,E> PrewRuleSet<T, P, NoFilter<T>, NoTransform<T>, E, NoReport<T>, NoContext>
    where T : Clone + Sync, P : Parser<T,NoContext> + Clone, E : Encoder<T> + Clone
{
    pub fn minimal(parser: &P, encoder: &E) -> PrewRuleSet<
        T,
        P,
        NoFilter<T>,
        NoTransform<T>,
        E,
        NoReport<T>,
        NoContext,
    > {
        PrewRuleSet::new(
            parser,
            &NoFilter::new(),
            &NoTransform::new(),
            encoder,
            &NoReport::new(),
        )
    }
}


#[derive(Clone)]
pub struct NoParserEncoder {}
impl NoParserEncoder {
    pub fn new() -> NoParserEncoder {
        NoParserEncoder {}
    }
}
#[async_trait]
impl Parser<Packet,NoContext> for NoParserEncoder {
    async fn parse(&self, packet: &Packet, _context: &NoContext) -> Result<Packet> {
        Ok(packet.clone())
    }
}
impl Encoder<Packet> for NoParserEncoder {
    fn encode(&self, message: &Packet) -> Result<Packet> {
        Ok(message.clone())
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
impl<T: Sync, C> Reporter<T, C> for NoReport<T> {
    async fn report(&self, _message: &T, _direction: Direction, _context: &C) -> Result<()> {
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


