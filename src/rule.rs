use std::marker::PhantomData;
use std::sync::Arc;

use anyhow::Result;
use async_trait::async_trait;
use futures::lock::Mutex;

use crate::packet::{Direction, Packet, PacketProcessingSession, PacketProcessor};
use crate::read_postgresql_packet;


#[derive(Debug, Clone)]
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
    fn authinfo(&mut self) -> &mut AuthenticationContext;
}

#[derive(Debug, Clone)]
pub struct DefaultContext {
    pub authinfo: AuthenticationContext,
}
impl WithAuthenticationContext for DefaultContext {
    fn authinfo(&mut self) -> &mut AuthenticationContext {
        &mut self.authinfo
    }
}
impl DefaultContext {
    pub fn new() -> Self {
        DefaultContext {
            authinfo: AuthenticationContext::new(),
        }
    }
}

// #[async_trait]
pub trait Parser<T, C> {
    fn parse(&self, packet: &Packet, context: &mut C) -> Result<T>;
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

// #[async_trait]
pub trait Reporter<T, C> {
    fn report(&self, message: &T, direction: Direction, context: &C) -> Result<()>;
}

#[derive(Clone)]
pub struct PrewRuleSet<
        T,
        P : Parser<T,C> + Clone,
        F : Filter<T> + Clone,
        X : Transformer<T> + Clone,
        E : Encoder<T> + Clone,
        R : Reporter<T, C> + Clone,
        C,
        CC : Fn() -> C,
> {
    pub parser: Box<P>,
    pub filter: Box<F>,
    pub transformer: Box<X>,
    pub encoder: Box<E>,
    pub reporter: Box<R>,
    packet_type: PhantomData<T>,
    // context_type: PhantomData<C>,
    create_context: CC,
    // router: Router<T>
}

impl<T,P,F,X,E,R,C,CC> PacketProcessor for PrewRuleSet<T,P,F,X,E,R,C,CC> where
    T : Clone + Send + Sync + 'static,
    P : Parser<T,C> + Clone + Send + Sync + 'static,
    F : Filter<T> + Clone + Send + Sync + 'static,
    X : Transformer<T> + Clone + Send + Sync + 'static,
    E : Encoder<T> + Clone + Send + Sync + 'static,
    R : Reporter<T, C> + Clone + Send + Sync + 'static,
    C : Clone + Send + Sync + 'static,
    CC : Fn() -> C,
{
    fn start_session(&self) -> Arc<Mutex<dyn PacketProcessingSession + Send>> {
        let context = (self.create_context)();
        let session = PrewRuleSession::new(
            self.parser.as_ref(),
            self.filter.as_ref(),
            self.transformer.as_ref(),
            self.encoder.as_ref(),
            self.reporter.as_ref(),
            &context,
        );
        Arc::new(Mutex::new(session))
    }
}

pub struct PrewRuleSession<
    T,
    P : Parser<T,C> + Clone,
    F : Filter<T> + Clone,
    X : Transformer<T> + Clone,
    E : Encoder<T> + Clone,
    R : Reporter<T, C> + Clone,
    C : Clone,
> {
    pub parser: Box<P>,
    pub filter: Box<F>,
    pub transformer: Box<X>,
    pub encoder: Box<E>,
    pub reporter: Box<R>,
    packet_type: PhantomData<T>,
    context: Box<C>,
}

pub trait PacketTransformer {
    type PacketType;
    fn transform(&self, packet: &Self::PacketType) -> Self::PacketType;
}

impl<T,P,F,X,E,R,C,CC> PrewRuleSet<T,P,F,X,E,R,C,CC> where
    T : Clone,
    P : Parser<T,C> + Clone,
    F : Filter<T> + Clone,
    X : Transformer<T> + Clone,
    E : Encoder<T> + Clone,
    R : Reporter<T, C> + Clone,
    CC : Fn() -> C + Clone,
{
    pub fn new(
        parser: &P,
        filter: &F,
        transformer: &X,
        encoder: &E,
        reporter: &R,
        create_context: &CC,
    ) -> PrewRuleSet<T,P,F,X,E,R,C,CC> {
        PrewRuleSet {
            parser: Box::new(parser.clone()),
            filter: Box::new(filter.clone()),
            transformer: Box::new(transformer.clone()),
            encoder: Box::new(encoder.clone()),
            reporter: Box::new(reporter.clone()),
            packet_type: PhantomData,
            create_context: create_context.clone(),
        }
    }

    pub fn with_reporter<RN>(&self, new_reporter: &RN) -> PrewRuleSet<T, P, F, X, E, RN, C, CC>
        where RN : Reporter<T, C> + Clone
    {
        PrewRuleSet::new(
            &self.parser.clone(),
            &self.filter.clone(),
            &self.transformer.clone(),
            &self.encoder.clone(),
            new_reporter,
            &self.create_context,
        )
    }

    pub fn with_filter<FN>(&self, new_filter: &FN) -> PrewRuleSet<T, P, FN, X, E, R, C, CC>
        where FN : Filter<T> + Clone
    {
        PrewRuleSet::new(
            &self.parser.clone(),
            new_filter,
            &self.transformer.clone(),
            &self.encoder.clone(),
            &self.reporter.clone(),
            &self.create_context,
        )
    }

    pub fn with_transformer<XN>(&self, new_transformer: &XN) -> PrewRuleSet<T, P, F, XN, E, R, C, CC>
        where XN : Transformer<T> + Clone
    {
        PrewRuleSet::new(
            &self.parser,
            &self.filter,
            new_transformer,
            &self.encoder,
            &self.reporter,
            &self.create_context,
        )
    }
}

impl<T,P,F,X,E,R,C> PrewRuleSession<T,P,F,X,E,R,C> where
    T : Clone,
    P : Parser<T,C> + Clone,
    F : Filter<T> + Clone,
    X : Transformer<T> + Clone,
    E : Encoder<T> + Clone,
    R : Reporter<T, C> + Clone,
    C : Clone,
{
    pub fn new(
        parser: &P,
        filter: &F,
        transformer: &X,
        encoder: &E,
        reporter: &R,
        context: &C,
    ) -> PrewRuleSession<T,P,F,X,E,R,C> {
        PrewRuleSession {
            parser: Box::new(parser.clone()),
            filter: Box::new(filter.clone()),
            transformer: Box::new(transformer.clone()),
            encoder: Box::new(encoder.clone()),
            reporter: Box::new(reporter.clone()),
            packet_type: PhantomData,
            context: Box::new(context.clone()),
        }
    }
}


#[async_trait]
impl<T,P,F,X,E,R,C> PacketProcessingSession for PrewRuleSession<T, P, F, X, E, R, C> where
    T : Clone + Send + Sync,
    P : Parser<T,C> + Clone + Send + Sync,
    F : Filter<T> + Clone + Send + Sync,
    X : Transformer<T> + Clone + Send + Sync,
    E : Encoder<T> + Clone + Send + Sync,
    R : Reporter<T, C> + Clone + Send + Sync,
    C : Clone + Send + Sync,
{
    fn parse(&self, packet_buf: &mut Vec<u8>) -> Result<Option<Packet>> {
        // FIXME: assuming Postgres type packets
        read_postgresql_packet(packet_buf)
    }

    fn process_incoming(&mut self, packet: &Packet) -> Result<Option<Packet>> {
        let parsed = self.parser.parse(packet, &mut self.context)?;
        self.reporter.report(&parsed, Direction::Forward, &self.context)?;
        if self.filter.filter(&parsed) {
            let transformed = self.transformer.transform(&parsed)?;
            let encoded = self.encoder.encode(&transformed)?;
            Ok(Some(encoded))
        } else {
            Ok(None)
        }
    }

    fn process_outgoing(&mut self, packet: &Packet) -> Result<Option<Packet>> {
        self.reporter.report(
            &self.parser.parse(packet, &mut self.context)?,
            Direction::Backward,
            &self.context
        )?;
        Ok(Some(packet.clone()))
    }
}

#[derive(Debug, Clone)]
pub struct NoContext {}
impl NoContext {
    fn new() -> NoContext {
        NoContext {}
    }
}

impl<T,P,E,CC> PrewRuleSet<T, P, NoFilter<T>, NoTransform<T>, E, NoReport<T>, NoContext, CC> where
    T : Clone + Sync,
    P : Parser<T,NoContext> + Clone,
    E : Encoder<T> + Clone,
    CC : Fn() -> NoContext,
{
    pub fn minimal(parser: &P, encoder: &E) -> PrewRuleSet<
        T,
        P,
        NoFilter<T>,
        NoTransform<T>,
        E,
        NoReport<T>,
        NoContext,
        impl Fn() -> NoContext,
    > {
        PrewRuleSet::new(
            parser,
            &NoFilter::new(),
            &NoTransform::new(),
            encoder,
            &NoReport::new(),
            &NoContext::new,
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
    fn parse(&self, packet: &Packet, _context: &mut NoContext) -> Result<Packet> {
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
    fn report(&self, _message: &T, _direction: Direction, _context: &C) -> Result<()> {
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


