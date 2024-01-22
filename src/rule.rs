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

pub trait Transformer<T, C> {
    fn transform(&self, message: &T, context: &C) -> Result<T>;
}

pub trait Encoder<T> {
    fn encode(&self, message: &T) -> Result<Packet>;
}

// #[async_trait]
pub trait Reporter<T, C> {
    fn report(&self, message: &T, direction: Direction, context: &C) -> Result<()>;
}

#[derive(Clone)]
pub struct RuleSetProcessor<
        T,
        P : Parser<T, C> + Clone,
        F : Filter<T> + Clone,
        X : Transformer<T, C> + Clone,
        OX : Transformer<T, C> + Clone,
        E : Encoder<T> + Clone,
        R : Reporter<T, C> + Clone,
        C,
        CC : Fn() -> C,
> {
    pub parser: Box<P>,
    pub filter: Box<F>,
    pub transformer: Box<X>,
    pub out_transformer: Box<OX>,
    pub encoder: Box<E>,
    pub reporter: Box<R>,
    packet_type: PhantomData<T>,
    // context_type: PhantomData<C>,
    create_context: CC,
    // router: Router<T>
}

impl<T,P,F,X,OX,E,R,C,CC> PacketProcessor for RuleSetProcessor<T,P,F,X,OX,E,R,C,CC> where
    T : Clone + Send + Sync + 'static,
    P : Parser<T,C> + Clone + Send + Sync + 'static,
    F : Filter<T> + Clone + Send + Sync + 'static,
    X : Transformer<T, C> + Clone + Send + Sync + 'static,
    OX : Transformer<T, C> + Clone + Send + Sync + 'static,
    E : Encoder<T> + Clone + Send + Sync + 'static,
    R : Reporter<T, C> + Clone + Send + Sync + 'static,
    C : Clone + Send + Sync + 'static,
    CC : Fn() -> C,
{
    fn start_session(&self) -> Arc<Mutex<dyn PacketProcessingSession + Send>> {
        let context = (self.create_context)();
        let session = RuleSetSession::new(
            self.parser.as_ref(),
            self.filter.as_ref(),
            self.transformer.as_ref(),
            self.out_transformer.as_ref(),
            self.encoder.as_ref(),
            self.reporter.as_ref(),
            &context,
        );
        Arc::new(Mutex::new(session))
    }
}

pub struct RuleSetSession<
    T,
    P : Parser<T,C> + Clone,
    F : Filter<T> + Clone,
    X : Transformer<T, C> + Clone,
    OX : Transformer<T, C> + Clone,
    E : Encoder<T> + Clone,
    R : Reporter<T, C> + Clone,
    C : Clone,
> {
    pub parser: Box<P>,
    pub filter: Box<F>,
    pub transformer: Box<X>,
    pub out_transformer: Box<OX>,
    pub encoder: Box<E>,
    pub reporter: Box<R>,
    packet_type: PhantomData<T>,
    context: Box<C>,
}

pub trait PacketTransformer {
    type PacketType;
    fn transform(&self, packet: &Self::PacketType) -> Self::PacketType;
}

impl<T,P,F,X,OX,E,R,C,CC> RuleSetProcessor<T,P,F,X,OX,E,R,C,CC> where
    T : Clone,
    P : Parser<T,C> + Clone,
    F : Filter<T> + Clone,
    X : Transformer<T, C> + Clone,
    OX : Transformer<T, C> + Clone,
    E : Encoder<T> + Clone,
    R : Reporter<T, C> + Clone,
    CC : Fn() -> C + Clone,
{
    pub fn new(
        parser: &P,
        filter: &F,
        transformer: &X,
        out_transformer: &OX,
        encoder: &E,
        reporter: &R,
        create_context: &CC,
    ) -> RuleSetProcessor<T,P,F,X,OX,E,R,C,CC> {
        RuleSetProcessor {
            parser: Box::new(parser.clone()),
            filter: Box::new(filter.clone()),
            transformer: Box::new(transformer.clone()),
            out_transformer: Box::new(out_transformer.clone()),
            encoder: Box::new(encoder.clone()),
            reporter: Box::new(reporter.clone()),
            packet_type: PhantomData,
            create_context: create_context.clone(),
        }
    }

    pub fn with_reporter<RN>(&self, new_reporter: &RN) -> RuleSetProcessor<T, P, F, X, OX, E, RN, C, CC>
        where RN : Reporter<T, C> + Clone
    {
        RuleSetProcessor::new(
            &self.parser.clone(),
            &self.filter.clone(),
            &self.transformer.clone(),
            &self.out_transformer.clone(),
            &self.encoder.clone(),
            new_reporter,
            &self.create_context,
        )
    }

    pub fn with_filter<FN>(&self, new_filter: &FN) -> RuleSetProcessor<T, P, FN, X, OX, E, R, C, CC>
        where FN : Filter<T> + Clone
    {
        RuleSetProcessor::new(
            &self.parser.clone(),
            new_filter,
            &self.transformer.clone(),
            &self.out_transformer.clone(),
            &self.encoder.clone(),
            &self.reporter.clone(),
            &self.create_context,
        )
    }

    pub fn with_transformer<XN>(&self, new_transformer: &XN) -> RuleSetProcessor<T, P, F, XN, OX, E, R, C, CC>
        where XN : Transformer<T, C> + Clone
    {
        RuleSetProcessor::new(
            &self.parser,
            &self.filter,
            new_transformer,
            &self.out_transformer,
            &self.encoder,
            &self.reporter,
            &self.create_context,
        )
    }
}

impl<T,P,F,X,OX,E,R,C> RuleSetSession<T,P,F,X,OX,E,R,C> where
    T : Clone,
    P : Parser<T,C> + Clone,
    F : Filter<T> + Clone,
    X : Transformer<T, C> + Clone,
    OX : Transformer<T, C> + Clone,
    E : Encoder<T> + Clone,
    R : Reporter<T, C> + Clone,
    C : Clone,
{
    pub fn new(
        parser: &P,
        filter: &F,
        transformer: &X,
        out_transformer: &OX,
        encoder: &E,
        reporter: &R,
        context: &C,
    ) -> RuleSetSession<T,P,F,X,OX,E,R,C> {
        RuleSetSession {
            parser: Box::new(parser.clone()),
            filter: Box::new(filter.clone()),
            transformer: Box::new(transformer.clone()),
            out_transformer: Box::new(out_transformer.clone()),
            encoder: Box::new(encoder.clone()),
            reporter: Box::new(reporter.clone()),
            packet_type: PhantomData,
            context: Box::new(context.clone()),
        }
    }
}


#[async_trait]
impl<T,P,F,X,OX,E,R,C> PacketProcessingSession for RuleSetSession<T, P, F, X, OX, E, R, C> where
    T : Clone + Send + Sync,
    P : Parser<T,C> + Clone + Send + Sync,
    F : Filter<T> + Clone + Send + Sync,
    X : Transformer<T, C> + Clone + Send + Sync,
    OX : Transformer<T, C> + Clone + Send + Sync,
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
            let transformed = self.transformer.transform(&parsed, &self.context)?;
            let encoded = self.encoder.encode(&transformed)?;
            Ok(Some(encoded))
        } else {
            Ok(None)
        }
    }

    fn process_outgoing(&mut self, packet: &Packet) -> Result<Option<Packet>> {
        let parsed = self.parser.parse(packet, &mut self.context)?;
        self.reporter.report(
            &self.parser.parse(packet, &mut self.context)?,
            Direction::Backward,
            &self.context
        )?;
        let transformed = self.out_transformer.transform(&parsed, &self.context)?;
        let encoded = self.encoder.encode(&transformed)?;
        Ok(Some(encoded))
    }
}

#[derive(Debug, Clone)]
pub struct NoContext {}
impl NoContext {
    fn new() -> NoContext {
        NoContext {}
    }
}

impl<T,P,E,CC> RuleSetProcessor<T, P, NoFilter<T>, NoTransform<T>, NoTransform<T>, E, NoReport<T>, NoContext, CC> where
    T : Clone + Sync,
    P : Parser<T,NoContext> + Clone,
    E : Encoder<T> + Clone,
    CC : Fn() -> NoContext,
{
    pub fn minimal(parser: &P, encoder: &E) -> RuleSetProcessor<
        T,
        P,
        NoFilter<T>,
        NoTransform<T>,
        NoTransform<T>,
        E,
        NoReport<T>,
        NoContext,
        impl Fn() -> NoContext,
    > {
        RuleSetProcessor::new(
            parser,
            &NoFilter::new(),
            &NoTransform::new(),
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
impl<T, C> Transformer<T, C> for NoTransform<T> where T : Clone {
    fn transform(&self, message: &T, _context: &C) -> Result<T> {
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


