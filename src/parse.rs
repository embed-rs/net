use ethernet::{EthernetPacket, EthernetKind};

pub trait Parse<'a>: Sized {
    fn parse(data: &'a [u8]) -> Result<Self, ParseError>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseError {
    Unimplemented(&'static str),
    Malformed(&'static str),
    Truncated(usize),
}

pub fn parse(data: &[u8]) -> Result<EthernetPacket<EthernetKind>, ParseError> {
    EthernetPacket::parse(data)
}