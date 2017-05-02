use {TxPacket, WriteOut};
use ipv4::Ipv4Packet;
use arp::ArpPacket;
use core::fmt;

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct EthernetAddress([u8; 6]);

impl EthernetAddress {
    pub const fn new(addr: [u8; 6]) -> Self {
        EthernetAddress(addr)
    }

    pub fn from_bytes(bytes: &[u8]) -> Self {
        assert_eq!(bytes.len(), 6);
        let mut addr = [0; 6];
        addr.copy_from_slice(bytes);
        EthernetAddress::new(addr)
    }

    pub const fn broadcast() -> Self {
        Self::new([0xff; 6])
    }

    pub fn as_bytes(&self) -> [u8; 6] {
        self.0
    }
}

impl fmt::Debug for EthernetAddress {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}", self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5])
    }
}

#[derive(Debug)]
pub struct EthernetHeader {
    pub src_addr: EthernetAddress,
    pub dst_addr: EthernetAddress,
    pub ether_type: EtherType,
}

#[derive(Debug)]
pub struct EthernetPacket<T> {
    pub header: EthernetHeader,
    pub payload: T,
}

impl<'a> EthernetPacket<&'a [u8]> {
    pub fn new(src_addr: EthernetAddress,
               dst_addr: EthernetAddress,
               ether_type: EtherType,
               data: &'a [u8])
               -> Self {
        EthernetPacket {
            header: EthernetHeader {
                src_addr: src_addr,
                dst_addr: dst_addr,
                ether_type: ether_type,
            },
            payload: data,
        }
    }
}

impl<T> EthernetPacket<Ipv4Packet<T>> {
    pub fn new_ipv4(src_addr: EthernetAddress,
                    dst_addr: EthernetAddress,
                    ip_data: Ipv4Packet<T>)
                    -> Self {
        EthernetPacket {
            header: EthernetHeader {
                src_addr: src_addr,
                dst_addr: dst_addr,
                ether_type: EtherType::Ipv4,
            },
            payload: ip_data,
        }
    }
}

impl EthernetPacket<ArpPacket> {
    pub fn new_arp(src_addr: EthernetAddress,
                    dst_addr: EthernetAddress,
                    arp_data: ArpPacket)
                    -> Self {
        EthernetPacket {
            header: EthernetHeader {
                src_addr: src_addr,
                dst_addr: dst_addr,
                ether_type: EtherType::Arp,
            },
            payload: arp_data,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EtherType {
    Ipv4,
    Arp,
    Unknown(u16),
}

impl EtherType {
    pub fn number(&self) -> u16 {
        use self::EtherType::*;

        match *self {
            Ipv4 => 0x0800,
            Arp => 0x0806,
            Unknown(number) => number,
        }
    }
}

impl<T: WriteOut> WriteOut for EthernetPacket<T> {
    fn len(&self) -> usize {
        self.payload.len() + 2 * 6 + 2
    }

    fn write_out<P: TxPacket>(&self, packet: &mut P) -> Result<(), ()> {
        packet.push_bytes(&self.header.dst_addr.as_bytes())?;
        packet.push_bytes(&self.header.src_addr.as_bytes())?;
        packet.push_u16(self.header.ether_type.number())?;

        self.payload.write_out(packet)?;

        Ok(())
    }
}

use parse::{Parse, ParseError};
use ipv4::Ipv4Kind;

impl<'a> Parse<'a> for EthernetPacket<&'a [u8]> {
    fn parse(data: &'a [u8]) -> Result<Self, ParseError> {
        use byteorder::{ByteOrder, NetworkEndian};

        if data.len() < 60 {
            return Err(ParseError::Truncated(data.len()));
        }

        let dst_mac = EthernetAddress::from_bytes(&data[0..6]);
        let src_mac = EthernetAddress::from_bytes(&data[6..12]);
        let ether_type = match NetworkEndian::read_u16(&data[12..14]) {
            0x0800 => EtherType::Ipv4,
            0x0806 => EtherType::Arp,
            other => EtherType::Unknown(other),
        };

        Ok(EthernetPacket::new(dst_mac, src_mac, ether_type, &data[14..]))
    }
}

#[derive(Debug)]
pub enum EthernetKind<'a> {
    Ipv4(Ipv4Packet<Ipv4Kind<'a>>),
    Arp(ArpPacket),
    Unknown(&'a [u8]),
}

impl<'a> Parse<'a> for EthernetPacket<EthernetKind<'a>> {
    fn parse(data: &'a [u8]) -> Result<Self, ParseError> {
        let ethernet = EthernetPacket::parse(data)?;
        match ethernet.header.ether_type {
            EtherType::Ipv4 => {
                let ipv4 = Ipv4Packet::parse(ethernet.payload)?;
                Ok(EthernetPacket {
                       header: ethernet.header,
                       payload: EthernetKind::Ipv4(ipv4),
                   })
            }
            EtherType::Arp => {
                let arp = ArpPacket::parse(ethernet.payload)?;
                Ok(EthernetPacket {
                    header: ethernet.header,
                    payload: EthernetKind::Arp(arp),
                })
            }
            EtherType::Unknown(_) => Err(ParseError::Unimplemented("only ipv4 parsing is supported at the moment")),
        }
    }
}
