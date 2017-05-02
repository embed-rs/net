use {TxPacket, WriteOut, ip_checksum};
use udp::UdpPacket;
use icmp::IcmpPacket;
use core::convert::TryInto;
use core::fmt;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Ipv4Address([u8; 4]);

impl Ipv4Address {
    pub fn new(a0: u8, a1: u8, a2: u8, a3: u8) -> Self {
        Ipv4Address([a0, a1, a2, a3])
    }

    pub fn from_bytes(bytes: &[u8]) -> Self {
        let mut inner = [0; 4];
        inner.copy_from_slice(bytes);
        Ipv4Address(inner)
    }

    pub fn as_bytes(&self) -> [u8; 4] {
        self.0
    }
}

impl fmt::Debug for Ipv4Address {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}.{}.{}.{}", self.0[0], self.0[1], self.0[2], self.0[3])
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpProtocol {
    Icmp,
    Udp,
    Tcp,
    Unknown(u8),
}

impl IpProtocol {
    pub fn from_number(number: u8) -> IpProtocol {
        use self::IpProtocol::*;

        match number {
            1 => Icmp,
            6 => Tcp,
            17 => Udp,
            number => Unknown(number),
        }
    }

    pub fn number(&self) -> u8 {
        use self::IpProtocol::*;

        match *self {
            Icmp => 1,
            Tcp => 6,
            Udp => 17,
            Unknown(number) => number,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ipv4Header {
    pub src_addr: Ipv4Address,
    pub dst_addr: Ipv4Address,
    protocol: IpProtocol,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ipv4Packet<T> {
    pub header: Ipv4Header,
    pub payload: T,
}

impl<T> Ipv4Packet<UdpPacket<T>> {
    pub fn new_udp(src_addr: Ipv4Address, dst_addr: Ipv4Address, udp: UdpPacket<T>) -> Self {
        Ipv4Packet {
            header: Ipv4Header {
                src_addr: src_addr,
                dst_addr: dst_addr,
                protocol: IpProtocol::Udp,
            },
            payload: udp,
        }
    }
}

impl<T> Ipv4Packet<IcmpPacket<T>> {
    pub fn new_icmp(src_addr: Ipv4Address, dst_addr: Ipv4Address, icmp: IcmpPacket<T>) -> Self {
        Ipv4Packet {
            header: Ipv4Header {
                src_addr: src_addr,
                dst_addr: dst_addr,
                protocol: IpProtocol::Icmp,
            },
            payload: icmp,
        }
    }
}

impl<T> Ipv4Packet<T> {
    fn header_len(&self) -> u8 {
        20
    }
}

impl<T: WriteOut> Ipv4Packet<T> {
    fn write_out_impl<P: TxPacket>(&self, packet: &mut P) -> Result<(), ()> {
        let start_index = packet.len();

        packet.push_byte(4 << 4 | self.header_len() / 4)?; // version and header_len
        packet.push_byte(0)?; // dscp_ecn
        let total_len = self.len().try_into().unwrap();
        packet.push_u16(total_len)?; // total_len

        packet.push_u16(0)?; // identification
        packet.push_u16(1 << 14)?; // flags and fragment_offset (bit 14 == don't fragment)

        packet.push_byte(64)?; // time to live
        packet.push_byte(self.header.protocol.number())?; // protocol
        let checksum_idx = packet.push_u16(0)?; // checksum

        packet.push_bytes(&self.header.src_addr.as_bytes())?;
        packet.push_bytes(&self.header.dst_addr.as_bytes())?;

        let end_index = packet.len();

        // calculate ip checksum
        let checksum = !ip_checksum::data(&packet[start_index..end_index]);
        packet.set_u16(checksum_idx, checksum);

        Ok(())
    }
}

impl<T: WriteOut> WriteOut for Ipv4Packet<T> {
    fn len(&self) -> usize {
        self.payload.len() + usize::from(self.header_len())
    }

    default fn write_out<P: TxPacket>(&self, packet: &mut P) -> Result<(), ()> {
        self.write_out_impl(packet)?;
        self.payload.write_out(packet)
    }
}

impl<T: WriteOut> WriteOut for Ipv4Packet<UdpPacket<T>> {
    fn write_out<P: TxPacket>(&self, packet: &mut P) -> Result<(), ()> {
        self.write_out_impl(packet)?;

        let udp_start_index = packet.len();
        self.payload.write_out(packet)?;

        // calculate udp checksum
        let pseudo_header_checksum = !ip_checksum::pseudo_header(&self.header.src_addr,
                                                                 &self.header.dst_addr,
                                                                 self.header.protocol,
                                                                 self.payload.len());

        let udp_checksum_idx = udp_start_index + 3 * 2;
        packet.update_u16(udp_checksum_idx, |checksum| {
            let checksums = [checksum, pseudo_header_checksum];
            ip_checksum::combine(&checksums)
        });

        Ok(())
    }
}

use parse::{Parse, ParseError};
use udp::UdpKind;

impl<'a> Parse<'a> for Ipv4Packet<&'a [u8]> {
    fn parse(data: &'a [u8]) -> Result<Self, ParseError> {
        Ok(Ipv4Packet {
               header: Ipv4Header {
                   src_addr: Ipv4Address::from_bytes(&data[12..16]),
                   dst_addr: Ipv4Address::from_bytes(&data[16..20]),
                   protocol: IpProtocol::from_number(data[9]),
               },
               payload: &data[20..],
           })
    }
}

#[derive(Debug)]
pub enum Ipv4Kind<'a> {
    Udp(UdpPacket<UdpKind<'a>>),
    Icmp(IcmpPacket<&'a [u8]>),
    Unknown(u8, &'a [u8]),
}

impl<'a> Parse<'a> for Ipv4Packet<Ipv4Kind<'a>> {
    fn parse(data: &'a [u8]) -> Result<Self, ParseError> {
        let ip = Ipv4Packet::parse(data)?;
        match ip.header.protocol {
            IpProtocol::Udp => {
                let udp = UdpPacket::parse(ip.payload)?;
                Ok(Ipv4Packet {
                       header: ip.header,
                       payload: Ipv4Kind::Udp(udp),
                   })
            }
            IpProtocol::Icmp => {
                let icmp = IcmpPacket::parse(ip.payload)?;
                Ok(Ipv4Packet {
                       header: ip.header,
                       payload: Ipv4Kind::Icmp(icmp),
                   })
            }
            IpProtocol::Unknown(number) => {
                Ok(Ipv4Packet {
                       header: ip.header,
                       payload: Ipv4Kind::Unknown(number, ip.payload),
                   })
            }
            _ => return Err(ParseError::Unimplemented("unimplemented ip protocol")),
        }
    }
}

#[test]
fn checksum() {
    use test::{Empty, HexDumpPrint};
    use HeapTxPacket;

    let ip = Ipv4Packet {
        header: Ipv4Header {
            src_addr: Ipv4Address::new(141, 52, 45, 122),
            dst_addr: Ipv4Address::new(255, 255, 255, 255),
            protocol: IpProtocol::Udp,
        },
        payload: Empty,
    };

    let mut packet = HeapTxPacket::new(ip.len());
    ip.write_out(&mut packet).unwrap();


    let data = packet.0.as_slice();
    let reference_data = &[0x45, 0x00, 0x00, 0x14, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11, 0x80, 0x2b,
                           0x8d, 0x34, 0x2d, 0x7a, 0xff, 0xff, 0xff, 0xff];

    assert_eq!(data,
               reference_data,
               "{:?}=== vs ==={:?}",
               HexDumpPrint(data),
               HexDumpPrint(reference_data));
}
