use {TxPacket, WriteOut};
use ip_checksum;
use byteorder::{ByteOrder, NetworkEndian};
use ethernet::{EthernetPacket, EthernetAddress};
use ipv4::{Ipv4Packet, Ipv4Address};
use alloc::borrow::Cow;
use bit_field::BitField;

pub fn new_tcp_packet<T>(src_mac: EthernetAddress,
                         dst_mac: EthernetAddress,
                         src_ip: Ipv4Address,
                         dst_ip: Ipv4Address,
                         src_port: u16,
                         dst_port: u16,
                         payload: T)
                         -> EthernetPacket<Ipv4Packet<TcpPacket<T>>> {
    EthernetPacket::new_ipv4(src_mac,
                             dst_mac,
                             Ipv4Packet::new_tcp(src_ip,
                                                 dst_ip,
                                                 TcpPacket::new(src_port, dst_port, payload)))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TcpHeader {
    pub src_port: u16,
    pub dst_port: u16,
    pub sequence_number: u32,
    pub ack_number: u32,
    pub options: TcpOptions,
    pub window_size: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TcpPacket<T> {
    pub header: TcpHeader,
    pub payload: T,
}

impl<T> TcpPacket<T> {
    pub fn new(src_port: u16, dst_port: u16, payload: T) -> Self {
        TcpPacket {
            header: TcpHeader { src_port, dst_port, sequence_number: 0, ack_number: 0, options: TcpOptions::new(), window_size:0 },
            payload,
        }
    }
}

impl<T: WriteOut> WriteOut for TcpPacket<T> {
    fn len(&self) -> usize {
        self.payload.len() + 4 * 2
    }

    fn write_out<P: TxPacket>(&self, packet: &mut P) -> Result<(), ()> {
        let start_index = packet.len();

        packet.push_u16(self.header.src_port)?;
        packet.push_u16(self.header.dst_port)?;
        packet.push_u32(self.header.sequence_number)?;
        packet.push_u32(self.header.ack_number)?;
        packet.push_byte(self.header.options.header_len)?;
        packet.push_byte(self.header.options.flags)?;
        packet.push_u16(self.header.window_size)?;
        let checksum_idx = packet.push_u16(0)?; // checksum
        packet.push_u16(0)?; // urgent pointer

        self.payload.write_out(packet)?;
        let end_index = packet.len();

        // calculate tcp checksum (without pseudo header)
        let checksum = !ip_checksum::data(&packet[start_index..end_index]);
        packet.set_u16(checksum_idx, checksum);

        Ok(())
    }
}

use parse::{Parse, ParseError};

impl<'a> Parse<'a> for TcpPacket<&'a [u8]> {
    fn parse(data: &'a [u8]) -> Result<Self, ParseError> {
        use bit_field::BitField;

        let data_offset = data[12].get_bits(0..4);
        let data_offset_bytes = usize::from(data_offset) * 4;
        Ok(TcpPacket {
               header: TcpHeader {
                   src_port: NetworkEndian::read_u16(&data[0..2]),
                   dst_port: NetworkEndian::read_u16(&data[2..4]),
                   sequence_number: NetworkEndian::read_u32(&data[4..8]),
                   ack_number: NetworkEndian::read_u32(&data[8..12]),
                   options: TcpOptions::from_bytes(data[12], data[13]),
                   window_size: NetworkEndian::read_u16(&data[14..16]),
               },
               payload: &data[data_offset_bytes..],
           })
    }
}

#[derive(Debug)]
pub enum TcpKind<'a> {
    Unknown(&'a [u8]),
}

impl<'a> Parse<'a> for TcpPacket<TcpKind<'a>> {
    fn parse(data: &'a [u8]) -> Result<Self, ParseError> {
        let tcp = TcpPacket::parse(data)?;

        Ok(TcpPacket {
                header: tcp.header,
                payload: TcpKind::Unknown(tcp.payload),
            })
    }
}

#[derive(Debug)]
pub struct TcpConnection {
    src_ip: Ipv4Address,
    dst_ip: Ipv4Address,
    src_port: u16,
    dst_port: u16,
    state: TcpState,
}

impl TcpConnection {
    pub fn new(id: (Ipv4Address, Ipv4Address, u16, u16)) -> TcpConnection {
        TcpConnection {
            src_ip: id.0,
            dst_ip: id.1,
            src_port: id.2,
            dst_port: id.3,
            state: TcpState::Disconnected,
        }
    }

    pub fn handle_packet<'a, F>(&mut self, packet: &'a TcpPacket<&[u8]>, mut f: F) -> Option<TcpPacket<Cow<'a, [u8]>>>
        where for<'d> F: FnMut(&TcpConnection, &'d [u8]) -> Option<Cow<'d, [u8]>>
    {
        static EMPTY: [u8; 0] = [];

        match self.state {
            TcpState::Disconnected | TcpState::SynAckSent if packet.header.options.syn() => {
                let header = TcpHeader {
                    src_port: self.dst_port,
                    dst_port: self.src_port,
                    sequence_number: 42, // TODO random
                    ack_number: packet.header.sequence_number.wrapping_add(1),
                    window_size: 1000, // TODO
                    options: TcpOptions::syn_ack(),
                };
                self.state = TcpState::SynAckSent;
                Some(TcpPacket {
                    payload: Cow::from(&EMPTY[..]),
                    header: header,
                })
            }
            TcpState::SynAckSent if packet.header.options.ack() => {
                self.state = TcpState::Connected;
                None
            }
            TcpState::Connected => f(self, packet.payload).map(|d| TcpPacket::new(self.dst_port, self.src_port, d)),
            _ => None, // TODO
        }
    }
}

#[derive(Debug)]
enum TcpState {
    Disconnected,
    SynAckSent,
    Connected
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TcpOptions {
    header_len: u8,
    flags: u8
}

impl TcpOptions {
    pub fn new() -> Self {
        TcpOptions {
            header_len: 5 << 4,
            flags: 0,
        }
    }

    pub fn from_bytes(header_len: u8, flags: u8) -> Self {
        TcpOptions {
            header_len,
            flags,
        }
    }

    pub fn syn_ack() -> Self {
        let mut options = Self::new();
        options.set_syn(true);
        options.set_ack(true);
        options
    }

    pub fn header_len(&self) -> u8 {
        self.header_len.get_bits(4..8) as u8
    }

    pub fn ns(&self) -> bool {
        self.header_len.get_bit(0)
    }

    pub fn cwr(&self) -> bool {
        self.flags.get_bit(7)
    }

    pub fn ece(&self) -> bool {
        self.flags.get_bit(6)
    }

    pub fn urg(&self) -> bool {
        self.flags.get_bit(5)
    }

    pub fn ack(&self) -> bool {
        self.flags.get_bit(4)
    }

    pub fn set_ack(&mut self, value: bool) {
        self.flags.set_bit(4, value);
    }

    pub fn psh(&self) -> bool {
        self.flags.get_bit(3)
    }

    pub fn rst(&self) -> bool {
        self.flags.get_bit(2)
    }

    pub fn syn(&self) -> bool {
        self.flags.get_bit(1)
    }

    pub fn set_syn(&mut self, value: bool) {
        self.flags.set_bit(1, value);
    }

    pub fn fin(&self) -> bool {
        self.flags.get_bit(0)
    }
}