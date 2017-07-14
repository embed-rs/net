use {TxPacket, WriteOut};
use ip_checksum;
use byteorder::{ByteOrder, NetworkEndian};
use ipv4::Ipv4Address;
use alloc::borrow::Cow;
use bit_field::BitField;
use core::num::Wrapping;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TcpHeader {
    pub src_port: u16,
    pub dst_port: u16,
    pub sequence_number: Wrapping<u32>,
    pub ack_number: Wrapping<u32>,
    pub options: TcpOptions,
    pub window_size: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TcpPacket<T> {
    pub header: TcpHeader,
    pub payload: T,
}

impl<T: WriteOut> WriteOut for TcpPacket<T> {
    fn len(&self) -> usize {
        self.payload.len() + 6 * 2 + 2 * 4
    }

    fn write_out<P: TxPacket>(&self, packet: &mut P) -> Result<(), ()> {
        let start_index = packet.len();

        packet.push_u16(self.header.src_port)?;
        packet.push_u16(self.header.dst_port)?;
        packet.push_u32(self.header.sequence_number.0)?;
        packet.push_u32(self.header.ack_number.0)?;
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

        let header_len = data[12].get_bits(4..8);
        let header_len_bytes = usize::from(header_len) * 4;
        Ok(TcpPacket {
               header: TcpHeader {
                   src_port: NetworkEndian::read_u16(&data[0..2]),
                   dst_port: NetworkEndian::read_u16(&data[2..4]),
                   sequence_number: Wrapping(NetworkEndian::read_u32(&data[4..8])),
                   ack_number: Wrapping(NetworkEndian::read_u32(&data[8..12])),
                   options: TcpOptions::from_bytes(data[12], data[13]),
                   window_size: NetworkEndian::read_u16(&data[14..16]),
               },
               payload: &data[header_len_bytes..],
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
    sequence_number: Wrapping<u32>,
    ack_number: Wrapping<u32>,
    window_size: u16,
}

impl TcpConnection {
    pub fn new(id: (Ipv4Address, Ipv4Address, u16, u16)) -> TcpConnection {
        TcpConnection {
            src_ip: id.0,
            dst_ip: id.1,
            src_port: id.2,
            dst_port: id.3,
            state: TcpState::Listen,
            sequence_number: Wrapping(0x12345), // TODO random
            ack_number: Wrapping(0),
            window_size: 1000, // TODO
        }
    }

    pub fn handle_packet<'a, F>(&mut self, packet: &'a TcpPacket<&[u8]>, mut f: F) -> Option<TcpPacket<Cow<'a, [u8]>>>
        where for<'d> F: FnMut(&TcpConnection, &'d [u8]) -> Option<Cow<'d, [u8]>>
    {
        static EMPTY: [u8; 0] = [];

        match self.state {
            TcpState::Closed => None,
            TcpState::Listen | TcpState::SynReceived if packet.header.options.syn() => {
                assert!(!packet.header.options.ack()); // TODO avoid panic
                self.ack_number = packet.header.sequence_number + Wrapping(1);
                let header = TcpHeader {
                    src_port: self.dst_port,
                    dst_port: self.src_port,
                    sequence_number: self.sequence_number,
                    ack_number: self.ack_number,
                    window_size: self.window_size,
                    options: TcpOptions::new_syn_ack(),
                };
                self.state = TcpState::SynReceived;
                self.sequence_number += Wrapping(1);
                Some(TcpPacket {
                    payload: Cow::from(&EMPTY[..]),
                    header: header,
                })
            }
            TcpState::SynReceived if packet.header.options.ack() => {
                self.state = TcpState::Established;
                None
            }
            TcpState::LastAck if packet.header.options.ack() => {
                self.state = TcpState::Closed;
                None
            }
            TcpState::Established if packet.header.options.fin() => {
                let mut options = TcpOptions::new_ack();
                options.set_fin(true);
                let header = TcpHeader {
                    src_port: self.dst_port,
                    dst_port: self.src_port,
                    sequence_number: self.sequence_number,
                    ack_number: packet.header.sequence_number + Wrapping(1),
                    window_size: 1000, // TODO
                    options,
                };
                self.state = TcpState::LastAck;
                self.sequence_number += Wrapping(1);
                Some(TcpPacket {
                    payload: Cow::from(&EMPTY[..]),
                    header: header,
                })
            }
            TcpState::Established => {
                if packet.header.sequence_number == self.ack_number {
                    self.ack_number += Wrapping(packet.payload.len() as u32);
                } else if packet.header.sequence_number < self.ack_number {
                    // old packet, do nothing
                    return None;
                } else {
                    panic!("TCP packet out of order. Expected seq no: {}, received: {}", self.ack_number, packet.header.sequence_number);
                }

                if packet.header.options.ack() && packet.payload.len() == 0 {
                    return None; // don't react to ACKs
                }

                let header = TcpHeader {
                    src_port: self.dst_port,
                    dst_port: self.src_port,
                    sequence_number: self.sequence_number,
                    ack_number: self.ack_number,
                    window_size: self.window_size,
                    options: TcpOptions::new_ack(),
                };

                let reply = f(self, packet.payload).map(|payload| TcpPacket {
                        payload, header,
                    });
                if let Some(ref r) = reply {
                    self.sequence_number += Wrapping(r.payload.len() as u32);
                }
                Some(reply.unwrap_or(TcpPacket {header, payload: Cow::from(&EMPTY[..])}))
            },
            _ => None, // TODO
        }
    }
}


/// The state of a TCP socket, according to [RFC 793][rfc793].
/// [rfc793]: https://tools.ietf.org/html/rfc793
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum TcpState {
    Closed,
    Listen,
    SynSent,
    SynReceived,
    Established,
    FinWait1,
    FinWait2,
    CloseWait,
    Closing,
    LastAck,
    TimeWait
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

    pub fn new_ack() -> Self {
        let mut options = Self::new();
        options.set_ack(true);
        options
    }

    pub fn new_syn_ack() -> Self {
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

    pub fn set_fin(&mut self, value: bool) {
        self.flags.set_bit(0, value);
    }
}