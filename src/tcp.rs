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
        packet.push_u16(self.header.options.bits())?;
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
                   options: TcpOptions::from_bits(NetworkEndian::read_u16(&data[12..14])),
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
            TcpState::Listen | TcpState::SynReceived if packet.header.options.flags == TcpFlags::SYN => {
                self.ack_number = packet.header.sequence_number + Wrapping(1);
                let header = TcpHeader {
                    src_port: self.dst_port,
                    dst_port: self.src_port,
                    sequence_number: self.sequence_number,
                    ack_number: self.ack_number,
                    window_size: self.window_size,
                    options: TcpOptions::new(TcpFlags::SYN | TcpFlags::ACK),
                };
                self.state = TcpState::SynReceived;
                Some(TcpPacket {
                    payload: Cow::from(&EMPTY[..]),
                    header: header,
                })
            }
            TcpState::SynReceived if packet.header.options.flags == TcpFlags::ACK => {
                self.sequence_number += Wrapping(1);
                self.state = TcpState::Established;
                None
            }
            TcpState::LastAck if packet.header.options.flags == TcpFlags::ACK => {
                self.state = TcpState::Closed;
                None
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

                if packet.header.options.flags == TcpFlags::ACK && packet.payload.len() == 0 {
                    return None; // don't react to ACKs
                }

                if packet.header.options.flags.contains(TcpFlags::FIN) {
                    let options = TcpOptions::new(TcpFlags::ACK | TcpFlags::FIN);
                    self.ack_number += Wrapping(1);
                    let header = TcpHeader {
                        src_port: self.dst_port,
                        dst_port: self.src_port,
                        sequence_number: self.sequence_number,
                        ack_number: self.ack_number,
                        window_size: 1000, // TODO
                        options,
                    };
                    self.state = TcpState::LastAck;
                    self.sequence_number += Wrapping(1);
                    return Some(TcpPacket {
                        payload: Cow::from(&EMPTY[..]),
                        header: header,
                    });
                }

                let header = TcpHeader {
                    src_port: self.dst_port,
                    dst_port: self.src_port,
                    sequence_number: self.sequence_number,
                    ack_number: self.ack_number,
                    window_size: self.window_size,
                    options: TcpOptions::new(TcpFlags::ACK),
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
    header_len: u16,
    flags: TcpFlags,
}

impl TcpOptions {
    pub fn new(flags: TcpFlags) -> Self {
        TcpOptions {
            header_len: 5,
            flags: flags,
        }
    }

    pub fn from_bits(bits: u16) -> Self {
        TcpOptions {
            header_len: bits.get_bits(12..16), // TODO
            flags: TcpFlags::from_bits_truncate(bits),
        }
    }

    pub fn bits(&self) -> u16 {
        self.flags.bits() | (self.header_len << 12) // TODO
    }
}

bitflags! {
    pub struct TcpFlags: u16 {
        const NS = 1 << 8;
        const CWR = 1 << 7;
        const ECE = 1 << 6;
        const URG = 1 << 5;
        const ACK = 1 << 4;
        const PSH = 1 << 3;
        const RST = 1 << 2;
        const SYN = 1 << 1;
        const FIN = 1 << 0;
    }
}
