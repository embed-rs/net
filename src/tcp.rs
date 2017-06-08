use {TxPacket, WriteOut};
use ip_checksum;
use byteorder::{ByteOrder, NetworkEndian};
use ethernet::{EthernetPacket, EthernetAddress};
use ipv4::{Ipv4Packet, Ipv4Address};

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
    pub options: u16,
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
            header: TcpHeader { src_port, dst_port, sequence_number: 0, ack_number: 0, options:0, window_size:0 },
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
        packet.push_u16(self.header.options)?;
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
                   options: NetworkEndian::read_u16(&data[12..14]),
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
