use core::convert::TryInto;

use {TxPacket, WriteOut};
use ip_checksum;
use dhcp::DhcpPacket;
use byteorder::{ByteOrder, NetworkEndian};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UdpHeader {
    src_port: u16,
    dst_port: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UdpPacket<T> {
    pub header: UdpHeader,
    pub payload: T,
}

impl UdpPacket<DhcpPacket> {
    pub fn new(dhcp: DhcpPacket) -> Self {
        UdpPacket {
            header: UdpHeader {
                src_port: 68,
                dst_port: 67,
            },
            payload: dhcp,
        }
    }
}

impl<T: WriteOut> WriteOut for UdpPacket<T> {
    fn len(&self) -> usize {
        self.payload.len() + 4 * 2
    }

    fn write_out(&self, packet: &mut TxPacket) -> Result<(), ()> {
        let start_index = packet.0.len();

        packet.push_u16(self.header.src_port)?;
        packet.push_u16(self.header.dst_port)?;
        packet.push_u16(self.len().try_into().unwrap())?; // len
        let checksum_idx = packet.push_u16(0)?; // checksum

        self.payload.write_out(packet)?;
        let end_index = packet.0.len();

        // calculate udp checksum (without pseudo header)
        let checksum = !ip_checksum::data(&packet.0[start_index..end_index]);
        packet.set_u16(checksum_idx, checksum);

        Ok(())
    }
}

use parse::{Parse, ParseError};

impl<'a> Parse<'a> for UdpPacket<&'a [u8]> {
    fn parse(data: &'a [u8]) -> Result<Self, ParseError> {
        Ok(UdpPacket {
               header: UdpHeader {
                   src_port: NetworkEndian::read_u16(&data[0..2]),
                   dst_port: NetworkEndian::read_u16(&data[2..4]),
               },
               payload: &data[8..],
           })
    }
}

#[derive(Debug)]
pub enum UdpKind<'a> {
    Dhcp(DhcpPacket),
    Unknown(&'a [u8]),
}

impl<'a> Parse<'a> for UdpPacket<UdpKind<'a>> {
    fn parse(data: &'a [u8]) -> Result<Self, ParseError> {
        let udp = UdpPacket::parse(data)?;

        let src_dst = (udp.header.src_port, udp.header.dst_port);
        if src_dst == (67, 68) || src_dst == (68,67) {
            let dhcp = DhcpPacket::parse(udp.payload)?;
            Ok(UdpPacket {
                   header: udp.header,
                   payload: UdpKind::Dhcp(dhcp),
               })
        } else {
            Ok(UdpPacket {
                   header: udp.header,
                   payload: UdpKind::Unknown(udp.payload),
               })
        }
    }
}

#[test]
fn checksum() {
    use ipv4::{Ipv4Address, Ipv4Packet};
    use test::{Empty, HexDumpPrint};

    let udp = UdpPacket {
        header: UdpHeader {
            src_port: 53,
            dst_port: 57529,
        },
        payload: Empty,
    };
    let ip = Ipv4Packet::new_udp(Ipv4Address::new(141, 52, 46, 46),
                             Ipv4Address::new(141, 52, 46, 162),
                             udp);

    let mut packet = TxPacket::new(ip.len());
    ip.write_out(&mut packet).unwrap();

    let data = packet.0.as_slice();
    let reference_data = &[0x45, 0x00, 0x00, 0x1c, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11, 0xc3, 0x98,
                           0x8d, 0x34, 0x2e, 0x2e, 0x8d, 0x34, 0x2e, 0xa2, 0x00, 0x35, 0xe0, 0xb9,
                           0x00, 0x08, 0xa7, 0xb6];

    assert_eq!(data,
               reference_data,
               "{:?}=== vs ==={:?}",
               HexDumpPrint(data),
               HexDumpPrint(reference_data));
}
