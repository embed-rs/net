use ethernet::{EthernetAddress, EthernetPacket};
use ipv4::Ipv4Address;
use byteorder::{ByteOrder, NetworkEndian};
use {WriteOut, TxPacket};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArpPacket {
    pub operation: ArpOperation,
    pub src_mac: EthernetAddress,
    pub dst_mac: EthernetAddress,
    pub src_ip: Ipv4Address,
    pub dst_ip: Ipv4Address,
}

impl ArpPacket {
    pub fn response(&self, mac: EthernetAddress) -> ArpPacket {
        assert!(self.operation == ArpOperation::Request,
                "can only generate response for request");

        ArpPacket {
            operation: ArpOperation::Response,
            src_mac: mac,
            dst_mac: self.src_mac,
            src_ip: self.dst_ip,
            dst_ip: self.src_ip,
        }
    }

    pub fn response_packet(&self, mac: EthernetAddress) -> EthernetPacket<ArpPacket> {
        let response = self.response(mac);
        EthernetPacket::new_arp(mac, self.src_mac, response)
    }
}

pub fn new_request_packet(src_mac: EthernetAddress,
                          src_ip: Ipv4Address,
                          dst_ip: Ipv4Address)
                          -> EthernetPacket<ArpPacket> {
    let arp = ArpPacket {
        operation: ArpOperation::Request,
        src_mac: src_mac,
        dst_mac: EthernetAddress::broadcast(),
        src_ip: src_ip,
        dst_ip: dst_ip,
    };
    EthernetPacket::new_arp(src_mac, EthernetAddress::broadcast(), arp)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArpOperation {
    Request,
    Response,
}

impl WriteOut for ArpPacket {
    fn len(&self) -> usize {
        28
    }

    fn write_out<T: TxPacket>(&self, packet: &mut T) -> Result<(), ()> {
        packet.push_u16(1)?; // hardware type == ethernet (1)
        packet.push_u16(0x0800)?; // protocol type == ipv4 (0x0800)
        packet.push_byte(6)?; // hardware address size
        packet.push_byte(4)?; // protocol address size

        packet
            .push_u16(match self.operation {
                          ArpOperation::Request => 1,
                          ArpOperation::Response => 2,
                      })?;

        packet.push_bytes(&self.src_mac.as_bytes())?;
        packet.push_bytes(&self.src_ip.as_bytes())?;
        packet.push_bytes(&self.dst_mac.as_bytes())?;
        packet.push_bytes(&self.dst_ip.as_bytes())?;

        Ok(())
    }
}


use parse::{Parse, ParseError};

impl<'a> Parse<'a> for ArpPacket {
    fn parse(data: &'a [u8]) -> Result<Self, ParseError> {
        let operation = match NetworkEndian::read_u16(&data[6..8]) {
            1 => ArpOperation::Request,
            2 => ArpOperation::Response,
            _ => return Err(ParseError::Malformed("invalid value in ARP operation field")),
        };
        Ok(ArpPacket {
               operation: operation,
               src_mac: EthernetAddress::from_bytes(&data[8..14]),
               dst_mac: EthernetAddress::from_bytes(&data[18..24]),
               src_ip: Ipv4Address::from_bytes(&data[14..18]),
               dst_ip: Ipv4Address::from_bytes(&data[24..28]),
           })
    }
}
