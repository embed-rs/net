use {TxPacket, WriteOut};
use ip_checksum;
use byteorder::{ByteOrder, NetworkEndian};
use ethernet::{EthernetAddress, EthernetPacket};
use ipv4::{Ipv4Address, Ipv4Packet};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IcmpType {
    EchoRequest { id: u16, sequence_number: u16 },
    EchoReply { id: u16, sequence_number: u16 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IcmpPacket<T> {
    pub type_: IcmpType,
    pub data: T,
}

impl<T: Clone> IcmpPacket<T> {
    pub fn echo_reply(&self) -> IcmpPacket<T> {
        let (id, sequence_number) = match self.type_ {
            IcmpType::EchoRequest {
                id,
                sequence_number,
            } => (id, sequence_number),
            t => panic!("Can't generate reply for {:?}", t),
        };

        IcmpPacket {
            type_: IcmpType::EchoReply {
                id,
                sequence_number,
            },
            data: self.data.clone(),
        }
    }
    pub fn echo_reply_packet(&self,
                             src_mac: EthernetAddress,
                             dst_mac: EthernetAddress,
                             src_ip: Ipv4Address,
                             dst_ip: Ipv4Address)
                             -> EthernetPacket<Ipv4Packet<IcmpPacket<T>>> {
        let reply = self.echo_reply();
        EthernetPacket::new_ipv4(src_mac,
                                 dst_mac,
                                 Ipv4Packet::new_icmp(src_ip, dst_ip, reply))
    }
}

impl<T: AsRef<[u8]>> WriteOut for IcmpPacket<T> {
    fn len(&self) -> usize {
        self.data.as_ref().len() + 4 * 2
    }

    fn write_out<P: TxPacket>(&self, packet: &mut P) -> Result<(), ()> {
        let start_index = packet.len();

        match self.type_ {
            IcmpType::EchoRequest { .. } => {
                packet.push_byte(8)?; // type
                packet.push_byte(0)?; // code
            }
            IcmpType::EchoReply { .. } => {
                packet.push_byte(0)?; // type
                packet.push_byte(0)?; // code
            }
        }

        let checksum_idx = packet.push_u16(0)?; // checksum

        match self.type_ {
            IcmpType::EchoRequest {
                id,
                sequence_number,
            } |
            IcmpType::EchoReply {
                id,
                sequence_number,
            } => {
                packet.push_u16(id)?;
                packet.push_u16(sequence_number)?;
            }
        }

        packet.push_bytes(self.data.as_ref())?;
        let end_index = packet.len();

        // calculate Icmp checksum
        let checksum = !ip_checksum::data(&packet[start_index..end_index]);
        packet.set_u16(checksum_idx, checksum);

        Ok(())
    }
}

use parse::{Parse, ParseError};

impl<'a> Parse<'a> for IcmpPacket<&'a [u8]> {
    fn parse(data: &'a [u8]) -> Result<Self, ParseError> {
        let type_code = (data[0], data[1]);

        let type_ = match type_code {
            (8, 0) => {
                IcmpType::EchoRequest {
                    id: NetworkEndian::read_u16(&data[4..6]),
                    sequence_number: NetworkEndian::read_u16(&data[6..8]),
                }
            }
            _ => return Err(ParseError::Unimplemented("Unknown ICMP packet type")),
        };

        Ok(IcmpPacket {
               type_: type_,
               data: &data[8..],
           })
    }
}
