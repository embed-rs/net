use {TxPacket, WriteOut};
use ethernet::{EthernetAddress, EthernetPacket};
use ipv4::{Ipv4Address, Ipv4Packet};
use udp::UdpPacket;

pub fn new_discover_msg(mac: EthernetAddress) -> EthernetPacket<Ipv4Packet<UdpPacket<DhcpPacket>>> {
    let dhcp_discover = DhcpPacket {
        mac: mac,
        transaction_id: 0x12345678,
        operation: DhcpType::Discover,
    };
    let udp = UdpPacket::new(68, 67, dhcp_discover);
    let ip = Ipv4Packet::new_udp(Ipv4Address::new(0, 0, 0, 0),
                                 Ipv4Address::new(255, 255, 255, 255),
                                 udp);
    EthernetPacket::new_ipv4(mac, EthernetAddress::new([0xff; 6]), ip)
}

pub fn new_request_msg(mac: EthernetAddress,
                       ip: Ipv4Address,
                       dhcp_server_ip: Ipv4Address)
                       -> EthernetPacket<Ipv4Packet<UdpPacket<DhcpPacket>>> {
    let dhcp_request = DhcpPacket {
        mac: mac,
        transaction_id: 0x12345678,
        operation: DhcpType::Request { ip, dhcp_server_ip },
    };
    let udp = UdpPacket::new(68, 67, dhcp_request);
    let ip = Ipv4Packet::new_udp(Ipv4Address::new(0, 0, 0, 0),
                                 Ipv4Address::new(255, 255, 255, 255),
                                 udp);
    EthernetPacket::new_ipv4(mac, EthernetAddress::new([0xff; 6]), ip)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DhcpPacket {
    pub mac: EthernetAddress,
    pub transaction_id: u32,
    pub operation: DhcpType,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DhcpType {
    Discover,
    Request {
        ip: Ipv4Address,
        dhcp_server_ip: Ipv4Address,
    },
    Offer {
        ip: Ipv4Address,
        dhcp_server_ip: Ipv4Address,
    },
    Ack { ip: Ipv4Address },
}

impl WriteOut for DhcpPacket {
    fn len(&self) -> usize {
        240 +
        match self.operation {
            DhcpType::Discover => 10,
            DhcpType::Request { .. } => 16,
            DhcpType::Offer { .. } => unimplemented!(),
            DhcpType::Ack { .. } => unimplemented!(),
        }
    }

    fn write_out<T: TxPacket>(&self, packet: &mut T) -> Result<(), ()> {
        let operation = match self.operation {
            DhcpType::Discover |
            DhcpType::Request { .. } => 1,
            DhcpType::Offer { .. } |
            DhcpType::Ack { .. } => 2,
        };

        packet.push_byte(operation)?;
        packet.push_byte(1)?; // hardware type (1 == ethernet)
        packet.push_byte(6)?; // hardware address len
        packet.push_byte(0)?; // hops

        packet.push_u32(self.transaction_id)?;
        packet.push_u16(0)?; // seconds since start
        packet.push_u16(1 << 15)?; // flags (bit 15 == reply as broadcast)

        let zero_ip = &Ipv4Address::new(0, 0, 0, 0).as_bytes();

        packet.push_bytes(zero_ip)?; // client ip
        packet.push_bytes(zero_ip)?; // own ip
        packet.push_bytes(zero_ip)?; // server ip
        packet.push_bytes(zero_ip)?; // relay agent ip

        packet.push_bytes(&self.mac.as_bytes())?; // client mac
        packet.push_bytes(&[0; 10])?; // client mac padding

        packet.push_bytes(&[0; 64])?; // server name
        packet.push_bytes(&[0; 128])?; // file name
        packet.push_u32(0x63825363)?; // magic cookie

        // options
        match self.operation {
            DhcpType::Discover => {
                // DHCP message type
                packet.push_byte(53)?; // code
                packet.push_byte(1)?; // len
                packet.push_byte(1)?; // 1 == DHCP Discover

                // parameter request list
                packet.push_byte(55)?; // code
                packet.push_byte(4)?; // len
                packet.push_byte(1)?; // request subnet mask
                packet.push_byte(3)?; // router
                packet.push_byte(15)?; // domain name
                packet.push_byte(6)?; // domain name server

                packet.push_byte(255)?; // option end
            }
            DhcpType::Request { ip, dhcp_server_ip } => {
                // DHCP message type
                packet.push_byte(53)?; // code
                packet.push_byte(1)?; // len
                packet.push_byte(3)?; // 3 == DHCP Request

                // requested ip
                packet.push_byte(50)?; // code
                packet.push_byte(4)?; // len
                packet.push_bytes(&ip.as_bytes())?; // requested ip

                // dhcp server ip
                packet.push_byte(54)?; // code
                packet.push_byte(4)?; // len
                packet.push_bytes(&dhcp_server_ip.as_bytes())?; // dhcp server ip

                packet.push_byte(255)?; // option end
            }
            DhcpType::Offer { .. } |
            DhcpType::Ack { .. } => unimplemented!(),
        }

        Ok(())
    }
}

use parse::{Parse, ParseError};

impl<'a> Parse<'a> for DhcpPacket {
    fn parse(data: &'a [u8]) -> Result<Self, ParseError> {
        use byteorder::{ByteOrder, NetworkEndian};

        fn parse_message_type_tag(mut data: &[u8]) -> u8 {
            loop {
                let code = data[0];
                let len = data[1];
                if code == 53 && len == 1 {
                    return data[2];
                } else {
                    data = &data[(2 + usize::from(len))..];
                }
            }
        }

        let operation = match parse_message_type_tag(&data[240..]) {
            1 => {
                // discover
                return Err(ParseError::Unimplemented("dhcp discover"));
            }
            2 => {
                // offer
                let ip = Ipv4Address::from_bytes(&data[16..20]);
                let dhcp_server_ip = Ipv4Address::from_bytes(&data[20..24]);
                DhcpType::Offer { ip, dhcp_server_ip }
            }
            3 => {
                // request
                return Err(ParseError::Unimplemented("dhcp request"));
            }
            5 => {
                // ack
                let ip = Ipv4Address::from_bytes(&data[16..20]);
                DhcpType::Ack { ip }
            }
            _ => return Err(ParseError::Unimplemented("unknown dhcp message type")),
        };

        Ok(DhcpPacket {
               mac: EthernetAddress::from_bytes(&data[28..34]),
               transaction_id: NetworkEndian::read_u32(&data[4..8]),
               operation: operation,
           })
    }
}

#[test]
fn test_discover() {
    use HeapTxPacket;

    let discover = DhcpPacket {
        mac: EthernetAddress::new([0x00, 0x08, 0xdc, 0xab, 0xcd, 0xef]),
        transaction_id: 0xcafebabe,
        operation: DhcpType::Discover,
    };

    let mut packet = HeapTxPacket::new(discover.len());
    discover.write_out(&mut packet).unwrap();

    let data = packet.as_slice();
    let reference_data =
        &[0x01, 0x01, 0x06, 0x00, 0xca, 0xfe, 0xba, 0xbe, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00,
          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
          0x00, 0x08, 0xdc, 0xab, 0xcd, 0xef, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x63, 0x82,
          0x53, 0x63, 0x35, 0x01, 0x01, 0x37, 0x04, 0x01, 0x03, 0x0f, 0x06, 0xff];

    assert_eq!(data.len(), reference_data.len());
    for i in 0..data.len() {
        assert_eq!(data[i], reference_data[i], "{}", i);
    }
}

#[test]
fn test_request() {
    use HeapTxPacket;

    let request = DhcpPacket {
        mac: EthernetAddress::new([0x00, 0x08, 0xdc, 0xab, 0xcd, 0xef]),
        transaction_id: 0xcafebabe,
        operation: DhcpType::Request {
            ip: Ipv4Address::new(141, 52, 46, 201),
            dhcp_server_ip: Ipv4Address::new(141, 52, 46, 13),
        },
    };

    let mut packet = HeapTxPacket::new(request.len());
    request.write_out(&mut packet).unwrap();

    let data = packet.as_slice();
    let reference_data =
        &[0x01, 0x01, 0x06, 0x00, 0xca, 0xfe, 0xba, 0xbe, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00,
          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
          0x00, 0x08, 0xdc, 0xab, 0xcd, 0xef, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x63, 0x82,
          0x53, 0x63, 0x35, 0x01, 0x03, 0x32, 0x04, 0x8d, 0x34, 0x2e, 0xc9, 0x36, 0x04, 0x8d,
          0x34, 0x2e, 0x0d, 0xff];

    assert_eq!(data.len(), reference_data.len());
    for i in 0..data.len() {
        assert_eq!(data[i], reference_data[i], "{}", i);
    }
}


#[test]
fn test_discover_packet() {
    use HeapTxPacket;

    let discover = new_discover_msg(EthernetAddress::new([0x00, 0x08, 0xdc, 0xab, 0xcd, 0xef]));
    let mut packet = HeapTxPacket::new(discover.len());
    discover.write_out(&mut packet).unwrap();

    let data = packet.as_slice();
    let reference_data =
        &[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x08, 0xdc, 0xab, 0xcd, 0xef, 0x08, 0x00,
          0x45, 0x00, 0x01, 0x16, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11, 0x39, 0xd8, 0x00, 0x00,
          0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0x00, 0x44, 0x00, 0x43, 0x01, 0x02, 0x67, 0xe5,
          0x01, 0x01, 0x06, 0x00, 0x12, 0x34, 0x56, 0x78, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00,
          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
          0x00, 0x08, 0xdc, 0xab, 0xcd, 0xef, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x63, 0x82,
          0x53, 0x63, 0x35, 0x01, 0x01, 0x37, 0x04, 0x01, 0x03, 0x0f, 0x06, 0xff];

    assert_eq!(data.len(), reference_data.len());
    for i in 0..data.len() {
        assert_eq!(data[i], reference_data[i], "{}", i);
    }
}
