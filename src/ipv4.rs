use {TxPacket, WriteOut, ip_checksum};
use udp::UdpHeader;
use core::convert::TryInto;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ipv4Address([u8; 4]);

impl Ipv4Address {
    pub fn new(a0: u8, a1: u8, a2: u8, a3: u8) -> Self {
        Ipv4Address([a0, a1, a2, a3])
    }

    pub fn as_bytes(&self) -> [u8; 4] {
        self.0
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
pub struct Ipv4Header<T> {
    src_addr: Ipv4Address,
    dst_addr: Ipv4Address,
    protocol: IpProtocol,
    payload: T,
}

impl<T> Ipv4Header<UdpHeader<T>> {
    pub fn new(src_addr: Ipv4Address, dst_addr: Ipv4Address, udp: UdpHeader<T>) -> Self {
        Ipv4Header {
            src_addr: src_addr,
            dst_addr: dst_addr,
            protocol: IpProtocol::Udp,
            payload: udp,
        }
    }
}

impl<T> Ipv4Header<T> {
    fn header_len(&self) -> u8 {
        20
    }
}

impl<T: WriteOut> Ipv4Header<T> {
    fn write_out_impl(&self, packet: &mut TxPacket) -> Result<(), ()> {
        let start_index = packet.0.len();

        packet.push_byte(4 << 4 | self.header_len() / 4)?; // version and header_len
        packet.push_byte(0)?; // dscp_ecn
        let total_len = self.len().try_into().unwrap();
        packet.push_u16(total_len)?; // total_len

        packet.push_u16(0)?; // identification
        packet.push_u16(1 << 14)?; // flags and fragment_offset (bit 14 == don't fragment)

        packet.push_byte(64)?; // time to live
        packet.push_byte(self.protocol.number())?; // protocol
        let checksum_idx = packet.push_u16(0)?; // checksum

        packet.push_bytes(&self.src_addr.as_bytes())?;
        packet.push_bytes(&self.dst_addr.as_bytes())?;

        let end_index = packet.0.len();

        // calculate ip checksum
        let checksum = !ip_checksum::data(&packet.0[start_index..end_index]);
        packet.set_u16(checksum_idx, checksum);

        Ok(())
    }
}

impl<T: WriteOut> WriteOut for Ipv4Header<T> {
    fn len(&self) -> usize {
        self.payload.len() + usize::from(self.header_len())
    }

    default fn write_out(&self, packet: &mut TxPacket) -> Result<(), ()> {
        self.write_out_impl(packet)?;
        self.payload.write_out(packet)
    }
}

impl<T: WriteOut> WriteOut for Ipv4Header<UdpHeader<T>> {
    fn write_out(&self, packet: &mut TxPacket) -> Result<(), ()> {
        self.write_out_impl(packet)?;

        let udp_start_index = packet.0.len();
        self.payload.write_out(packet)?;

        // calculate udp checksum
        let pseudo_header_checksum = !ip_checksum::pseudo_header(&self.src_addr,
                                                                 &self.dst_addr,
                                                                 self.protocol,
                                                                 self.payload.len());

        let udp_checksum_idx = udp_start_index + 3 * 2;
        packet.update_u16(udp_checksum_idx, |checksum| {
            let checksums = [checksum, pseudo_header_checksum];
            ip_checksum::combine(&checksums)
        });

        Ok(())
    }
}

#[test]
fn checksum() {
    use test::{Empty, HexDumpPrint};

    let ip = Ipv4Header {
        src_addr: Ipv4Address::new(141, 52, 45, 122),
        dst_addr: Ipv4Address::new(255, 255, 255, 255),
        protocol: IpProtocol::Udp,
        payload: Empty,
    };

    let mut packet = TxPacket::new(ip.len());
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
