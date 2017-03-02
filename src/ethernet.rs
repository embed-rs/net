use {TxPacket, WriteOut};
use ipv4::Ipv4Header;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EthernetAddress([u8; 6]);

impl EthernetAddress {
    pub fn new(addr: [u8; 6]) -> Self {
        EthernetAddress(addr)
    }

    pub fn as_bytes(&self) -> [u8; 6] {
        self.0
    }
}

pub struct EthernetHeader<T> {
    src_addr: EthernetAddress,
    dst_addr: EthernetAddress,
    ether_type: EtherType,
    payload: T,
}

impl<T> EthernetHeader<Ipv4Header<T>> {
    pub fn new(src_addr: EthernetAddress,
               dst_addr: EthernetAddress,
               ip_data: Ipv4Header<T>)
               -> Self {
        EthernetHeader {
            src_addr: src_addr,
            dst_addr: dst_addr,
            ether_type: EtherType::Ipv4,
            payload: ip_data,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EtherType {
    Ipv4,
    Arp,
    Unknown(u16),
}

impl EtherType {
    pub fn number(&self) -> u16 {
        use self::EtherType::*;

        match *self {
            Ipv4 => 0x0800,
            Arp => 0x0806,
            Unknown(number) => number,
        }
    }
}

impl<T: WriteOut> WriteOut for EthernetHeader<T> {
    fn len(&self) -> usize {
        self.payload.len() + 2 * 6 + 2
    }

    fn write_out(&self, packet: &mut TxPacket) -> Result<(), ()> {
        packet.push_bytes(&self.dst_addr.as_bytes())?;
        packet.push_bytes(&self.src_addr.as_bytes())?;
        packet.push_u16(self.ether_type.number())?;

        self.payload.write_out(packet)?;

        Ok(())
    }
}
