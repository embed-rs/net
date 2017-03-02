// from smoltcp

use byteorder::{ByteOrder, NetworkEndian};
use ipv4::{Ipv4Address, IpProtocol};

fn propagate_carries(word: u32) -> u16 {
    let sum = (word >> 16) + (word & 0xffff);
    ((sum >> 16) as u16) + (sum as u16)
}

/// Compute an RFC 1071 compliant checksum (without the final complement).
pub fn data(data: &[u8]) -> u16 {
    let mut accum: u32 = 0;
    let mut i = 0;
    while i < data.len() {
        let word;
        if i + 2 <= data.len() {
            word = NetworkEndian::read_u16(&data[i..i + 2]) as u32
        } else {
            word = (data[i] as u32) << 8
        }
        accum += word;
        i += 2;
    }
    propagate_carries(accum)
}

/// Combine several RFC 1071 compliant checksums.
pub fn combine(checksums: &[u16]) -> u16 {
    let mut accum: u32 = 0;
    for &word in checksums {
        accum += word as u32;
    }
    propagate_carries(accum)
}

/// Compute an IP pseudo header checksum.
pub fn pseudo_header(src_addr: &Ipv4Address,
                     dst_addr: &Ipv4Address,
                     protocol: IpProtocol,
                     length: usize)
                     -> u16 {

    let mut proto_len = [0u8; 4];
    proto_len[1] = protocol.number();
    NetworkEndian::write_u16(&mut proto_len[2..4], length as u16);

    combine(&[data(&src_addr.as_bytes()), data(&dst_addr.as_bytes()), data(&proto_len[..])])
}
