#![feature(try_from)]
#![feature(specialization)]
#![feature(const_fn)]
#![feature(conservative_impl_trait)]

#![cfg_attr(not(test), no_std)]
#![cfg_attr(any(test, feature = "alloc"), feature(alloc))]

#[cfg(any(test, feature = "alloc"))]
extern crate alloc;

extern crate byteorder;
extern crate bit_field;

#[cfg(test)]
mod core {
    pub use std::*;
}

pub use parse::{parse, ParseError};
#[cfg(any(test, feature = "alloc"))]
pub use heap_tx_packet::HeapTxPacket;

use core::ops::{Index, IndexMut, Range};
use core::borrow::Borrow;
use byteorder::{ByteOrder, NetworkEndian};

#[macro_use]
extern crate bitflags_associated_constants;

pub mod ethernet;
pub mod arp;
pub mod ipv4;
pub mod udp;
pub mod tcp;
pub mod dhcp;
pub mod icmp;
mod ip_checksum;
mod test;
mod parse;

pub trait TxPacket: Index<usize, Output=u8> + IndexMut<usize> + Index<Range<usize>, Output=[u8]>
    + IndexMut<Range<usize>>
{
    fn push_bytes(&mut self, bytes: &[u8]) -> Result<usize, ()>;

    fn len(&self) -> usize;

    fn push_byte(&mut self, value: u8) -> Result<usize, ()> {
        let bytes = [value];
        self.push_bytes(&bytes)
    }

    fn push_u16(&mut self, value: u16) -> Result<usize, ()> {
        let mut bytes = [0, 0];
        NetworkEndian::write_u16(&mut bytes, value);
        self.push_bytes(&bytes)
    }

    fn push_u32(&mut self, value: u32) -> Result<usize, ()> {
        let mut bytes = [0, 0, 0, 0];
        NetworkEndian::write_u32(&mut bytes, value);
        self.push_bytes(&bytes)
    }

    fn get_bytes(&mut self, index: usize, len: usize) -> &[u8] {
        &self[index..(index + len)]
    }

    fn set_bytes(&mut self, index: usize, bytes: &[u8]) {
        self[index..(index + bytes.len())].copy_from_slice(bytes);
    }

    fn set_u16(&mut self, index: usize, value: u16) {
        let mut bytes = [0, 0];
        NetworkEndian::write_u16(&mut bytes, value);
        self.set_bytes(index, &bytes);
    }

    fn update_u16<F>(&mut self, index: usize, f: F)
        where F: FnOnce(u16) -> u16
    {
        let value = NetworkEndian::read_u16(self.get_bytes(index, 2));
        let value = f(value);
        self.set_u16(index, value);
    }
}

pub trait WriteOut {
    fn len(&self) -> usize;
    fn write_out<T: TxPacket>(&self, packet: &mut T) -> Result<(), ()>;
}

impl<T> WriteOut for T where T: Borrow<[u8]> {
    fn len(&self) -> usize {
        <[u8]>::len(self.borrow())
    }

    fn write_out<P: TxPacket>(&self, packet: &mut P) -> Result<(), ()> {
        packet.push_bytes(self.borrow()).map(|_| ())
    }
}

#[cfg(any(test, feature = "alloc"))]
mod heap_tx_packet {
    use core::ops::{Deref, Index, IndexMut, Range};
    use alloc::boxed::Box;
    use alloc::vec::Vec;
    use ethernet::EthernetPacket;
    use {WriteOut, TxPacket};

    pub struct HeapTxPacket(Vec<u8>);

    impl HeapTxPacket {
        pub fn new(max_len: usize) -> HeapTxPacket {
            HeapTxPacket(Vec::with_capacity(max_len))
        }

        pub fn write_out<T: WriteOut>(packet: EthernetPacket<T>) -> Result<HeapTxPacket, ()> {
            let mut tx_packet = HeapTxPacket::new(packet.len());
            packet.write_out(&mut tx_packet)?;
            Ok(tx_packet)
        }

        pub fn into_boxed_slice(self) -> Box<[u8]> {
            self.0.into_boxed_slice()
        }
    }

    impl TxPacket for HeapTxPacket {
        fn push_bytes(&mut self, bytes: &[u8]) -> Result<usize, ()> {
            if self.0.capacity() - self.0.len() < bytes.len() {
                Err(())
            } else {
                let index = self.0.len();
                for &byte in bytes {
                    self.0.push(byte);
                }
                Ok(index)
            }
        }

        fn len(&self) -> usize {
            self.0.len()
        }
    }

    impl Deref for HeapTxPacket {
        type Target = Vec<u8>;

        fn deref(&self) -> &Vec<u8> {
            &self.0
        }
    }

    impl Index<usize> for HeapTxPacket {
        type Output = u8;

        fn index(&self, index: usize) -> &u8 {
            self.0.index(index)
        }
    }

    impl IndexMut<usize> for HeapTxPacket {
        fn index_mut(&mut self, index: usize) -> &mut u8 {
            self.0.index_mut(index)
        }
    }

    impl Index<Range<usize>> for HeapTxPacket {
        type Output = [u8];

        fn index(&self, index: Range<usize>) -> &[u8] {
            self.0.index(index)
        }
    }

    impl IndexMut<Range<usize>> for HeapTxPacket {
        fn index_mut(&mut self, index: Range<usize>) -> &mut [u8] {
            self.0.index_mut(index)
        }
    }
}
