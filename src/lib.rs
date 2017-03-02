#![feature(collections)]
#![feature(try_from)]
#![feature(specialization)]

#![cfg_attr(not(test), no_std)]

extern crate collections;

extern crate byteorder;

#[cfg(test)]
mod core {
    pub use std::*;
}

use collections::vec::Vec;

use byteorder::{ByteOrder, NetworkEndian};

pub mod ethernet;
pub mod ipv4;
pub mod udp;
pub mod dhcp;

mod ip_checksum;
mod test;

pub struct TxPacket(Vec<u8>);

impl TxPacket {
    pub fn new(max_len: usize) -> TxPacket {
        TxPacket(Vec::with_capacity(max_len))
    }

    pub fn push_bytes(&mut self, bytes: &[u8]) -> Result<usize, ()> {
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

    pub fn push_byte(&mut self, value: u8) -> Result<usize, ()> {
        let bytes = [value];
        self.push_bytes(&bytes)
    }

    pub fn push_u16(&mut self, value: u16) -> Result<usize, ()> {
        let mut bytes = [0, 0];
        NetworkEndian::write_u16(&mut bytes, value);
        self.push_bytes(&bytes)
    }

    pub fn push_u32(&mut self, value: u32) -> Result<usize, ()> {
        let mut bytes = [0, 0, 0, 0];
        NetworkEndian::write_u32(&mut bytes, value);
        self.push_bytes(&bytes)
    }

    pub fn get_bytes(&mut self, index: usize, len: usize) -> &[u8] {
        &self.0[index..(index + len)]
    }

    pub fn set_bytes(&mut self, index: usize, bytes: &[u8]) {
        self.0[index..(index + bytes.len())].copy_from_slice(bytes);
    }

    pub fn set_u16(&mut self, index: usize, value: u16) {
        let mut bytes = [0, 0];
        NetworkEndian::write_u16(&mut bytes, value);
        self.set_bytes(index, &bytes);
    }

    pub fn update_u16<F>(&mut self, index: usize, f: F)
        where F: FnOnce(u16) -> u16
    {
        let value = NetworkEndian::read_u16(self.get_bytes(index, 2));
        let value = f(value);
        self.set_u16(index, value);
    }
}


pub trait WriteOut {
    fn len(&self) -> usize;
    fn write_out(&self, packet: &mut TxPacket) -> Result<(), ()>;
}
