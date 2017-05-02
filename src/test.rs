#![cfg(test)]

use {WriteOut, TxPacket};

pub struct Empty;

impl WriteOut for Empty {
    fn len(&self) -> usize {
        0
    }

    fn write_out<T: TxPacket>(&self, _: &mut T) -> Result<(), ()> {
        Ok(())
    }
}

pub struct HexDumpPrint<'a>(pub &'a [u8]);

impl<'a> ::core::fmt::Debug for HexDumpPrint<'a> {
    fn fmt(&self, fmt: &mut ::core::fmt::Formatter) -> Result<(), ::core::fmt::Error> {
        for (i, byte) in self.0.iter().enumerate() {
            if i % 16 == 0 {
                write!(fmt, "\n{:04x}  ", i)?;
            }
            write!(fmt, " {:02x}", byte)?;
        }
        writeln!(fmt, "")
    }
}
