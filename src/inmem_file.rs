use std::io::{Read, Seek, SeekFrom};

pub trait ReadAndSeek: Read + Seek {}

impl<RS: Read + Seek> ReadAndSeek for RS {}

pub struct InMemFile<'a> {
    pos: u64,
    buf: &'a [u8],
}

impl<'a> InMemFile<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        InMemFile { pos: 0, buf }
    }
}

impl<'a> Seek for InMemFile<'a> {
    fn seek(&mut self, pos: std::io::SeekFrom) -> std::io::Result<u64> {
        match pos {
            SeekFrom::Start(offset) => {
                if offset > self.buf.len() as u64 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "SeekFrom::Start",
                    ));
                }
                self.pos = offset as u64;
                Ok(offset)
            }
            SeekFrom::End(pos) => {
                if pos > 0 || -pos > self.buf.len() as i64 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "SeekFrom::End",
                    ));
                }
                self.pos = (self.buf.len() as i64 + pos) as u64;
                Ok(self.pos)
            }
            SeekFrom::Current(offset) => {
                if (self.pos as i64 + offset) < 0
                    || (self.pos as i64 + offset) as u64 > self.buf.len() as u64
                {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "SeekFrom::Current",
                    ));
                }
                self.pos += offset as u64;
                Ok(self.pos)
            }
        }
    }
}

impl<'a> Read for InMemFile<'a> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let l = (self.buf.len() - self.pos as usize).min(buf.len());
        buf[0..l].copy_from_slice(&self.buf[self.pos as usize..self.pos as usize + l]);
        self.pos += l as u64;
        Ok(l)
    }
}
