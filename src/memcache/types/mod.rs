use byteorder::{BigEndian, ByteOrder};
use num::traits::FromPrimitive;

use std::fmt;
use std::str;
use std::mem;
use std::io;
use std::slice;

pub mod constants;

#[repr(C)]
pub struct Request {
    magic : u8,
    pub op    : u8,
    klen  : u16,
    elen  : u8,
    dt    : u8,
    pub vb    : u16,
    blen  : u32,
    opq   : u32,
    pub cas   : u64,
    // Command extras, key, and body follow
    data  : [u8; 0],
}

impl Request {
    #[allow(mutable_transmutes)]
    pub fn parse<'a>(buf : &'a mut [u8]) -> &'a Request {
        let buf_ : *const u8 = buf.as_ptr();
        let req : &mut Request = unsafe { mem::transmute(buf_) };
        req.klen = BigEndian::read_u16(&buf[2..4]);
        req.vb = BigEndian::read_u16(&buf[6..8]);
        req.blen = BigEndian::read_u32(&buf[8..12]);
        req.opq = BigEndian::read_u32(&buf[12..16]);
        req.cas = BigEndian::read_u64(&buf[16..24]);
        debug!("{:?}", req);
        req
    }

    pub fn body<'a>(&'a self) -> &'a [u8] {
        let prelen = self.elen as isize + self.klen as isize;
        unsafe {
            let ptr : *const u8 = mem::transmute(&self.data);
            slice::from_raw_parts(ptr.offset(prelen), (self.blen as isize - prelen) as usize)
        }
    }

    pub fn extras<'a>(&'a self) -> &'a [u8] {
        unsafe {
            let ptr : *const u8 = mem::transmute(&self.data);
            slice::from_raw_parts(ptr, self.elen as usize)
        }
    }

    pub fn key<'a>(&'a self) -> &'a [u8] {
        unsafe {
            let ptr : *const u8 = mem::transmute(&self.data);
            slice::from_raw_parts(ptr.offset(self.elen as isize), self.klen as usize)
        }
    }
}

impl fmt::Debug for Request {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "memcache request w/opcode={:?}, elen={}, blen={}, klen={}, key={:?}", constants::Command::from_u8(self.op), self.elen, self.blen, self.klen, str::from_utf8(self.key()))
    }
}

#[repr(C)]
pub struct ResponseHeader {
    magic : u8,
    pub op    : u8,
    klen  : u16,
    elen  : u8,
    pub dt    : u8,
    pub status: u16,
    blen  : u32,
    pub opq   : u32,
    pub cas   : u64,
}

pub struct ResponseSet<'a> {
    hdr : ResponseHeader,
    extras : &'a [u8],
    key : &'a [u8],
    body : &'a [u8],
}

impl Default for ResponseHeader {
    fn default() -> ResponseHeader {
        ResponseHeader {
            magic  : constants::RES_MAGIC,
            op     : 0,
            klen   : 0,
            elen   : 0,
            dt     : 0,
            status : constants::Status::TMPFAIL as u16,
            blen   : 0,
            opq    : 0,
            cas    : 0,
        }
    }
}

impl ResponseHeader {
    pub fn from_req(req : &Request) -> ResponseHeader {
        let mut r = ResponseHeader::default();
        r.op = req.op;
        r.opq = req.opq;
        r
    }

    pub fn construct<'a>(mut self, extras : &'a [u8], key : &'a [u8], body : &'a [u8]) -> ResponseSet<'a> {
        self.elen = extras.len() as u8;
        self.klen = key.len() as u16;
        self.blen = (extras.len() + key.len() + body.len()) as u32;
        ResponseSet{
            hdr: self,
            extras : extras,
            key : key,
            body : body,
        }
    }
}

impl<'a> ResponseSet<'a> {
    pub fn transmit(mut self, to : &mut io::Write) -> bool {
        if let Some(op) = constants::Command::from_u8(self.hdr.op) {
            if op == constants::Command::GETQ || op == constants::Command::GETKQ {
                if self.hdr.status == constants::Status::KEY_ENOENT as u16 {
                    // no output on cache miss
                    return true;
                }
            }
        }

        let res = self.hdr.status;

        debug!("{:?}", self);
        let buf = unsafe {
            let ptr : *mut u8 = mem::transmute(&mut self.hdr);
            slice::from_raw_parts_mut(ptr, 24)
        };
        BigEndian::write_u16(&mut buf[2..4], self.hdr.klen);
        BigEndian::write_u16(&mut buf[6..8], self.hdr.status);
        BigEndian::write_u32(&mut buf[8..12], self.hdr.blen);
        BigEndian::write_u32(&mut buf[12..16], self.hdr.opq);
        BigEndian::write_u64(&mut buf[16..24], self.hdr.cas);

        if let Err(_) = to.write_all(buf) { return false; }
        if let Err(_) = to.write_all(self.extras) { return false; }
        if let Err(_) = to.write_all(self.key) { return false; }
        if let Err(_) = to.write_all(self.body) { return false; }

        if let Some(op) = constants::Command::from_u8(self.hdr.op) {
            if !op.quiet() || res != 0 {
                if let Err(_) = to.flush() {
                    return false;
                }
            }
        }
        true
    }
}

impl fmt::Debug for ResponseHeader {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "memcache response w/status={:?}, klen={}, elen={}, blen={}", constants::Status::from_u16(self.status), self.klen, self.elen, self.blen)
    }
}

impl<'a> fmt::Debug for ResponseSet<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.hdr.fmt(f)
    }
}
