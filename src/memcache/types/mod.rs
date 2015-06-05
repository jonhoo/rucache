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
        req.klen = u16::from_be(req.klen);
        req.vb = u16::from_be(req.vb);
        req.blen = u32::from_be(req.blen);
        req.opq = u32::from_be(req.opq);
        req.cas = u64::from_be(req.cas);
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
        if self.hdr.status == constants::Status::KEY_ENOENT as u16 {
            if self.hdr.op == constants::Command::GETQ as u8 || self.hdr.op == constants::Command::GETKQ as u8 {
                // no output on cache miss
                return true;
            }
        }

        let res = self.hdr.status;

        self.hdr.klen = u16::to_be(self.hdr.klen);
        self.hdr.status = u16::to_be(self.hdr.status);
        self.hdr.blen = u32::to_be(self.hdr.blen);
        self.hdr.opq = u32::to_be(self.hdr.opq);
        self.hdr.cas = u64::to_be(self.hdr.cas);

        debug!("{:?}", self);
        let buf = unsafe {
            let ptr : *const u8 = mem::transmute(&self.hdr);
            slice::from_raw_parts(ptr, 24)
        };

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
