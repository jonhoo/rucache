use std::fmt;
use std::str;
use std::str::FromStr;

mod types;
pub use self::types::{Request, ResponseHeader, ResponseSet};
pub use self::types::constants::{REQ_MAGIC, RES_MAGIC, Status, Command};

#[derive(Debug)]
pub struct Item {
    pub bytes   : Vec<u8>,
    pub flags   : u32,
    pub casid   : u64,
    pub expires : i64,
}

impl fmt::Display for Item {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "bytes {:?}", self.bytes)
    }
}

impl Item {
    pub fn present(&self, now : i64) -> bool {
        return self.expires == 0 || self.expires > now
    }
}

pub fn fset(bytes : Vec<u8>, flags : u32, expires : i64, casid : u64) -> Box<Fn(Option<&Item>) -> (Status, Result<Item, Option<String>>)> {
    Box::new(move |prev : Option<&Item>| {
        match prev {
            None if casid != 0 => (Status::KEY_ENOENT, Err(None)),
            Some(ref v) if casid != 0 && v.casid != casid => (Status::KEY_EEXISTS, Err(None)),

            None => { (Status::SUCCESS, Ok(Item {
                bytes: bytes.to_vec(),
                flags: flags,
                casid: 1,
                expires: expires,
            }))}
            Some(ref v) => { (Status::SUCCESS, Ok(Item {
                bytes: bytes.to_vec(),
                flags: flags,
                casid: v.casid + 1,
                expires: expires,
            }))}
        }
    })
}

pub fn fadd(bytes : Vec<u8>, flags : u32, expires : i64) -> Box<Fn(Option<&Item>) -> (Status, Result<Item, Option<String>>)> {
    Box::new(move |prev : Option<&Item>| {
        match prev {
            None => { (Status::SUCCESS, Ok(Item {
                bytes: bytes.to_vec(),
                flags: flags,
                casid: 1,
                expires: expires,
            }))}
            Some(_) => { (Status::KEY_EEXISTS, Err(None)) }
        }
    })
}

pub fn freplace(bytes : Vec<u8>, flags : u32, expires : i64) -> Box<Fn(Option<&Item>) -> (Status, Result<Item, Option<String>>)> {
    Box::new(move |prev : Option<&Item>| {
        match prev {
            Some(v) => { (Status::SUCCESS, Ok(Item {
                bytes: bytes.to_vec(),
                flags: flags,
                casid: v.casid + 1,
                expires: expires,
            }))}
            None => { (Status::KEY_ENOENT, Err(None)) }
        }
    })
}

fn fjoin(bytes : Vec<u8>, prepend : bool, casid : u64) -> Box<Fn(Option<&Item>) -> (Status, Result<Item, Option<String>>)> {
    Box::new(move |prev : Option<&Item>| {
        match prev {
            Some(ref v) if casid != 0 && v.casid != casid => {
                (Status::KEY_EEXISTS, Err(None))
            }
            Some(v) => {
                let mut nb = Vec::with_capacity(bytes.len() + v.bytes.len());
                if prepend {
                    for b in &bytes {
                        nb.push(*b);
                    }
                }
                for b in &v.bytes {
                    nb.push(*b);
                }
                if !prepend {
                    for b in &bytes {
                        nb.push(*b);
                    }
                }

                (Status::SUCCESS, Ok(Item {
                    bytes: nb,
                    flags: v.flags,
                    casid: v.casid + 1,
                    expires: v.expires,
                }))}
            None => { (Status::KEY_ENOENT, Err(None)) }
        }
    })
}

pub fn fappend(bytes : Vec<u8>, casid : u64) -> Box<Fn(Option<&Item>) -> (Status, Result<Item, Option<String>>)> {
    fjoin(bytes, false, casid)
}

pub fn fprepend(bytes : Vec<u8>, casid : u64) -> Box<Fn(Option<&Item>) -> (Status, Result<Item, Option<String>>)> {
    fjoin(bytes, true, casid)
}

fn fpm(by : u64, def : u64, expires : i64, plus : bool) -> Box<Fn(Option<&Item>) -> (Status, Result<Item, Option<String>>)> {
    Box::new(move |prev : Option<&Item>| {
        match prev {
            Some(v) => {
                let mut value : u64;
                if let Ok(s) = str::from_utf8(&v.bytes[..]) {
                    if let Ok(v) = u64::from_str(s) {
                        value = v;
                    } else {
                        return (Status::DELTA_BADVAL, Err(None));
                    }
                } else {
                    return (Status::DELTA_BADVAL, Err(None));
                }

                if plus {
                    value += by
                } else {
                    if by > value {
                        value = 0
                    } else {
                        value -= by
                    }
                }

                (Status::SUCCESS, Ok(Item {
                    bytes: value.to_string().into_bytes(),
                    flags: v.flags,
                    casid: v.casid + 1,
                    expires: v.expires,
                }))}
            None if expires == 0xffffffff => { (Status::KEY_ENOENT, Err(None)) }
            None => {
                (Status::SUCCESS, Ok(Item {
                    bytes: def.to_string().into_bytes(),
                    flags: 0,
                    casid: 1,
                    expires: expires,
                }))}
        }
    })
}

pub fn fincr(by : u64, def : u64, expires : i64) -> Box<Fn(Option<&Item>) -> (Status, Result<Item, Option<String>>)> {
    return fpm(by, def, expires, true)
}

pub fn fdecr(by : u64, def : u64, expires : i64) -> Box<Fn(Option<&Item>) -> (Status, Result<Item, Option<String>>)> {
    return fpm(by, def, expires, false)
}

#[allow(dead_code)]
pub fn ftouch(expires : i64) -> Box<Fn(Option<&Item>) -> (Status, Result<Item, Option<String>>)> {
    Box::new(move |prev : Option<&Item>| {
        match prev {
            Some(v) => { (Status::SUCCESS, Ok(Item {
                bytes: v.bytes.to_vec(), // TODO: this copy should be avoided
                flags: v.flags,
                casid: v.casid,
                expires: expires,
            }))}
            None => { (Status::KEY_ENOENT, Err(None)) }
        }
    })
}
