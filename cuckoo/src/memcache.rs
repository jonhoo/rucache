use std::fmt;

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

#[derive(Debug, PartialEq, Eq)]
pub enum Status {
    SUCCESS         = 0x00,
	KEY_ENOENT      = 0x01,
	KEY_EEXISTS     = 0x02,
	E2BIG           = 0x03,
	EINVAL          = 0x04,
	NOT_STORED      = 0x05,
	DELTA_BADVAL    = 0x06,
	NOT_MY_VBUCKET  = 0x07,
	UNKNOWN_COMMAND = 0x81,
	ENOMEM          = 0x82,
	TMPFAIL         = 0x86,
}

use std::sync;
use slot;
pub type MapResult = (Status, Result<Option<sync::Arc<slot::Value>>, Option<String>>);
