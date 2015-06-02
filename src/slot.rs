use memcache;
use std::fmt;

#[derive(Debug)]
pub struct Value {
    pub bno : u8,
    pub key : Vec<u8>,
    pub val : memcache::Item,
}

impl fmt::Display for Value {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "slot for key {:?} holding {}", self.key, self.val)
    }
}
