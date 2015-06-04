use std::ptr;
use std::mem;
use std::sync;
use std::sync::atomic::{AtomicPtr, Ordering};
use std::boxed;

use slot;
use memcache;

pub const ASSOCIATIVITY_E : u16 = 3;
pub const ASSOCIATIVITY : usize = 1 << ASSOCIATIVITY_E;

#[derive(Default)]
pub struct Void;

impl Default for Bin {
    fn default() -> Bin {
        Bin {
            mx: sync::Mutex::new(Void),
            vals: [
                BinVal::default(),
                BinVal::default(),
                BinVal::default(),
                BinVal::default(),
                BinVal::default(),
                BinVal::default(),
                BinVal::default(),
                BinVal::default(),
            ],
        }
    }
}

struct BinVal {
    val : AtomicPtr<sync::Arc<slot::Value>>,
    tag : u8,
}

impl Default for BinVal {
    fn default() -> BinVal {
        BinVal {
            val: AtomicPtr::new(ptr::null_mut()),
            tag: 0,
        }
    }
}

pub struct Bin {
    pub mx : sync::Mutex<Void>,
    vals   : [BinVal; ASSOCIATIVITY],
}

impl Drop for Bin {
    fn drop(&mut self) {
        if let Ok(_) = self.mx.lock() {
            for i in 0..ASSOCIATIVITY {
                let v = self.gc(i);
                self.vals[i].val.store(ptr::null_mut(), Ordering::SeqCst);
                drop(v);
            }
        }
    }
}

impl Bin {
    pub fn has(&self, key : &[u8], now : i64) -> Option<(usize, sync::Arc<slot::Value>)> {
        for i in 0..ASSOCIATIVITY {
            if self.vals[i].tag != key[0] {
                continue;
            }
            match self.v(i, now) {
                Some(v) => {
                    // NOTE: can't use guard when moving value
                    if v.key == key {
                        return Some((i, v))
                    }
                }
                _ => {}
            }
        }

        None
    }

    pub fn v(&self, i : usize, now : i64) -> Option<sync::Arc<slot::Value>> {
        let v = self.vals[i].val.load(Ordering::Relaxed);

        if v == ptr::null_mut() {
            return None
        }

        let av : &sync::Arc<slot::Value> = unsafe { mem::transmute(v) };

        if !av.val.present(now) {
            return None
        }

        Some(av.clone())
    }

    pub fn gc(&self, i : usize) -> Option<Box<sync::Arc<slot::Value>>> {
        // garbage collect by taking ownership of the Arc, causing it to be dropped
        let p = self.vals[i].val.load(Ordering::SeqCst);

        if p == ptr::null_mut() {
            return None
        }

        Some(unsafe{ Box::from_raw(p) })
    }

    #[allow(mutable_transmutes)]
    pub fn setv(&self, i : usize, v : sync::Arc<slot::Value>, bno : u8) -> ::MapResult {
        // setv should *always* be called while holding locks for all bins that may hold this value
        // since everyone else considers slot::Values to be read-only, this means we should be the
        // only ones to modify it.
        unsafe {
            let vb : &mut u8 = mem::transmute(&v.bno);
            *vb = bno;
            let tag : &mut u8 = mem::transmute(&self.vals[i].tag);
            *tag = v.key[0];
        }

        /* This is kind of tricky:
         *  - first, we gc takes ownership of the currently set Arc (if any)
         *  - next, we get a pointer to the arc that we can atomically swap in
         *    it would be better if we could move the refcount into slot::Value, and thus avoid the
         *    extra indirection here, but that would require duplicating all of the sync::Arc
         *    logic, which I'm wont to do right now.
         *  - next, we swap in our new v using boxed::into_raw(). This consumes ownership, but does
         *    not call the destructor! this is what allows v to continue to exist after setv exits.
         *    the value will be garbage collected when gc() is called some time in the future
         *    (potentially never) for this item, so we are not leaking memory.
         *  - finally, we drop the old Arc, causing its refcount to be dropped.
         *    this will cause *some* thread holding a reference to decrease the count to 0,
         *    which will in turn free the underlying element.
         */
        let oldv = self.gc(i);
        trace!("subbing in {:?} for {:?}", v, oldv);
        self.vals[i].val.store(boxed::into_raw(Box::new(v.clone())), Ordering::SeqCst);
        drop(oldv);

        (memcache::Status::SUCCESS, Ok(v))
    }

    pub fn subin(&self, v : sync::Arc<slot::Value>, bno : u8, now : i64) -> Result<::MapResult, sync::Arc<slot::Value>> {
        for i in 0..ASSOCIATIVITY {
            match self.v(i, now) {
                None => {
                    return Ok(self.setv(i, v, bno));
                }
                _ => {}
            }
        }

        Err(v)
    }

    pub fn kill(&self, i : usize) {
        let oldv = self.gc(i);
        self.vals[i as usize].val.store(ptr::null_mut(), Ordering::SeqCst);
        drop(oldv);
    }

    pub fn available(&self, now : i64) -> bool {
        for i in 0..ASSOCIATIVITY {
            if let None = self.v(i, now) {
                return true;
            }
        }
        return false
    }

    pub fn add(&self, v : sync::Arc<slot::Value>, bno : u8, now : i64) -> Result<::MapResult, sync::Arc<slot::Value>> {
        let x = self.mx.lock().unwrap();
        let res = self.subin(v, bno, now);
        drop(x);
        res
    }
}
