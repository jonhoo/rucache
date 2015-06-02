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
                AtomicPtr::new(ptr::null_mut()),
                AtomicPtr::new(ptr::null_mut()),
                AtomicPtr::new(ptr::null_mut()),
                AtomicPtr::new(ptr::null_mut()),
                AtomicPtr::new(ptr::null_mut()),
                AtomicPtr::new(ptr::null_mut()),
                AtomicPtr::new(ptr::null_mut()),
                AtomicPtr::new(ptr::null_mut()),
            ],
        }
    }
}

pub struct Bin {
	pub mx : sync::Mutex<Void>,
    vals   : [AtomicPtr<sync::Arc<slot::Value>>; ASSOCIATIVITY],
}

impl Bin {
    pub fn has(&self, key : &[u8], now : i64) -> Option<(usize, sync::Arc<slot::Value>)> {
        for i in 0..ASSOCIATIVITY {
            println!("does slot {} contain the element?", i);
            match self.v(i, now) {
                Some(v) => {
                    println!("well, at least there's an element here...");
                    // NOTE: can't use guard when moving value
                    if v.key == key {
                        println!("yay, same key!");
                        return Some((i, v))
                    }
                    println!("nope, key differs ({:?} != {:?})", v.key, key);
                }
                _ => {
                    println!("nope, the slot is empty");
                }
            }
        }

        None
    }

    pub fn v(&self, i : usize, now : i64) -> Option<sync::Arc<slot::Value>> {
        let v = self.vals[i].load(Ordering::Relaxed);

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
        let p = self.vals[i].load(Ordering::SeqCst);

        if p == ptr::null_mut() {
            return None
        }

        Some(unsafe{ Box::from_raw(p) })
    }

    #[allow(mutable_transmutes)]
    pub fn setv(&self, i : usize, v : sync::Arc<slot::Value>, bno : u8) -> memcache::MapResult {
        // setv should *always* be called while holding locks for all bins that may hold this value
        // since everyone else considers slot::Values to be read-only, this means we should be the
        // only ones to modify it.
        println!("setv: v is {:?}", v);
        unsafe {
            let vb : &mut u8 = mem::transmute(&v.bno);
            *vb = bno;
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
        println!("subbing in {:?} for {:?}", v, oldv);
        self.vals[i].store(unsafe{ boxed::into_raw(Box::new(v.clone())) }, Ordering::SeqCst);
        drop(oldv);

        (memcache::Status::SUCCESS, Ok(Some(v)))
    }

    pub fn subin(&self, v : sync::Arc<slot::Value>, bno : u8, now : i64) -> Result<memcache::MapResult, sync::Arc<slot::Value>> {
        for i in 0..ASSOCIATIVITY {
            match self.v(i, now) {
                None => {
                    println!("found empty slot at {} for {:?}", i, v);
                    return Ok(self.setv(i, v, bno));
                }
                _ => {}
            }
        }

        Err(v)
    }

    pub fn kill(&self, i : usize) {
        let oldv = self.gc(i);
        self.vals[i as usize].store(ptr::null_mut(), Ordering::SeqCst);
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

    pub fn add(&self, v : sync::Arc<slot::Value>, bno : u8, now : i64) -> Result<memcache::MapResult, sync::Arc<slot::Value>> {
        let x = self.mx.lock().unwrap();
        println!("adding {:?}", v);
        let res = self.subin(v, bno, now);
        drop(x);
        res
    }
}
