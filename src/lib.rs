#![crate_name = "cucache"]
#![crate_type = "lib"]
#![feature(alloc)]

#[macro_use] extern crate enum_primitive;
extern crate num;
extern crate time;
extern crate rand;
extern crate byteorder;

#[macro_use]
extern crate log;

use std::ptr;
use std::sync;
use std::boxed;
use std::sync::Arc;
use std::hash::{Hash, Hasher, SipHasher};
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::AtomicPtr;
use std::sync::atomic::Ordering;
use std::sync::RwLockReadGuard;


#[cfg(test)]
use rand::Rng;

mod bins;
mod slot;
pub mod memcache;

const MAX_HASHES : usize = 10;
const MAX_SEARCH_DEPTH : usize = 100;

struct CuckooMap {
	bins    : Vec<bins::Bin>,
	nhashes : AtomicUsize,
}

type Mapref = sync::Arc<CuckooMap>;
pub type MapResult = (memcache::Status, Result<sync::Arc<slot::Value>, Option<String>>);

pub struct Map {
    resize : sync::RwLock<bool>,
	map    : AtomicPtr<Mapref>,
	size   : AtomicUsize,
}

unsafe impl Sync for Map { }

impl Drop for Map {
    fn drop(&mut self) {
        if let Ok(_) = self.resize.write() {
            let gc : Box<Mapref> = unsafe { Box::from_raw(self.map.load(Ordering::SeqCst)) };
            self.map.store(ptr::null_mut(), Ordering::SeqCst);
            self.size.store(0, Ordering::SeqCst);
            // TODO: what about concurrent gets?
            drop(gc);
        }
    }
}

impl Map {
    fn fix(&self, nhashes : usize, rlock : RwLockReadGuard<bool>) {
        debug!("asked to grow map");

        if nhashes+1 < MAX_HASHES {
            if self.get_().nhashes.compare_and_swap(nhashes, nhashes+1, Ordering::SeqCst) == nhashes {
                info!("increased the number of hashes to {}", nhashes+1);
            } else {
                debug!("someone already changed the number of hash functions");
            }
            return;
        }

        let nowp = self.map.load(Ordering::SeqCst);

        drop(rlock);

        let startmx = time::get_time();
        let mx = self.resize.write().unwrap();

        // we need to check that no-one else fixed the map while we were waiting for the lock
        if self.map.load(Ordering::SeqCst) != nowp {
            // someone else already resized the map
            debug!("map already grown");
            return;
        }

        let start = time::get_time();

        // we now have exclusive access write access to the map
        // and we know no-one else can change it while we're in here
        // first, take ownership of old map to ensure it gets killed when we're done
        let old : Box<Mapref> = unsafe { Box::from_raw(nowp) };

        let nsize = self.size.load(Ordering::SeqCst) << 1;
        let newm = Box::new(create(nsize));
        info!("growing hashtable to {}", nsize);

        // copy over all the items
        // TODO: parallelize
        for v in old.into_iter() {
            // TODO: preserve CAS
            let upd = memcache::fset(v.val.bytes.to_vec(), v.val.flags, v.val.expires, 0);
            let mut r = newm.insert(&v.key[..], &upd);
            if r.0 != memcache::Status::SUCCESS {
                newm.nhashes.fetch_add(1, Ordering::SeqCst);
                r = newm.insert(&v.key[..], &upd);
                if r.0 != memcache::Status::SUCCESS {
                    panic!("Failed to move element {:?} to new map while resizing", v.val)
                }
            }
        }

        // swap in new map
        let newmp = boxed::into_raw(newm);
        trace!("updated primary mapref to {:?}", newmp);
        self.map.store(newmp, Ordering::SeqCst);
        self.size.store(nsize, Ordering::SeqCst);

        drop(mx);
        println!("_ resize {}", (time::get_time() - start).num_microseconds().unwrap());
    }

    fn get_(&self) -> Mapref {
        let p = self.map.load(Ordering::SeqCst);
        trace!("primary mapref at {:?}?", p);
        let m : &Mapref = unsafe { &*p };
        m.clone()
    }

    fn getm(&self) -> (RwLockReadGuard<bool>, Mapref) {
        let mx = self.resize.read().unwrap();
        (mx, self.get_())
    }

    fn op(&self, key : &[u8], upd : Box<Fn(Option<&memcache::Item>) -> (memcache::Status, Result<memcache::Item, Option<String>>)>) -> MapResult {
        let start = time::get_time();
        loop {
            let (mx, map) = self.getm();
            let nh = map.nhashes.load(Ordering::SeqCst);
            let r = map.insert(key, &upd);

            if r.0 == memcache::Status::ENOMEM {
                debug!("_ iterate {}", (time::get_time() - start).num_microseconds().unwrap());
                self.fix(nh, mx);
                continue
            }
            println!("_ insert {}", (time::get_time() - start).num_microseconds().unwrap());
            return r;
        }
    }

    pub fn get(&self, key : &[u8]) -> MapResult {
        self.get_().get(key)
    }

    pub fn delete(&self, key : &[u8], casid : u64) -> MapResult {
        self.getm().1.delete(key, casid)
    }

    pub fn set(&self, key : &[u8], bytes : Vec<u8>, flags : u32, expires : i64) -> MapResult {
        self.op(key, memcache::fset(bytes, flags, expires, 0))
    }

    pub fn add(&self, key : &[u8], bytes : Vec<u8>, flags : u32, expires : i64) -> MapResult {
        self.op(key, memcache::fadd(bytes, flags, expires))
    }

    pub fn replace(&self, key : &[u8], bytes : Vec<u8>, flags : u32, expires : i64) -> MapResult {
        self.op(key, memcache::freplace(bytes, flags, expires))
    }

    pub fn append(&self, key : &[u8], bytes : Vec<u8>, casid : u64) -> MapResult {
        self.op(key, memcache::fappend(bytes, casid))
    }

    pub fn prepend(&self, key : &[u8], bytes : Vec<u8>, casid : u64) -> MapResult {
        self.op(key, memcache::fprepend(bytes, casid))
    }

    pub fn cas(&self, key : &[u8], bytes : Vec<u8>, flags : u32, expires : i64, casid : u64) -> MapResult {
        self.op(key, memcache::fset(bytes, flags, expires, casid))
    }

    pub fn incr(&self, key : &[u8], by : u64, def : u64, expires : i64) -> MapResult {
        self.op(key, memcache::fincr(by, def, expires))
    }

    pub fn decr(&self, key : &[u8], by : u64, def : u64, expires : i64) -> MapResult {
        self.op(key, memcache::fdecr(by, def, expires))
    }
}

pub fn new(esize_in : usize) -> Map {
    let mut esize = esize_in;
    if esize == 0 {
        esize = 1 << 16;
    }
    debug!("constructing map with {} slots", esize);

    // make esize a power of two
    if (esize&(esize-1)) != 0 {
        // at least 2^10 bins unless we're given a power of two explicitly
        let mut shift : usize = 1 << 10;
        while esize > shift {
            shift <<= 1
        }
        esize = shift;
    }
    trace!("(actually {} slots)", esize);

    let newm = Box::new(create(esize));
    let newmp = boxed::into_raw(newm);
    trace!("new primary mapref is {:?}", newmp);
    let m = Map {
        resize : sync::RwLock::new(false),
        map    : AtomicPtr::new(newmp),
        size   : AtomicUsize::new(esize),
    };
    m
}

fn create(esize : usize) -> sync::Arc<CuckooMap> {
    // since each bin can hold ASSOCIATIVITY elements we don't need as many bins
    let mut bins = esize >> bins::ASSOCIATIVITY_E;

    if bins == 0 {
        bins = 1
    }
    trace!("creating inner map with {} bins", bins);

    sync::Arc::new(CuckooMap {
        bins    : (0..bins as usize).map(|_| bins::Bin::default()).collect(),
        nhashes : AtomicUsize::new(2),
    })
}

#[derive(Clone, Debug)]
struct Displacement {
	v    : sync::Arc<slot::Value>,
	from : usize,
    ki   : usize,
	to   : usize,
	tobn : usize,
}

impl CuckooMap {
    /// get returns the current value (if any) for the given key
    pub fn get(&self, key : &[u8]) -> MapResult {
        debug!("asked to retrieve key {:?}", key);

        let now = time::get_time().sec;
        let bins : Vec<usize> = (0..self.nhashes.load(Ordering::Relaxed)).map(|n| self.nth_key_bin(key, n)).collect();

        trace!("bins are {:?}", bins);

        for bin in bins {
            trace!("checking bin {:?}", bin);
            match self.bins[bin].has(key, now) {
                Some((_, v)) => {
                    return (memcache::Status::SUCCESS, Ok(v))
                }
                _ => {}
            }
        }

        trace!("none of the bins held our value :(");
        (memcache::Status::KEY_ENOENT, Err(None))
    }

    fn lock_in_order(&self, bins_ : &Vec<usize>) -> Vec<(usize, sync::MutexGuard<bins::Void>)> {
        let mut bins = bins_.to_vec();
        bins.sort();

        let mut last = -1_i64;
        let mut v = Vec::with_capacity(bins.len());

        for b in bins {
            if b as i64 != last {
                v.push((b, self.bins[b].mx.lock().unwrap()));
                last = b as i64;
            }
        }
        v
    }

    pub fn insert(&self, key : &[u8], upd : &Box<Fn(Option<&memcache::Item>) -> (memcache::Status, Result<memcache::Item, Option<String>>)>) -> MapResult {
        debug!("asked to do an insert of key {:?}", key);
        trace!("using {} hashes and {} bins", self.nhashes.load(Ordering::SeqCst), self.bins.len());

        let now = time::get_time().sec;
        let mut bins = (0..self.nhashes.load(Ordering::SeqCst)).map(|n| self.nth_key_bin(key, n)).collect();

        trace!("bins are {:?}", bins);

        let mxs = self.lock_in_order(&bins);
        for (bi, b) in bins.iter().enumerate() {
            if let Some((i, v)) = self.bins[*b].has(key, now) {
                debug!("key already exists; overwriting");
                let r = upd(Some(&v.val));
                match r.0 {
                    memcache::Status::SUCCESS => {
                        return self.bins[*b].setv(i, sync::Arc::new(slot::Value{
                            key: key.to_vec(),
                            bno: bi as u8,
                            val: r.1.unwrap(),
                        }), bi as u8);
                    }
                    s => {
                        match r.1 {
                            Ok(_) => { panic!("got failure, but Ok value!"); }
                            Err(x) => { return (s, Err(x)); }
                        }
                    }
                }
            }
        }
        drop(mxs);

        trace!("key does not already exists");

        let (status, res) = upd(None);
        if status != memcache::Status::SUCCESS {
            if let Err(v) = res {
                return (status, Err(v));
            } else {
                panic!("received status {:?}, but result was not an error: {:?}", status, res);
            }
        }

        if let Err(_) = res {
            panic!("received SUCCESS, but result was an error: {:?}", res);
        }

        trace!("upd for new entry on key {:?} returned value {:?}", key, res);
        let mut newv = sync::Arc::new(slot::Value {
            bno: 0,
            key: key.to_vec(),
            val: res.unwrap(),
        });

        trace!("checking for direct insert");
        for (bi, b) in bins.iter().enumerate() {
            if self.bins[*b].available(now) {
                trace!("bin {} has available slot", *b);
                match self.bins[*b].add(newv, bi as u8, now) {
                    Ok(res) => { return res; }
                    Err(v) => { trace!("add failed, darn..."); newv = v; }
                }
            }
        }

        trace!("need to do a search");
        loop {
            let path_ = self.search(&bins, now);
            match path_ {
                None => {
                    return (memcache::Status::ENOMEM, Err(None))
                }
                _ => {}
            }

            let path = path_.unwrap();
            trace!("found path {:?}", path);
            let freeing = path[0].from;

            // recompute bins because #hashes might have changed
            let hashes = self.nhashes.load(Ordering::SeqCst);
            if bins.len() != hashes { 
                bins = (0..hashes).map(|n| self.nth_key_bin(&newv.key[..], n)).collect();
            }

            // sanity check that this path will make room in the right bin
            let mut tobin = 0;
            for (bi, b) in bins.iter().enumerate() {
                if freeing == *b {
                    tobin = bi as u8;
                }
            }

            // only after the search do we acquire locks
            if self.validate_execute(path, now) {
                match self.bins[freeing].add(newv, tobin, now) {
                    Ok(res) => { return res; }
                    Err(v) => { newv = v; }
                }
            }
            trace!("search path validation failed");
        }
    }

    pub fn delete(&self, key : &[u8], casid : u64) -> MapResult {
        debug!("asked to do delete key {:?}", key);

        let now = time::get_time().sec;
        let mut bins = (0..self.nhashes.load(Ordering::SeqCst)).map(|n| self.nth_key_bin(key, n)).collect();
        let mxs = self.lock_in_order(&mut bins);

        let mut res : MapResult = (memcache::Status::KEY_ENOENT, Err(None));
        for (b, mx) in mxs {
            match self.bins[b].has(key, now) {
                Some((i, v)) => {
                    if v.val.casid != 0 && v.val.casid != casid {
                        return (memcache::Status::KEY_EEXISTS, Err(None));
                    }

                    self.bins[b].kill(i);
                    res = (memcache::Status::SUCCESS, Ok(v))
                }
                _ => {}
            }
            drop(mx)
        }
        res
    }

    fn nth_key_bin(&self, key : &[u8], n : usize) -> usize {
        let mut h = SipHasher::new();
        key.hash(&mut h);
        n.hash(&mut h);
        h.finish() as usize % self.bins.len()
    }

    fn search(&self, bins : &Vec<usize>, now : i64) -> Option<Vec<Displacement>> {
        for depth in 1..MAX_SEARCH_DEPTH {
            for b in bins {
                if let path @ Some(_) = self.find(Vec::new(), *b, depth as isize, now) {
                    return path
                }
            }
        }
        None
    }

    fn find(&self, path : Vec<Displacement>, bin : usize, depth : isize, now : i64) -> Option<Vec<Displacement>> {
        if depth < 0 {
            return None
        }

        for i in 0..bins::ASSOCIATIVITY {
            let v_ = self.bins[bin].v(i, now);
            match v_ {
                None => { return Some(path); }
                _ => {}
            }

            let v = v_.unwrap();
            let mut npath = path.to_vec();
            let mut mv = Displacement {
                v    : v,
                from : bin,
                ki   : i,
                to   : bin,
                tobn : 0,
            };

            mv.tobn = mv.v.bno as usize;
            let hashes = self.nhashes.load(Ordering::SeqCst);
            for _ in 0..hashes {
                mv.tobn = (mv.tobn + 1) % hashes;
                mv.to = self.nth_key_bin(&mv.v.key[..], mv.tobn);
                // XXX: could potentially try all bins here and
                // check each for available()? extra-broad
                // search...
                if mv.to != mv.from {
                    break
                }
            }

            if mv.to == mv.from {
                continue
            }

            if path.iter().any(|x| x.from == mv.to) {
                // path contains cycles
                // XXX: could instead try next bin here
                continue
            }

            let into = mv.to;
            npath.push(mv);
            if self.bins[into].available(now) {
                return Some(npath)
            } else {
                return self.find(npath, into, depth-1, now)
            }
        }
        None
    }

    fn validate_execute(&self, mut path : Vec<Displacement>, now : i64) -> bool {
        path.reverse();
        for mv in path {
            let _mxs = self.lock_in_order(&vec![mv.from, mv.to]);
            if !self.bins[mv.to].available(now) {
                return false
            }

            let v = self.bins[mv.from].v(mv.ki, now);
            match v {
                None => {
                    return false;
                }
                Some(ref av) if av.key != mv.v.key => {
                    return false;
                }
                _ => {}
            }

            // should insert before kill to avoid failed gets
            // there's also no need to check the return value, because we already checked that
            // there is room while holding the lock above.
            let _ = self.bins[mv.to].subin(v.unwrap(), mv.tobn as u8, now);
            self.bins[mv.from].kill(mv.ki);
        }
        true
	}
}

struct CuckooIterator<'a> {
    map  : &'a CuckooMap,
    bin  : usize,
    now  : i64,
    vals : Vec<sync::Arc<slot::Value>>,
    vali : usize,
}

impl<'a> IntoIterator for &'a CuckooMap {
    type Item = sync::Arc<slot::Value>;
    type IntoIter = CuckooIterator<'a>;

    fn into_iter(self) -> Self::IntoIter {
        CuckooIterator {
            map  : self,
            bin  : 0,
            now  : time::get_time().sec,
            vals : Vec::with_capacity(bins::ASSOCIATIVITY),
            vali : 0,
        }
    }
}

impl<'a> Iterator for CuckooIterator<'a> {
    type Item = sync::Arc<slot::Value>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.vals.len() == 0 {
            for i in 0..bins::ASSOCIATIVITY {
                if let Some(v) = self.map.bins[self.bin].v(i, self.now) {
                    self.vals.push(v);
                }
            }
        }

        if self.vali < self.vals.len() {
            self.vali += 1;
            return Some(self.vals[self.vali-1].clone())
        } else {
            self.bin += 1;
            self.vali = 0;
            self.vals.clear();
        }

        if self.bin == self.map.bins.len() {
            return None;
        }
        return self.next();
    }
}

#[cfg(test)]
fn setget(m : &Map, key : &[u8], val : Vec<u8>) -> sync::Arc<slot::Value> {
    let mut r = m.set(key, val.to_vec(), 0, 0);
    assert_eq!(r.0, memcache::Status::SUCCESS);
    r = m.get(key);
    assert_eq!(r.0, memcache::Status::SUCCESS);

    let r2 = r.1.unwrap().unwrap();
    assert_eq!(r2.val.bytes, val);
    r2
}

#[test]
fn it_gets_sets() {
    let m = new(1 << 10);
    let key : &[u8] = &['x' as u8; 1];
    let val = Vec::<u8>::from("y");
    let r = m.get(key);
    assert_eq!(r.0, memcache::Status::KEY_ENOENT);
    let _ = setget(&m, key, val.to_vec());
}

#[test]
fn it_deletes() {
    let m = new(1 << 10);
    let key : &[u8] = &['x' as u8; 1];
    let val = Vec::<u8>::from("y");
    let v = setget(&m, key, val.to_vec());
    let mut r = m.delete(key, v.val.casid);
    assert_eq!(r.0, memcache::Status::SUCCESS);

    r = m.get(key);
    assert_eq!(r.0, memcache::Status::KEY_ENOENT);
}

#[test]
fn it_handles_some_keys() {
    let m = new(1 << 10);
    let mut rng = rand::thread_rng();
    for i in 0..(1 << 9) {
        let x = rng.gen::<u64>().to_string().into_bytes();
        setget(&m, &x[..], i.to_string().into_bytes());
    }
}

#[test]
fn it_handles_resizes() {
    let m = new(1 << 9);
    let mut rng = rand::thread_rng();
    for i in 0..(1 << 10) {
        let x = rng.gen::<u64>().to_string().into_bytes();
        setget(&m, &x[..], i.to_string().into_bytes());
    }
    panic!("stop!");
}
