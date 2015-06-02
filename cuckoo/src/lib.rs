#![crate_name = "cuckoo"]
#![crate_type = "lib"]
#![feature(unboxed_closures)]
#![feature(alloc)]

extern crate time;
extern crate rand;

use std::sync;
use rand::Rng;
use std::thread;
use std::hash::{Hash, Hasher, SipHasher};

mod bins;
mod slot;
mod memcache;

const MAX_HASHES : usize = 10;
const MAX_SEARCH_DEPTH : usize = 1000;

struct CuckooMap {
	bins    : Vec<bins::Bin>,
	nhashes : u8,
}

pub struct Map {
	map  : sync::RwLock<CuckooMap>,
	size : u64,
}

impl Map {
    pub fn get(&self, key : &[u8]) -> memcache::MapResult {
        self.map.read().unwrap().get(key)
    }

    pub fn delete(&self, key : &[u8], casid : u64) -> memcache::MapResult {
        self.map.read().unwrap().delete(key, casid)
    }

    pub fn set(&self, key : &[u8], bytes : Vec<u8>, flags : u32, expires : i64) -> memcache::MapResult {
        self.map.read().unwrap().insert(key, memcache::fset(bytes, flags, expires, 0))
    }

    pub fn add(&self, key : &[u8], bytes : Vec<u8>, flags : u32, expires : i64) -> memcache::MapResult {
        self.map.read().unwrap().insert(key, memcache::fadd(bytes, flags, expires))
    }

    pub fn replace(&self, key : &[u8], bytes : Vec<u8>, flags : u32, expires : i64) -> memcache::MapResult {
        self.map.read().unwrap().insert(key, memcache::freplace(bytes, flags, expires))
    }

    pub fn append(&self, key : &[u8], bytes : Vec<u8>, casid : u64) -> memcache::MapResult {
        self.map.read().unwrap().insert(key, memcache::fappend(bytes, casid))
    }

    pub fn prepend(&self, key : &[u8], bytes : Vec<u8>, casid : u64) -> memcache::MapResult {
        self.map.read().unwrap().insert(key, memcache::fprepend(bytes, casid))
    }

    pub fn cas(&self, key : &[u8], bytes : Vec<u8>, flags : u32, expires : i64, casid : u64) -> memcache::MapResult {
        self.map.read().unwrap().insert(key, memcache::fset(bytes, flags, expires, casid))
    }

    pub fn incr(&self, key : &[u8], by : u64, def : u64, expires : i64) -> memcache::MapResult {
        self.map.read().unwrap().insert(key, memcache::fincr(by, def, expires))
    }

    pub fn decr(&self, key : &[u8], by : u64, def : u64, expires : i64) -> memcache::MapResult {
        self.map.read().unwrap().insert(key, memcache::fincr(by, def, expires))
    }
}

pub fn new(esize_in : u64) -> Map {
    let mut esize = esize_in;
    if esize == 0 {
        esize = 1 << 16;
    }
    println!("constructing map with {} slots", esize);

    // make esize a power of two
    if (esize&(esize-1)) != 0 {
        // at least 2^10 bins unless we're given a power of two explicitly
        let mut shift : u64 = 1 << 10;
        while esize > shift {
            shift <<= 1
        }
        esize = shift;
    }
    println!("(actually {} slots)", esize);

    // since each bin can hold ASSOCIATIVITY elements we don't need as many bins
    let mut bins = esize >> bins::ASSOCIATIVITY_E;
    println!("(so actually {} bins)", bins);

    if bins == 0 {
        bins = 1
    }

    let map = CuckooMap {
        bins    : (0..bins as usize).map(|_| bins::Bin::default()).collect(),
        nhashes : 2
    };

    Map {
        map  : sync::RwLock::new(map),
        size : esize,
    }
}

#[derive(Clone, Debug)]
struct Displacement {
	v    : sync::Arc<slot::Value>,
	from : usize,
    ki   : usize,
	to   : usize,
	tobn : u8,
}

impl CuckooMap {
    /// get returns the current value (if any) for the given key
    pub fn get(&self, key : &[u8]) -> memcache::MapResult {
        println!("asked to retrieve key {:?}", key);

        let now = time::get_time().sec;
        let bins : Vec<usize> = (0..self.nhashes).map(|n| self.nth_key_bin(key, n)).collect();

        println!("bins are {:?}", bins);

        for bin in bins {
            println!("checking bin {:?}", bin);
            match self.bins[bin].has(key, now) {
                Some((_, v)) => {
                    println!("bin holds {:?}!", v);
                    return (memcache::Status::SUCCESS, Ok(Some(v)))
                }
                _ => {}
            }
        }

        println!("none of the bins held our value :(");
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

    pub fn insert(&self, key : &[u8], upd : Box<Fn(Option<&memcache::Item>) -> (memcache::Status, Result<memcache::Item, Option<String>>)>) -> memcache::MapResult {
        println!("asked to do an insert of key {:?}", key);
        println!("using {} hashes and {} bins", self.nhashes, self.bins.len());

        let now = time::get_time().sec;
        let mut bins = (0..self.nhashes).map(|n| self.nth_key_bin(key, n)).collect();

        println!("bins are {:?}", bins);

        let mxs = self.lock_in_order(&bins);
        for (bi, b) in bins.iter().enumerate() {
            if let Some((i, v)) = self.bins[*b].has(key, now) {
                println!("key already exists; overwriting");
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

        println!("key does not already exists");

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

        println!("upd for new entry on key {:?} returned value {:?}", key, res);
        let mut newv = sync::Arc::new(slot::Value {
            bno: 0,
            key: key.to_vec(),
            val: res.unwrap(),
        });

        println!("checking for direct insert");
        for (bi, b) in bins.iter().enumerate() {
            if self.bins[*b].available(now) {
                println!("bin {} has available slot", *b);
                match self.bins[*b].add(newv, bi as u8, now) {
                    Ok(res) => { println!("got it -- done!"); return res; }
                    Err(v) => { println!("add failed, darn..."); newv = v; }
                }
            }
        }

        println!("need to do a search");
        loop {
            let path_ = self.search(&bins, now);
            match path_ {
                None => {
                    return (memcache::Status::ENOMEM, Err(None))
                }
                _ => {}
            }

            let path = path_.unwrap();
            println!("found path {:?}", path);
            let freeing = path[0].from;

            // recompute bins because #hashes might have changed
            if bins.len() as u8 != self.nhashes {
                bins = (0..self.nhashes).map(|n| self.nth_key_bin(&newv.key[..], n)).collect();
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
        }
    }

    pub fn delete(&self, key : &[u8], casid : u64) -> memcache::MapResult {
        let now = time::get_time().sec;
        let mut bins = (0..self.nhashes).map(|n| self.nth_key_bin(key, n)).collect();
        let mxs = self.lock_in_order(&mut bins);

        let mut res : memcache::MapResult = (memcache::Status::KEY_ENOENT, Err(None));
        for (b, mx) in mxs {
            match self.bins[b].has(key, now) {
                Some((i, v)) => {
                    if v.val.casid != 0 && v.val.casid != casid {
                        return (memcache::Status::KEY_EEXISTS, Err(None));
                    }

                    self.bins[b].kill(i);
                    res = (memcache::Status::SUCCESS, Ok(Some(v)))
                }
                _ => {}
            }
            drop(mx)
        }
        res
    }

    fn nth_key_bin(&self, key : &[u8], n : u8) -> usize {
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

            mv.tobn = mv.v.bno;
            for _ in 0..self.nhashes {
                mv.tobn = (mv.tobn + 1) % self.nhashes;
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
        for (i, mv) in path.iter().enumerate() {
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
            self.bins[mv.to].subin(v.unwrap(), mv.tobn, now);
            self.bins[mv.from].kill(mv.ki);
        }
        true
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
fn it_works() {
    let m = new(1 << 10);
    let key : &[u8] = &['x' as u8; 1];
    let val = Vec::<u8>::from("y");
    let mut r = m.get(key);
    assert_eq!(r.0, memcache::Status::KEY_ENOENT);

    let v = setget(&m, key, val.to_vec());
    r = m.delete(key, v.val.casid);
    assert_eq!(r.0, memcache::Status::SUCCESS);

    r = m.get(key);
    assert_eq!(r.0, memcache::Status::KEY_ENOENT);

    let mut rng = rand::thread_rng();
    for i in 0..(1 << 9) {
        let x = rng.gen::<u64>().to_string().into_bytes();
        setget(&m, &x[..], i.to_string().into_bytes());
    }
}
