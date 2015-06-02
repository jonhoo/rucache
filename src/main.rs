extern crate cucache;

fn main() {
    let m = cucache::new(1 << 10);
    let key : &[u8] = &['x' as u8; 1];
    let val = Vec::<u8>::from("y");
    let mut r = m.get(key);
    assert_eq!(r.0, cucache::memcache::Status::KEY_ENOENT);
    r = m.set(key, val.to_vec(), 0, 0);
    assert_eq!(r.0, cucache::memcache::Status::SUCCESS);
    r = m.get(key);
    assert_eq!(r.0, cucache::memcache::Status::SUCCESS);

    assert_eq!(r.1.unwrap().unwrap().val.bytes, val);
    println!("it all seems to work!");
}
