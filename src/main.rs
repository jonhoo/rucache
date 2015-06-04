#![feature(scoped)]

extern crate rucache;
use rucache::memcache;

extern crate getopts;
extern crate time;
extern crate byteorder;
use byteorder::{BigEndian, ByteOrder};

#[macro_use]
extern crate log;
use log::{LogRecord, LogLevel, LogLevelFilter, LogMetadata};

use std::io::Write;
use std::net;
use std::thread;
use std::env;
use std::str::FromStr;
use std::process;
use std::sync;
use std::sync::mpsc;
use std::io;
use std::str;

extern crate num;
use num::traits::FromPrimitive;

fn from_mctime(i : u32) -> i64 {
    if i > 0 && i < 30*24*60*60 {
        time::get_time().sec + i as i64
    } else {
        i as i64
    }
}

fn main() {
    let _ = log::set_logger(|max_log_level| {
        max_log_level.set(LogLevelFilter::Warn);
        Box::new(SimpleLogger)
    });

    let mut opts = getopts::Options::new();
    opts.optflagopt("p", "", "Listen on TCP port <num>, the default is port 11211.", "<num>");
    opts.optflagopt("U", "", "Listen on UDP port <num>, the default is port 11211, 0 is off.", "<num>");
    opts.optflag("h", "help", "display this help and exit");

    let args: Vec<String> = env::args().collect();
    let matches = match opts.parse(&args[1..]) {
        Ok(m) => m,
        Err(f) => {
            println!("{}", f);
            process::exit(1);
        }
    };

    if matches.opt_present("help") {
        let brief = format!("Usage: {} [options]", args[0]);
        println!("{}", opts.usage(&brief));
        return;
    }

    let host = "127.0.0.1";
    let mut tcp_port = 11211;
    if let Some(port) = matches.opt_str("p") {
        if let Ok(portn) = u16::from_str(&port) {
            tcp_port = portn;
        }
    }

    info!("listening on {}:tcp:{}", host, tcp_port);
    let listener = net::TcpListener::bind((host, tcp_port));
    if let Err(e) = listener {
        panic!("failed to listen on port: {}", e);
    }

    info!("allocating map");
    let m = rucache::new(1 << 10);

    info!("spinning up worker pool");
    let (tx, rx) = mpsc::channel();
    let rxmx = sync::Mutex::new(rx);
    let pool : Vec<thread::JoinGuard<()>> = (1..1000).map(|_| {
        let map = &m;
        let rxl = &rxmx;
        thread::scoped(move || {
            handle_clients(map, rxl);
        })
    }).collect();

    info!("accepting connections");
    for stream in listener.unwrap().incoming() {
        match stream {
            Ok(stream) => {
                if let Err(e) = tx.send(stream) {
                    panic!("failed to queue incoming request {}", e);
                }
            }
            Err(e) => {
                warn!("{}", e);
            }
        }
    }

    drop(pool);
}

fn read_full(r : &mut io::Read, to : &mut [u8]) -> Result<(), io::Error> {
    let mut nread = 0 as usize;
    while nread < to.len() {
        match r.read(&mut to[nread..]) {
            Ok(n) if n == 0 => { return Err(std::io::Error::new(std::io::ErrorKind::ConnectionAborted, "")); }
            Ok(n) => { nread += n; }
            Err(ref e) if e.kind() == io::ErrorKind::Interrupted => {},
            Err(e) => return Err(From::from(e))
        }
    }
    Ok(())
}

fn execute(m : &rucache::Map, req : &memcache::Request, c : &mut net::TcpStream) -> bool {
    let mut rh = memcache::ResponseHeader::from_req(req);
    match memcache::Command::from_u8(req.op) {
        Some(op) => {
            let key = req.key();
            let extras = req.extras();
            let body = req.body();

            match op.noq() {
                memcache::Command::FLUSH if extras.len() == 4 => {
                    let mut tm = from_mctime(BigEndian::read_u32(extras));
                    if tm == 0 {
                        tm = time::get_time().sec;
                    }
                    m.touchall(tm);

                    rh.status = memcache::Status::SUCCESS as u16;
                    rh.construct(&[], &[], &[]).transmit(c)
                }
                memcache::Command::SET
                | memcache::Command::ADD
                | memcache::Command::REPLACE
                if extras.len() == 8 => {
                    let flags = BigEndian::read_u32(&extras[0..4]);
                    let expires = from_mctime(BigEndian::read_u32(&extras[4..8]));

                    // XXX: unfortunate copy...
                    let b = body.to_vec();

                    let res = match op.noq() {
                        memcache::Command::SET if req.cas == 0 => m.set(key, b, flags, expires),
                        memcache::Command::REPLACE if req.cas == 0 => m.replace(key, b, flags, expires),
                        memcache::Command::ADD => m.add(key, b, flags, expires),
                        memcache::Command::SET | memcache::Command::REPLACE | _ => {
                            m.cas(key, b, flags, expires, req.cas)
                        }
                    };

                    rh.status = res.0 as u16;
                    if let (memcache::Status::SUCCESS, Ok(v)) = res {
                        rh.cas = v.val.casid;
                    }

                    rh.construct(&[], &[], &[]).transmit(c)
                }
                memcache::Command::DELETE => {
                    rh.status = m.delete(key, req.cas).0 as u16;
                    rh.construct(&[], &[], &[]).transmit(c)
                }
                memcache::Command::INCREMENT
                | memcache::Command::DECREMENT
                if extras.len() == 20 => {
                    let by = BigEndian::read_u64(&extras[0..8]);
                    let def = BigEndian::read_u64(&extras[8..16]);
                    let expires = from_mctime(BigEndian::read_u32(&extras[16..20]));

                    let v = match op.noq() {
                        memcache::Command::INCREMENT => m.incr(key, by, def, expires),
                        memcache::Command::DECREMENT | _ => m.decr(key, by, def, expires),
                    };

                    rh.status = v.0 as u16;
                    if let (memcache::Status::SUCCESS, Ok(v)) = v {
                        let extras = &mut [0u8; 8];
                        BigEndian::write_u64(&mut extras[..], u64::from_str(str::from_utf8(&v.val.bytes[..]).unwrap()).unwrap());

                        rh.cas = v.val.casid;
                        rh.construct(&extras[..], &[], &[]).transmit(c)
                    } else {
                        rh.construct(&[], &[], &[]).transmit(c)
                    }
                }
                memcache::Command::GET | memcache::Command::GETK => {
                    let v = m.get(key);
                    rh.status = v.0 as u16;

                    if let (memcache::Status::SUCCESS, Ok(v)) = v {
                        rh.cas = v.val.casid;
                        let extras = &mut [0u8; 4];
                        BigEndian::write_u32(&mut extras[..], v.val.flags);
                        rh.construct(
                            &extras[..],
                            if op.noq() == memcache::Command::GETK {key} else {&[]},
                            &v.val.bytes[..]
                        ).transmit(c)
                    } else {
                        rh.construct(&[], &[], &[]).transmit(c)
                    }
                }
                memcache::Command::APPEND | memcache::Command::PREPEND => {
                    // XXX: unfortunate copy...
                    let b = body.to_vec();

                    let res = match op.noq() {
                        memcache::Command::PREPEND => m.prepend(key, b, req.cas),
                        memcache::Command::APPEND | _ => m.append(key, b, req.cas),
                    };

                    rh.status = res.0 as u16;
                    if let (memcache::Status::SUCCESS, Ok(v)) = res {
                        rh.cas = v.val.casid;
                    }

                    rh.construct(&[], &[], &[]).transmit(c)
                }
                memcache::Command::VERSION => {
                    rh.status = memcache::Status::SUCCESS as u16;
                    rh.construct(&[], &[], "0.1.0".as_bytes()).transmit(c)
                }
                memcache::Command::NOOP => {
                    rh.status = memcache::Status::SUCCESS as u16;
                    rh.construct(&[], &[], &[]).transmit(c)
                }
                _ => {
                    warn!("client sent unhandled command: {:?}", op);
                    rh.status = memcache::Status::EINVAL as u16;
                    rh.construct(&[], &[], &[]).transmit(c)
                }
            }
        }
        None => {
            rh.status = memcache::Status::UNKNOWN_COMMAND as u16;
            rh.construct(&[], &[], &[]).transmit(c)
        }
    }
}

fn handle_client(m : &rucache::Map, mut c : net::TcpStream) {
    let mut magic = [0_u8; 1];
    let mut body = Vec::with_capacity(100);
    'outer: loop {
        if let Err(_) = read_full(&mut c, &mut magic) {
            break 'outer;
        }

        unsafe { body.set_len(100); }
        body.shrink_to_fit();
        body.clear();
        unsafe { body.set_len(24); }
        match magic[0] {
            0x80 => {
                // binary protocol
                // memcache request
                body[0] = magic[0];
                if let Err(_) = read_full(&mut c, &mut body[1..24]) {
                    break 'outer;
                }

                let blen = BigEndian::read_u32(&body[8..12]) as usize;
                body.reserve_exact(blen);
                unsafe { body.set_len(24 + blen); }

                if let Err(_) = read_full(&mut c, &mut body[24..(24+blen)]) {
                    break 'outer;
                }

                let req = memcache::Request::parse(&mut body[..]);
                if !execute(m, req, &mut c) {
                    break 'outer;
                }
            }
            0x81 => {
                warn!("expected request from client, got response magic");
                break 'outer;
            }
            _ => {
                // text protocol
            }
        }
    };

    info!("client {:?} hung up", c);
}

fn handle_clients(m : &rucache::Map, rxmx : &sync::Mutex<mpsc::Receiver<net::TcpStream>>) {
    loop {
        if let Ok(rx) = rxmx.lock() {
            if let Ok(c) = rx.recv() {
                drop(rx);
                handle_client(&m, c);
            } else {
                // channel receive error
                return;
            }
        } else {
            // lock poisoned by panic
            return;
        }
    }
}

struct SimpleLogger;
impl log::Log for SimpleLogger {
    fn enabled(&self, metadata: &LogMetadata) -> bool {
        metadata.level() <= LogLevel::Warn
    }

    #[allow(unused_must_use)]
    fn log(&self, record: &LogRecord) {
        if self.enabled(record.metadata()) {
            writeln!(&mut std::io::stderr(), "{} - {}", record.level(), record.args());
        }
    }
}

