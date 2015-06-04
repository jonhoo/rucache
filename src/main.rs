#![feature(scoped)]

extern crate cucache;
use cucache::memcache;

extern crate getopts;
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

extern crate num;
use num::traits::FromPrimitive;

fn main() {
    let _ = log::set_logger(|max_log_level| {
        max_log_level.set(LogLevelFilter::Debug);
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
    let listener = net::TcpListener::bind((host, tcp_port)).unwrap();

    info!("allocating map");
    let m = cucache::new(1 << 10);

    info!("spinning up worker pool");
    let (tx, rx) = mpsc::channel();
    let rxmx = sync::Mutex::new(rx);
    let pool : Vec<thread::JoinGuard<()>> = (1..10).map(|_| {
        let map = &m;
        let rxl = &rxmx;
        thread::scoped(move || {
            handle_clients(map, rxl);
        })
    }).collect();

    info!("accepting connections");
    for stream in listener.incoming() {
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
            Ok(n) => { nread += n; }
            Err(ref e) if e.kind() == io::ErrorKind::Interrupted => {},
            Err(e) => return Err(From::from(e))
        }
    }
    Ok(())
}

fn execute(m : &cucache::Map, req : &memcache::Request, c : &mut net::TcpStream) {
    let mut rh = memcache::ResponseHeader::from_req(req);
    match memcache::Command::from_u8(req.op) {
        Some(op) => {
            match op {
                memcache::Command::GET
                | memcache::Command::GETQ => {
                    let v = m.get(req.key());
                    rh.status = v.0 as u16;

                    if let (memcache::Status::SUCCESS, Ok(v)) = v {
                        rh.cas = v.val.casid;
                        let extras = &mut [0u8; 4];
                        BigEndian::write_u32(&mut extras[..], v.val.flags);
                        rh.construct(&extras[..], req.key(), &v.val.bytes[..]).transmit(c);
                    } else {
                        rh.construct(&[], &[], &[]).transmit(c);
                    };
                }
                _ => {
                    panic!("client sent valid (but unhandled) command: {:?}", op)
                    // TODO: not yet handled
                }
            }
        }
        None => {
            rh.status = memcache::Status::UNKNOWN_COMMAND as u16;
            rh.construct(&[], &[], &[]).transmit(c);
        }
    };
}

fn handle_client(m : &cucache::Map, mut c : net::TcpStream) {
    let mut magic = [0_u8; 1];
    let mut body = Vec::with_capacity(100);
    loop {
        if let Err(_) = read_full(&mut c, &mut magic) {
            return
        }

        body.truncate(100);
        body.shrink_to_fit();
        body.clear();
        match magic[0] {
            0x80 => {
                // binary protocol
                // memcache request
                body.push(magic[0]);
                if let Err(_) = read_full(&mut c, &mut body[1..24]) {
                    return
                }

                let blen = BigEndian::read_u32(&body[8..12]);
                body.reserve_exact(blen as usize);
                if let Err(_) = read_full(&mut c, &mut body[24..(24+blen as usize)]) {
                    return
                }

                let req = memcache::Request::parse(&mut body[..]);
                execute(m, req, &mut c);
            }
            0x81 => {
                warn!("expected request from client, got response magic");
                return
            }
            _ => {
                // text protocol
            }
        }
    }
}

fn handle_clients(m : &cucache::Map, rxmx : &sync::Mutex<mpsc::Receiver<net::TcpStream>>) {
    loop {
        if let Ok(rx) = rxmx.lock() {
            if let Ok(c) = rx.recv() {
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
        metadata.level() <= LogLevel::Debug
    }

    #[allow(unused_must_use)]
    fn log(&self, record: &LogRecord) {
        if self.enabled(record.metadata()) {
            writeln!(&mut std::io::stderr(), "{} - {}", record.level(), record.args());
        }
    }
}

