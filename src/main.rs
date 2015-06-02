extern crate cucache;

extern crate log;
use log::{LogRecord, LogLevel, LogLevelFilter, LogMetadata};

use std::io::Write;

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

fn main() {
    let _ = log::set_logger(|max_log_level| {
        max_log_level.set(LogLevelFilter::Debug);
        Box::new(SimpleLogger)
    });

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
