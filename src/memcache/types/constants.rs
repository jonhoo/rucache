pub const REQ_MAGIC : u8 = 0x80;
pub const RES_MAGIC : u8 = 0x81;

enum_from_primitive! {
#[allow(non_camel_case_types)]
#[derive(Debug, PartialEq, Eq, Copy, Clone)]
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
}

enum_from_primitive! {
#[allow(non_camel_case_types)]
#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub enum Command {
	GET        = 0x00,
	SET        = 0x01,
	ADD        = 0x02,
	REPLACE    = 0x03,
	DELETE     = 0x04,
	INCREMENT  = 0x05,
	DECREMENT  = 0x06,
	QUIT       = 0x07,
	FLUSH      = 0x08,
	GETQ       = 0x09,
	NOOP       = 0x0a,
	VERSION    = 0x0b,
	GETK       = 0x0c,
	GETKQ      = 0x0d,
	APPEND     = 0x0e,
	PREPEND    = 0x0f,
	STAT       = 0x10,
	SETQ       = 0x11,
	ADDQ       = 0x12,
	REPLACEQ   = 0x13,
	DELETEQ    = 0x14,
	INCREMENTQ = 0x15,
	DECREMENTQ = 0x16,
	QUITQ      = 0x17,
	FLUSHQ     = 0x18,
	APPENDQ    = 0x19,
	PREPENDQ   = 0x1a,
	RGET       = 0x30,
	RSET       = 0x31,
	RSETQ      = 0x32,
	RAPPEND    = 0x33,
	RAPPENDQ   = 0x34,
	RPREPEND   = 0x35,
	RPREPENDQ  = 0x36,
	RDELETE    = 0x37,
	RDELETEQ   = 0x38,
	RINCR      = 0x39,
	RINCRQ     = 0x3a,
	RDECR      = 0x3b,
	RDECRQ     = 0x3c,

	SASL_LIST_MECHS = 0x20,
	SASL_AUTH       = 0x21,
	SASL_STEP       = 0x22,

	TAP_CONNECT          = 0x40, // Client-sent request to initiate Tap feed
	TAP_MUTATION         = 0x41, // Notification of a SET/ADD/REPLACE/etc. on the server
	TAP_DELETE           = 0x42, // Notification of a DELETE on the server
	TAP_FLUSH            = 0x43, // Replicates a flush_all command
	TAP_OPAQUE           = 0x44, // Opaque control data from the engine
	TAP_VBUCKET_SET      = 0x45, // Sets state of vbucket in receiver (used in takeover)
	TAP_CHECKPOINT_START = 0x46, // Notifies start of new checkpoint
	TAP_CHECKPOINT_END   = 0x47, // Notifies end of checkpoint

	OBSERVE = 0x92,
}
}

impl Command {
    pub fn quiet(&self) -> bool {
        self.noq() != *self
    }

    pub fn noq(&self) -> Command {
        match *self {
            Command::GETQ => {Command::GET}
            Command::GETK => {Command::GETK}
            Command::SET => {Command::SET}
            Command::ADD => {Command::ADD}
            Command::REPLACE => {Command::REPLACE}
            Command::DELETE => {Command::DELETE}
            Command::INCREMENT => {Command::INCREMENT}
            Command::DECREMENT => {Command::DECREMENT}
            Command::QUIT => {Command::QUIT}
            Command::FLUSH => {Command::FLUSH}
            Command::APPEND => {Command::APPEND}
            Command::PREPEND => {Command::PREPEND}
            Command::RSET => {Command::RSET}
            Command::RAPPEND => {Command::RAPPEND}
            Command::RPREPEND => {Command::RPREPEND}
            Command::RDELETE => {Command::RDELETE}
            Command::RINCR => {Command::RINCR}
            Command::RDECR => {Command::RDECR}
            v => {v}
        }
    }
}
