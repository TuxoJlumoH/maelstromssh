//! The Telnet protocol (RFC 854) as a filter between the terminal and the
//! TCP connection: it strips commands out of what the server sends,
//! answers option negotiation, and escapes what the user types.
//!
//! Supported options: ECHO and SUPPRESS-GO-AHEAD (the server echoes and
//! works a character at a time, as every Telnet client asks for), BINARY,
//! NAWS (window size) and TERMINAL-TYPE. Everything else is refused.

/// Interpret As Command.
const IAC: u8 = 255;
const DONT: u8 = 254;
const DO: u8 = 253;
const WONT: u8 = 252;
const WILL: u8 = 251;
const SB: u8 = 250;
const BRK: u8 = 243;
const SE: u8 = 240;

const BINARY: u8 = 0;
const ECHO: u8 = 1;
const SGA: u8 = 3;
const TTYPE: u8 = 24;
const NAWS: u8 = 31;

/// TERMINAL-TYPE subnegotiation verbs.
const TTYPE_IS: u8 = 0;
const TTYPE_SEND: u8 = 1;

/// Longest subnegotiation kept; longer ones are cut (they are only parsed
/// for the options above, which are short).
const SB_MAX: usize = 256;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Opt {
    No,
    /// We asked and wait for the answer.
    Asked,
    Yes,
}

#[derive(Debug)]
enum State {
    Data,
    /// After a CR from the server: a following NUL is dropped.
    Cr,
    Iac,
    /// After IAC WILL/WONT/DO/DONT.
    Verb(u8),
    Sb,
    SbIac,
}

/// One connection's Telnet state.
#[derive(Debug)]
pub struct Telnet {
    state: State,
    /// Options the server does (it sent WILL, we DO).
    remote: [Opt; 256],
    /// Options we do (it sent DO, we WILL).
    local: [Opt; 256],
    sb: Vec<u8>,
    term_type: String,
    size: (u16, u16),
}

impl Telnet {
    pub fn new(term_type: &str, cols: u16, rows: u16) -> Self {
        Self {
            state: State::Data,
            remote: [Opt::No; 256],
            local: [Opt::No; 256],
            sb: Vec::new(),
            term_type: term_type.to_ascii_uppercase(),
            size: (cols, rows),
        }
    }

    /// What to send right after connecting: offer the window size and
    /// terminal type, and ask the server to echo and drop go-aheads.
    pub fn start(&mut self) -> Vec<u8> {
        let mut out = Vec::new();
        for opt in [NAWS, TTYPE] {
            self.local[opt as usize] = Opt::Asked;
            out.extend([IAC, WILL, opt]);
        }
        for opt in [ECHO, SGA] {
            self.remote[opt as usize] = Opt::Asked;
            out.extend([IAC, DO, opt]);
        }
        out
    }

    /// Splits what the server sent into terminal output (`data`) and
    /// answers to send back (`reply`).
    pub fn receive(&mut self, input: &[u8], data: &mut Vec<u8>, reply: &mut Vec<u8>) {
        for &b in input {
            self.state = match std::mem::replace(&mut self.state, State::Data) {
                State::Data | State::Cr if b == IAC => State::Iac,
                State::Cr if b == 0 => State::Data,
                State::Data | State::Cr => {
                    data.push(b);
                    if b == b'\r' && !self.binary_in() {
                        State::Cr
                    } else {
                        State::Data
                    }
                }
                State::Iac => match b {
                    IAC => {
                        data.push(IAC);
                        State::Data
                    }
                    WILL | WONT | DO | DONT => State::Verb(b),
                    SB => {
                        self.sb.clear();
                        State::Sb
                    }
                    // NOP, GA, DM, etc.: nothing to do.
                    _ => State::Data,
                },
                State::Verb(verb) => {
                    self.negotiate(verb, b, reply);
                    State::Data
                }
                State::Sb => {
                    if b == IAC {
                        State::SbIac
                    } else {
                        if self.sb.len() < SB_MAX {
                            self.sb.push(b);
                        }
                        State::Sb
                    }
                }
                State::SbIac => match b {
                    SE => {
                        self.subnegotiation(reply);
                        State::Data
                    }
                    IAC => {
                        if self.sb.len() < SB_MAX {
                            self.sb.push(IAC);
                        }
                        State::Sb
                    }
                    // Not allowed here; treat it as the end.
                    _ => {
                        self.subnegotiation(reply);
                        State::Data
                    }
                },
            };
        }
    }

    /// Escapes typed bytes for the wire: IAC is doubled, and outside
    /// binary mode a CR not followed by LF becomes CR NUL.
    pub fn encode(&self, input: &[u8], out: &mut Vec<u8>) {
        let binary = self.local[BINARY as usize] == Opt::Yes;
        for (i, &b) in input.iter().enumerate() {
            out.push(b);
            if b == IAC {
                out.push(IAC);
            } else if b == b'\r' && !binary && input.get(i + 1) != Some(&b'\n') {
                out.push(0);
            }
        }
    }

    /// Records the new size; returns the NAWS message if the server wants
    /// window sizes.
    pub fn resize(&mut self, cols: u16, rows: u16) -> Option<Vec<u8>> {
        self.size = (cols, rows);
        (self.local[NAWS as usize] == Opt::Yes).then(|| self.naws())
    }

    /// IAC BREAK, the Telnet break signal.
    pub fn brk() -> [u8; 2] {
        [IAC, BRK]
    }

    /// Whether the server echoes what is typed.
    pub fn server_echoes(&self) -> bool {
        self.remote[ECHO as usize] == Opt::Yes
    }

    fn binary_in(&self) -> bool {
        self.remote[BINARY as usize] == Opt::Yes
    }

    fn naws(&self) -> Vec<u8> {
        let mut out = vec![IAC, SB, NAWS];
        for v in [self.size.0, self.size.1] {
            for b in v.to_be_bytes() {
                out.push(b);
                if b == IAC {
                    out.push(IAC);
                }
            }
        }
        out.extend([IAC, SE]);
        out
    }

    /// RFC 1143's "Q method" without queues: answer only when the state
    /// changes, so two sides can never loop.
    fn negotiate(&mut self, verb: u8, opt: u8, reply: &mut Vec<u8>) {
        let i = opt as usize;
        match verb {
            WILL => {
                let ok = matches!(opt, ECHO | SGA | BINARY);
                match (self.remote[i], ok) {
                    (Opt::Yes, _) => {}
                    (Opt::Asked, true) => self.remote[i] = Opt::Yes,
                    (Opt::No, true) => {
                        self.remote[i] = Opt::Yes;
                        reply.extend([IAC, DO, opt]);
                    }
                    (Opt::Asked, false) => self.remote[i] = Opt::No,
                    (Opt::No, false) => reply.extend([IAC, DONT, opt]),
                }
            }
            WONT => match self.remote[i] {
                Opt::Yes => {
                    self.remote[i] = Opt::No;
                    reply.extend([IAC, DONT, opt]);
                }
                Opt::Asked => self.remote[i] = Opt::No,
                Opt::No => {}
            },
            DO => {
                let ok = matches!(opt, NAWS | TTYPE | SGA | BINARY);
                match (self.local[i], ok) {
                    (Opt::Yes, _) => {}
                    (Opt::Asked, true) => self.local[i] = Opt::Yes,
                    (Opt::No, true) => {
                        self.local[i] = Opt::Yes;
                        reply.extend([IAC, WILL, opt]);
                    }
                    (Opt::Asked, false) => self.local[i] = Opt::No,
                    (Opt::No, false) => reply.extend([IAC, WONT, opt]),
                }
                if opt == NAWS && self.local[i] == Opt::Yes {
                    reply.extend(self.naws());
                }
            }
            DONT => match self.local[i] {
                Opt::Yes => {
                    self.local[i] = Opt::No;
                    reply.extend([IAC, WONT, opt]);
                }
                Opt::Asked => self.local[i] = Opt::No,
                Opt::No => {}
            },
            _ => {}
        }
    }

    fn subnegotiation(&mut self, reply: &mut Vec<u8>) {
        if self.sb.as_slice() == [TTYPE, TTYPE_SEND] && self.local[TTYPE as usize] == Opt::Yes {
            reply.extend([IAC, SB, TTYPE, TTYPE_IS]);
            reply.extend(self.term_type.bytes().filter(|&b| b != IAC));
            reply.extend([IAC, SE]);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn feed(t: &mut Telnet, input: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let (mut data, mut reply) = (Vec::new(), Vec::new());
        t.receive(input, &mut data, &mut reply);
        (data, reply)
    }

    #[test]
    fn start_offers_naws_ttype_and_asks_for_echo() {
        let mut t = Telnet::new("xterm-256color", 80, 24);
        assert_eq!(
            t.start(),
            [IAC, WILL, NAWS, IAC, WILL, TTYPE, IAC, DO, ECHO, IAC, DO, SGA]
        );
    }

    #[test]
    fn answers_to_our_requests_are_not_answered_again() {
        let mut t = Telnet::new("xterm", 80, 24);
        t.start();
        let (data, reply) = feed(&mut t, &[IAC, WILL, ECHO, IAC, WILL, SGA, IAC, DO, TTYPE]);
        assert!(data.is_empty());
        assert!(reply.is_empty(), "{reply:?}");
        assert!(t.server_echoes());
        // Repeats change nothing.
        let (_, reply) = feed(&mut t, &[IAC, WILL, ECHO]);
        assert!(reply.is_empty());
    }

    #[test]
    fn naws_is_sent_when_accepted_and_on_resize() {
        let mut t = Telnet::new("xterm", 80, 24);
        assert_eq!(t.resize(100, 30), None);
        t.start();
        let (_, reply) = feed(&mut t, &[IAC, DO, NAWS]);
        assert_eq!(reply, [IAC, SB, NAWS, 0, 100, 0, 30, IAC, SE]);
        // A 255 in the size is escaped.
        assert_eq!(
            t.resize(255, 50),
            Some(vec![IAC, SB, NAWS, 0, 255, 255, 0, 50, IAC, SE])
        );
    }

    #[test]
    fn unsupported_options_are_refused_once() {
        let mut t = Telnet::new("xterm", 80, 24);
        let (_, reply) = feed(&mut t, &[IAC, DO, 39, IAC, WILL, 5]);
        assert_eq!(reply, [IAC, WONT, 39, IAC, DONT, 5]);
        // Refusals of things we never had are not answered.
        let (_, reply) = feed(&mut t, &[IAC, DONT, 39, IAC, WONT, 5]);
        assert!(reply.is_empty());
    }

    #[test]
    fn options_can_be_turned_off() {
        let mut t = Telnet::new("xterm", 80, 24);
        feed(&mut t, &[IAC, WILL, ECHO]);
        assert!(t.server_echoes());
        let (_, reply) = feed(&mut t, &[IAC, WONT, ECHO]);
        assert_eq!(reply, [IAC, DONT, ECHO]);
        assert!(!t.server_echoes());
    }

    #[test]
    fn terminal_type_is_sent_on_request() {
        let mut t = Telnet::new("xterm-256color", 80, 24);
        t.start();
        feed(&mut t, &[IAC, DO, TTYPE]);
        let (_, reply) = feed(&mut t, &[IAC, SB, TTYPE, TTYPE_SEND, IAC, SE]);
        let mut want = vec![IAC, SB, TTYPE, TTYPE_IS];
        want.extend(b"XTERM-256COLOR");
        want.extend([IAC, SE]);
        assert_eq!(reply, want);
    }

    #[test]
    fn data_is_unescaped_across_reads() {
        let mut t = Telnet::new("xterm", 80, 24);
        let (mut data, mut reply) = (Vec::new(), Vec::new());
        // A command and a doubled IAC split between reads.
        for chunk in [
            &b"lo"[..],
            &[b'g', IAC],
            &[IAC, b'i', IAC],
            &[WILL],
            &[ECHO, b'n'],
        ] {
            t.receive(chunk, &mut data, &mut reply);
        }
        assert_eq!(data, [b'l', b'o', b'g', IAC, b'i', b'n']);
        assert_eq!(reply, [IAC, DO, ECHO]);
    }

    #[test]
    fn cr_nul_from_the_server_becomes_cr() {
        let mut t = Telnet::new("xterm", 80, 24);
        let (data, _) = feed(&mut t, b"a\r\0b\r\nc");
        assert_eq!(data, b"a\rb\r\nc");
    }

    #[test]
    fn typed_bytes_are_escaped() {
        let t = Telnet::new("xterm", 80, 24);
        let mut out = Vec::new();
        t.encode(&[b'l', b's', b'\r', IAC, b'\r', b'\n'], &mut out);
        assert_eq!(out, [b'l', b's', b'\r', 0, IAC, IAC, b'\r', b'\n']);
    }

    #[test]
    fn long_and_unterminated_subnegotiations_are_safe() {
        let mut t = Telnet::new("xterm", 80, 24);
        let mut input = vec![IAC, SB, 99];
        input.extend(std::iter::repeat_n(7u8, 10_000));
        input.extend([IAC, SE, b'x']);
        let (data, reply) = feed(&mut t, &input);
        assert_eq!(data, b"x");
        assert!(reply.is_empty());
        assert!(t.sb.len() <= SB_MAX);
    }
}
