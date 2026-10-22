//! Translates egui key events into the byte sequences a terminal application
//! expects. Printable text (including IME input) is delivered via
//! `egui::Event::Text` by the app; this module handles everything else —
//! control/alt combinations and the non-printable keys — xterm-style
//! (DECCKM-aware arrows, CSI `1;mod` modifier sequences, `ESC`-prefixed Alt).

use egui::{Key, Modifiers};

/// The result of translating a key press.
pub enum KeyOut {
    /// Bytes to write to the shell's stdin.
    Bytes(Vec<u8>),
    /// The key is handled elsewhere (e.g. printable text via `Event::Text`).
    Ignore,
    /// A local quit shortcut (Ctrl+Shift+Q).
    Quit,
}

/// Maps a key event to its output. Printable keys with no Ctrl/Alt are
/// `Ignore`d here — their characters arrive as `Event::Text`.
pub fn encode(key: Key, mods: Modifiers, app_cursor: bool) -> KeyOut {
    let ctrl = mods.ctrl;
    let alt = mods.alt;
    let shift = mods.shift;

    if ctrl && shift && key == Key::Q {
        return KeyOut::Quit;
    }

    // Ctrl+letter/symbol -> control byte.
    if ctrl {
        if let Some(c) = key_char(key) {
            return KeyOut::Bytes(vec![ctrl_byte(c)]);
        }
    }

    let seq: Vec<u8> = match key {
        Key::Enter => vec![b'\r'],
        Key::Backspace => {
            if ctrl {
                vec![0x08]
            } else {
                vec![0x7f]
            }
        }
        Key::Tab => {
            if shift {
                b"\x1b[Z".to_vec()
            } else {
                vec![b'\t']
            }
        }
        Key::Escape => vec![0x1b],
        Key::ArrowUp => arrow(b'A', app_cursor, mod_code(mods)),
        Key::ArrowDown => arrow(b'B', app_cursor, mod_code(mods)),
        Key::ArrowRight => arrow(b'C', app_cursor, mod_code(mods)),
        Key::ArrowLeft => arrow(b'D', app_cursor, mod_code(mods)),
        Key::Home => home_end(b'H', app_cursor, mod_code(mods)),
        Key::End => home_end(b'F', app_cursor, mod_code(mods)),
        Key::Insert => tilde(2, mod_code(mods)),
        Key::Delete => tilde(3, mod_code(mods)),
        Key::PageUp => tilde(5, mod_code(mods)),
        Key::PageDown => tilde(6, mod_code(mods)),
        Key::F1 => b"\x1bOP".to_vec(),
        Key::F2 => b"\x1bOQ".to_vec(),
        Key::F3 => b"\x1bOR".to_vec(),
        Key::F4 => b"\x1bOS".to_vec(),
        Key::F5 => tilde(15, mod_code(mods)),
        Key::F6 => tilde(17, mod_code(mods)),
        Key::F7 => tilde(18, mod_code(mods)),
        Key::F8 => tilde(19, mod_code(mods)),
        Key::F9 => tilde(20, mod_code(mods)),
        Key::F10 => tilde(21, mod_code(mods)),
        Key::F11 => tilde(23, mod_code(mods)),
        Key::F12 => tilde(24, mod_code(mods)),
        _ => {
            // Alt+<printable> -> ESC + character (uppercased with Shift).
            if alt {
                if let Some(c) = key_char(key) {
                    let c = if shift { c.to_ascii_uppercase() } else { c };
                    let mut out = vec![0x1b];
                    out.extend_from_slice(&c.to_string().into_bytes());
                    return KeyOut::Bytes(out);
                }
            }
            return KeyOut::Ignore;
        }
    };

    if alt && !seq.is_empty() {
        let mut out = vec![0x1b];
        out.extend_from_slice(&seq);
        KeyOut::Bytes(out)
    } else {
        KeyOut::Bytes(seq)
    }
}

fn key_char(key: Key) -> Option<char> {
    Some(match key {
        Key::A => 'a',
        Key::B => 'b',
        Key::C => 'c',
        Key::D => 'd',
        Key::E => 'e',
        Key::F => 'f',
        Key::G => 'g',
        Key::H => 'h',
        Key::I => 'i',
        Key::J => 'j',
        Key::K => 'k',
        Key::L => 'l',
        Key::M => 'm',
        Key::N => 'n',
        Key::O => 'o',
        Key::P => 'p',
        Key::Q => 'q',
        Key::R => 'r',
        Key::S => 's',
        Key::T => 't',
        Key::U => 'u',
        Key::V => 'v',
        Key::W => 'w',
        Key::X => 'x',
        Key::Y => 'y',
        Key::Z => 'z',
        Key::Num0 => '0',
        Key::Num1 => '1',
        Key::Num2 => '2',
        Key::Num3 => '3',
        Key::Num4 => '4',
        Key::Num5 => '5',
        Key::Num6 => '6',
        Key::Num7 => '7',
        Key::Num8 => '8',
        Key::Num9 => '9',
        Key::Space => ' ',
        Key::OpenBracket => '[',
        Key::CloseBracket => ']',
        Key::Backslash => '\\',
        Key::Slash => '/',
        Key::Minus => '-',
        Key::Equals => '=',
        Key::Backtick => '`',
        Key::Period => '.',
        Key::Comma => ',',
        Key::Semicolon => ';',
        Key::Quote => '\'',
        Key::Colon => ':',
        Key::Questionmark => '?',
        Key::Pipe => '|',
        Key::Plus => '+',
        Key::OpenCurlyBracket => '{',
        Key::CloseCurlyBracket => '}',
        Key::Exclamationmark => '!',
        _ => return None,
    })
}

/// The control-byte form of a character, matching the low five bits for the
/// standard set and special-casing NUL-producing keys.
fn ctrl_byte(c: char) -> u8 {
    match c {
        '2' | ' ' | '@' => 0x00,
        _ => (c as u8) & 0x1f,
    }
}

fn mod_code(mods: Modifiers) -> u8 {
    let mut code = 0u8;
    if mods.shift {
        code += 1;
    }
    if mods.alt {
        code += 2;
    }
    if mods.ctrl {
        code += 4;
    }
    code
}

fn arrow(letter: u8, app_cursor: bool, mod_code: u8) -> Vec<u8> {
    if app_cursor && mod_code == 0 {
        vec![0x1b, b'O', letter]
    } else if mod_code != 0 {
        format!("\x1b[1;{}{}", mod_code + 1, letter as char).into_bytes()
    } else {
        vec![0x1b, b'[', letter]
    }
}

fn home_end(letter: u8, app_cursor: bool, mod_code: u8) -> Vec<u8> {
    if app_cursor && mod_code == 0 {
        vec![0x1b, b'O', letter]
    } else if mod_code != 0 {
        format!("\x1b[1;{}{}", mod_code + 1, letter as char).into_bytes()
    } else {
        vec![0x1b, b'[', letter]
    }
}

fn tilde(n: u8, mod_code: u8) -> Vec<u8> {
    if mod_code != 0 {
        format!("\x1b[{n};{}~", mod_code + 1).into_bytes()
    } else {
        format!("\x1b[{n}~").into_bytes()
    }
}

/// Encodes a mouse event as an xterm SGR (1006) sequence; coordinates are
/// 1-based on the wire.
pub fn sgr_mouse(
    column: u16,
    row: u16,
    button: u8,
    release: bool,
    motion: bool,
    mods: Modifiers,
) -> Vec<u8> {
    let mut code = button;
    if mods.shift {
        code += 4;
    }
    if mods.alt {
        code += 8;
    }
    if mods.ctrl {
        code += 16;
    }
    if motion {
        code += 32;
    }
    let suffix = if release { b'm' } else { b'M' };
    format!("\x1b[<{code};{};{}{}", column + 1, row + 1, suffix as char).into_bytes()
}

impl KeyOut {
    #[cfg(test)]
    fn bytes(&self) -> &[u8] {
        match self {
            KeyOut::Bytes(b) => b,
            _ => panic!("not bytes"),
        }
    }

    #[cfg(test)]
    fn is_ignore(&self) -> bool {
        matches!(self, KeyOut::Ignore)
    }

    #[cfg(test)]
    fn is_quit(&self) -> bool {
        matches!(self, KeyOut::Quit)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn m(ctrl: bool, alt: bool, shift: bool) -> Modifiers {
        Modifiers {
            alt,
            ctrl,
            shift,
            mac_cmd: false,
            command: false,
        }
    }

    #[test]
    fn ctrl_letters_become_control_bytes() {
        assert_eq!(
            encode(Key::C, m(true, false, false), false).bytes(),
            &[0x03]
        );
        assert_eq!(
            encode(Key::D, m(true, false, false), false).bytes(),
            &[0x04]
        );
    }

    #[test]
    fn alt_prefixes_escape() {
        assert_eq!(
            encode(Key::X, m(false, true, false), false).bytes(),
            b"\x1bx"
        );
    }

    #[test]
    fn special_keys() {
        assert_eq!(
            encode(Key::Enter, m(false, false, false), false).bytes(),
            b"\r"
        );
        assert_eq!(
            encode(Key::Backspace, m(false, false, false), false).bytes(),
            &[0x7f]
        );
        assert_eq!(
            encode(Key::Tab, m(false, false, false), false).bytes(),
            b"\t"
        );
    }

    #[test]
    fn arrows_respect_cursor_mode_and_modifiers() {
        assert_eq!(
            encode(Key::ArrowUp, m(false, false, false), false).bytes(),
            b"\x1b[A"
        );
        assert_eq!(
            encode(Key::ArrowUp, m(false, false, false), true).bytes(),
            b"\x1bOA"
        );
        assert_eq!(
            encode(Key::ArrowUp, m(true, false, false), false).bytes(),
            b"\x1b[1;5A"
        );
    }

    #[test]
    fn printable_ignored_for_text_events() {
        assert!(encode(Key::A, m(false, false, false), false).is_ignore());
        assert!(encode(Key::A, m(false, false, true), false).is_ignore());
    }

    #[test]
    fn quit_shortcut() {
        assert!(encode(Key::Q, m(true, false, true), false).is_quit());
    }
}
