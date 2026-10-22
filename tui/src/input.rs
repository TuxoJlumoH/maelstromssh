//! Translates crossterm key events into the byte sequences a terminal
//! application expects (the reverse direction of the core emulator). The
//! encoding is xterm-style: DECCKM-aware arrows/home/end, CSI `1;mod`
//! modifier sequences, and `ESC`-prefixed `Alt` combinations.

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

/// A viewport scroll gesture bound to a key, intercepted before anything is
/// forwarded to the remote host.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScrollAction {
    Up(usize),
    Down(usize),
    Top,
    Bottom,
}

/// Maps a key event to a scrollback gesture, if the key is one of the
/// Shift-modified paging keys reserved for the local viewport.
pub fn scroll_action(ev: &KeyEvent) -> Option<ScrollAction> {
    let shift = ev.modifiers.contains(KeyModifiers::SHIFT);
    if !shift {
        return None;
    }
    match ev.code {
        KeyCode::PageUp => Some(ScrollAction::Up(1)),
        KeyCode::PageDown => Some(ScrollAction::Down(1)),
        KeyCode::Up => Some(ScrollAction::Up(1)),
        KeyCode::Down => Some(ScrollAction::Down(1)),
        KeyCode::Home => Some(ScrollAction::Top),
        KeyCode::End => Some(ScrollAction::Bottom),
        _ => None,
    }
}

/// Encodes a key press into the bytes to write to the SSH channel. `None`
/// means the key is not forwarded (it was handled locally).
pub fn encode_key(ev: &KeyEvent, app_cursor: bool, app_keypad: bool) -> Option<Vec<u8>> {
    let ctrl = ev.modifiers.contains(KeyModifiers::CONTROL);
    let alt = ev.modifiers.contains(KeyModifiers::ALT);
    let shift = ev.modifiers.contains(KeyModifiers::SHIFT);
    let mod_code = modifier_code(ev.modifiers);

    let mut seq: Vec<u8> = match ev.code {
        KeyCode::Char(c) => {
            if ctrl {
                match c.to_ascii_lowercase() {
                    'a'..='z' => vec![c.to_ascii_lowercase() as u8 - b'a' + 1],
                    '@' => vec![0x00],
                    '[' => vec![0x1b],
                    '\\' => vec![0x1c],
                    ']' => vec![0x1d],
                    '^' => vec![0x1e],
                    '_' => vec![0x1f],
                    '2' => vec![0x00], // Ctrl+2 (NUL) — matches most terminals
                    _ => c.to_string().into_bytes(),
                }
            } else {
                c.to_string().into_bytes()
            }
        }
        KeyCode::Enter => vec![b'\r'],
        KeyCode::Backspace => {
            if ctrl {
                vec![0x08]
            } else {
                vec![0x7f]
            }
        }
        KeyCode::Tab => {
            if shift {
                vec![0x1b, b'Z']
            } else {
                vec![b'\t']
            }
        }
        KeyCode::BackTab => vec![0x1b, b'Z'],
        KeyCode::Esc => vec![0x1b],
        KeyCode::Up => arrow(b'A', app_cursor, mod_code),
        KeyCode::Down => arrow(b'B', app_cursor, mod_code),
        KeyCode::Right => arrow(b'C', app_cursor, mod_code),
        KeyCode::Left => arrow(b'D', app_cursor, mod_code),
        KeyCode::Home => home_end(b'H', app_cursor, mod_code),
        KeyCode::End => home_end(b'F', app_cursor, mod_code),
        KeyCode::Insert => tilde(2, mod_code),
        KeyCode::Delete => tilde(3, mod_code),
        KeyCode::PageUp => tilde(5, mod_code),
        KeyCode::PageDown => tilde(6, mod_code),
        KeyCode::F(n) => fkey(n, mod_code),
        KeyCode::Null => return None,
        KeyCode::CapsLock | KeyCode::ScrollLock | KeyCode::NumLock => return None,
        KeyCode::PrintScreen | KeyCode::Pause | KeyCode::Menu => return None,
        KeyCode::KeypadBegin => return None,
        KeyCode::Media(_) | KeyCode::Modifier(_) => return None,
    };

    if alt {
        // Alt+key is sent as ESC followed by the un-modified sequence; when
        // Shift is also held the character is uppercased.
        if shift && seq.len() == 1 && seq[0].is_ascii_lowercase() {
            seq[0] = seq[0].to_ascii_uppercase();
        }
        let mut out = vec![0x1b];
        out.extend_from_slice(&seq);
        return Some(out);
    }

    let _ = app_keypad; // keypad isn't distinguishable in crossterm yet
    Some(seq)
}

fn modifier_code(mods: KeyModifiers) -> u8 {
    let mut code = 0u8;
    if mods.contains(KeyModifiers::SHIFT) {
        code += 1;
    }
    if mods.contains(KeyModifiers::ALT) {
        code += 2;
    }
    if mods.contains(KeyModifiers::CONTROL) {
        code += 4;
    }
    code
}

/// Arrow keys: `ESC [ A` normally, `ESC O A` in application cursor mode,
/// `ESC [ 1;{mod}A` when a modifier is held.
fn arrow(letter: u8, app_cursor: bool, mod_code: u8) -> Vec<u8> {
    if app_cursor && mod_code == 0 {
        vec![0x1b, b'O', letter]
    } else if mod_code != 0 {
        format!("\x1b[1;{}{}", mod_code + 1, letter as char).into_bytes()
    } else {
        vec![0x1b, b'[', letter]
    }
}

/// Home/End: `ESC [ H` / `ESC [ F` (or `ESC O H/F` in application mode),
/// with the `1;mod` form when modified.
fn home_end(letter: u8, app_cursor: bool, mod_code: u8) -> Vec<u8> {
    if app_cursor && mod_code == 0 {
        vec![0x1b, b'O', letter]
    } else if mod_code != 0 {
        format!("\x1b[1;{}{}", mod_code + 1, letter as char).into_bytes()
    } else {
        vec![0x1b, b'[', letter]
    }
}

/// `ESC [ {n}~` (Insert/Delete/PageUp/PageDown) with optional modifier.
fn tilde(n: u8, mod_code: u8) -> Vec<u8> {
    if mod_code != 0 {
        format!("\x1b[{n};{}~", mod_code + 1).into_bytes()
    } else {
        format!("\x1b[{n}~").into_bytes()
    }
}

/// Function keys F1..F12.
fn fkey(n: u8, mod_code: u8) -> Vec<u8> {
    let code = match n {
        1 => 11,
        2 => 12,
        3 => 13,
        4 => 14,
        5 => 15,
        6 => 17,
        7 => 18,
        8 => 19,
        9 => 20,
        10 => 21,
        11 => 23,
        12 => 24,
        _ => return vec![],
    };
    let basic = match n {
        1 => b"\x1bOP".to_vec(),
        2 => b"\x1bOQ".to_vec(),
        3 => b"\x1bOR".to_vec(),
        4 => b"\x1bOS".to_vec(),
        _ => format!("\x1b[{code}~").into_bytes(),
    };
    if mod_code != 0 && n >= 5 {
        format!("\x1b[{code};{}~", mod_code + 1).into_bytes()
    } else {
        basic
    }
}

/// Encodes a mouse event as an xterm SGR (1006) sequence. Coordinates are
/// 1-based on the wire.
pub fn encode_sgr_mouse(
    column: u16,
    row: u16,
    button: u8,
    release: bool,
    motion: bool,
    mods: KeyModifiers,
) -> Vec<u8> {
    let mut code = button;
    if mods.contains(KeyModifiers::SHIFT) {
        code += 4;
    }
    if mods.contains(KeyModifiers::ALT) {
        code += 8;
    }
    if mods.contains(KeyModifiers::CONTROL) {
        code += 16;
    }
    if motion {
        code += 32;
    }
    let suffix = if release { b'm' } else { b'M' };
    format!("\x1b[<{code};{};{}{}", column + 1, row + 1, suffix as char).into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(code: KeyCode, mods: KeyModifiers) -> KeyEvent {
        KeyEvent {
            code,
            modifiers: mods,
            kind: crossterm::event::KeyEventKind::Press,
            state: crossterm::event::KeyEventState::empty(),
        }
    }

    #[test]
    fn plain_chars_and_control() {
        assert_eq!(
            encode_key(&key(KeyCode::Char('a'), KeyModifiers::NONE), false, false),
            Some(b"a".to_vec())
        );
        assert_eq!(
            encode_key(
                &key(KeyCode::Char('c'), KeyModifiers::CONTROL),
                false,
                false
            ),
            Some(vec![0x03])
        );
        assert_eq!(
            encode_key(&key(KeyCode::Enter, KeyModifiers::NONE), false, false),
            Some(b"\r".to_vec())
        );
        assert_eq!(
            encode_key(&key(KeyCode::Backspace, KeyModifiers::NONE), false, false),
            Some(vec![0x7f])
        );
    }

    #[test]
    fn alt_prefixes_escape() {
        assert_eq!(
            encode_key(&key(KeyCode::Char('x'), KeyModifiers::ALT), false, false),
            Some(b"\x1bx".to_vec())
        );
    }

    #[test]
    fn arrow_cursor_modes() {
        assert_eq!(
            encode_key(&key(KeyCode::Up, KeyModifiers::NONE), false, false),
            Some(b"\x1b[A".to_vec())
        );
        assert_eq!(
            encode_key(&key(KeyCode::Up, KeyModifiers::NONE), true, false),
            Some(b"\x1bOA".to_vec())
        );
        assert_eq!(
            encode_key(&key(KeyCode::Up, KeyModifiers::CONTROL), false, false),
            Some(b"\x1b[1;5A".to_vec())
        );
    }

    #[test]
    fn function_keys() {
        assert_eq!(
            encode_key(&key(KeyCode::F(1), KeyModifiers::NONE), false, false),
            Some(b"\x1bOP".to_vec())
        );
        assert_eq!(
            encode_key(&key(KeyCode::F(5), KeyModifiers::NONE), false, false),
            Some(b"\x1b[15~".to_vec())
        );
    }
}
