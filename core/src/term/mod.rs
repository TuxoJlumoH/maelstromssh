//! Terminal emulation: a full character grid with SGR attributes, bounded
//! scrollback, reflow-on-resize, scroll regions, and the alternate screen —
//! driven by a [`vte`] parser and rendered by front-ends (the `ratatui` TUI
//! today). Core stays UI-agnostic: front-ends read cells via
//! [`Terminal::viewport_line`] and push bytes with [`Terminal::feed`].
//!
//! Scope notes:
//! - Tab stops are a fixed 8-column grid (no HTS/TBC tracking).
//! - Combining (zero-width) characters are dropped; precomposed forms render.
//! - DCS sequences, charset designation, and OSC 52 clipboard are ignored.
//! - Height-only resize follows VTE semantics; width changes reflow both the
//!   screen and the scrollback. The alternate screen never reflows.

use vte::{Params, Parser, Perform};

pub mod cell;
mod grid;

pub use cell::{Attrs, Cell, Color};
pub use grid::{Grid, Line};

/// Default scrollback bound, matching `config::default_scrollback`.
pub const DEFAULT_SCROLLBACK: usize = 10_000;

/// What mouse events the remote application asked to receive (DECSET
/// 1000/1002/1003). Front-ends forward mouse input as SGR sequences when
/// this is not [`MouseMode::None`], and use the wheel for scrollback
/// otherwise.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MouseMode {
    None,
    /// Button press/release only (1000).
    Click,
    /// Press/release plus motion while pressed (1002).
    Drag,
    /// All motion (1003).
    Any,
}

#[derive(Clone, Copy, Debug)]
struct SavedCursor {
    row: u32,
    col: u32,
    attrs: Attrs,
}

/// A terminal emulator: grid + scrollback + parser state.
pub struct Terminal {
    parser: Parser,
    grid: Grid,
    alt_grid: Grid,
    alt_active: bool,

    cursor_row: u32,
    cursor_col: u32,
    /// Deferred autowrap: a character was written to the last column and the
    /// next printable character wraps first.
    wrap_pending: bool,
    /// The current SGR pen; cells are stamped with it as they are written.
    attrs: Attrs,
    saved: Option<SavedCursor>,

    /// Scroll region, inclusive 0-based bounds.
    scroll_top: u32,
    scroll_bottom: u32,

    origin_mode: bool,
    application_cursor: bool,
    application_keypad: bool,
    autowrap: bool,
    insert_mode: bool,
    cursor_visible: bool,
    mouse_mode: MouseMode,
    mouse_sgr: bool,
    bracketed_paste: bool,

    title: Option<String>,
    /// Responses owed to the host (DA, DSR/CPR, OSC color queries); drained
    /// by the front-end after each [`Terminal::feed`] and written to the
    /// channel.
    pending: Vec<u8>,
    /// Scrollback lines the view is lifted by; 0 = live (bottom) view.
    viewport: usize,
    /// Bumped on every state change so front-ends can skip redundant redraws.
    generation: u64,
    /// Last printed character, for REP (`CSI b`).
    last_print: Option<(char, u8)>,
}

impl Terminal {
    pub fn new(cols: u32, rows: u32) -> Self {
        Self::with_scrollback(cols, rows, DEFAULT_SCROLLBACK)
    }

    pub fn with_scrollback(cols: u32, rows: u32, max_scrollback: usize) -> Self {
        let cols = cols.max(1);
        let rows = rows.max(1);
        Self {
            parser: Parser::new(),
            grid: Grid::new(cols, rows, max_scrollback),
            alt_grid: Grid::new(cols, rows, 0),
            alt_active: false,
            cursor_row: 0,
            cursor_col: 0,
            wrap_pending: false,
            attrs: Attrs::default(),
            saved: None,
            scroll_top: 0,
            scroll_bottom: rows - 1,
            origin_mode: false,
            application_cursor: false,
            application_keypad: false,
            autowrap: true,
            insert_mode: false,
            cursor_visible: true,
            mouse_mode: MouseMode::None,
            mouse_sgr: false,
            bracketed_paste: false,
            title: None,
            pending: Vec::new(),
            viewport: 0,
            generation: 0,
            last_print: None,
        }
    }

    /// Resizes the terminal, reflowing the primary screen (the alternate
    /// screen is clipped/padded instead, as TUI apps redraw on SIGWINCH).
    /// Any lifted scrollback view snaps back to live.
    pub fn resize(&mut self, cols: u32, rows: u32) {
        let cols = cols.max(1);
        let rows = rows.max(1);
        if cols == self.grid.cols() && rows == self.grid.rows() {
            return;
        }
        // The active grid drives the cursor; it reflows only when it is the
        // primary screen. The inactive grid is resized alongside it — with a
        // reflow if it is the primary held in reserve.
        let mut cursor = (self.cursor_row, self.cursor_col);
        self.grid.resize(cols, rows, &mut cursor, !self.alt_active);
        let mut inactive_cursor = if self.alt_active {
            self.saved.map(|s| (s.row, s.col)).unwrap_or((0, 0))
        } else {
            (0, 0)
        };
        self.alt_grid
            .resize(cols, rows, &mut inactive_cursor, self.alt_active);
        if self.alt_active {
            if let Some(s) = &mut self.saved {
                s.row = inactive_cursor.0;
                s.col = inactive_cursor.1;
            }
        }
        self.cursor_row = cursor.0.min(rows - 1);
        self.cursor_col = cursor.1.min(cols - 1);
        if let Some(saved) = &mut self.saved {
            saved.row = saved.row.min(rows - 1);
            saved.col = saved.col.min(cols - 1);
        }
        self.scroll_top = 0;
        self.scroll_bottom = rows - 1;
        self.wrap_pending = false;
        self.viewport = 0;
        self.generation += 1;
    }

    pub fn cols(&self) -> u32 {
        self.grid.cols()
    }

    pub fn rows(&self) -> u32 {
        self.grid.rows()
    }

    /// (row, col), 0-based, relative to the live screen.
    pub fn cursor_position(&self) -> (u32, u32) {
        (self.cursor_row, self.cursor_col)
    }

    pub fn cursor_visible(&self) -> bool {
        self.cursor_visible
    }

    /// Feed server output through the parser, updating tracked state.
    pub fn feed(&mut self, bytes: &[u8]) {
        // The parser is swapped out so `Perform` can take `&mut self`.
        let mut parser = std::mem::replace(&mut self.parser, Parser::new());
        parser.advance(self, bytes);
        self.parser = parser;
        self.viewport = 0;
        self.generation += 1;
    }

    /// Responses the emulator owes the host (device attributes, cursor
    /// position reports, ...). The front-end sends these to the channel.
    pub fn take_responses(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.pending)
    }

    /// Bumped on every feed/resize/scroll so front-ends can skip redraws.
    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// View row `i` (0-based, top to bottom) under the current scrollback
    /// viewport.
    pub fn viewport_line(&self, i: u32) -> &Line {
        let rows = self.grid.rows() as usize;
        let sb = self.grid.scrollback_len();
        let end = sb + rows - self.viewport.min(sb);
        let abs = end - rows + i as usize;
        if abs < sb {
            self.grid.scrollback_line(abs)
        } else {
            self.grid.line((abs - sb) as u32)
        }
    }

    /// Lines the view is lifted into the scrollback by; 0 = live.
    pub fn viewport_offset(&self) -> usize {
        self.viewport
    }

    pub fn scrollback_len(&self) -> usize {
        self.grid.scrollback_len()
    }

    /// Lift the view into the scrollback (no-op on the alternate screen).
    pub fn scroll_up(&mut self, n: usize) {
        if self.alt_active {
            return;
        }
        let max = self.grid.scrollback_len();
        self.viewport = (self.viewport + n).min(max);
        self.generation += 1;
    }

    /// Lower the view back toward live output.
    pub fn scroll_down(&mut self, n: usize) {
        self.viewport = self.viewport.saturating_sub(n);
        self.generation += 1;
    }

    pub fn scroll_to_bottom(&mut self) {
        self.viewport = 0;
        self.generation += 1;
    }

    /// Window title set via OSC 0/2, if any.
    pub fn title(&self) -> Option<&str> {
        self.title.as_deref()
    }

    /// True when the remote put the cursor in application mode (DECCKM):
    /// arrow/home/end keys must be sent as `ESC O ...` instead of `ESC [ ...`.
    pub fn application_cursor_keys(&self) -> bool {
        self.application_cursor
    }

    /// True when the remote requested the application keypad (ESC =).
    pub fn application_keypad(&self) -> bool {
        self.application_keypad
    }

    /// True when the remote enabled mouse reporting (any of 1000/1002/1003).
    pub fn mouse_reporting(&self) -> bool {
        self.mouse_mode != MouseMode::None
    }

    /// Whether the remote asked for SGR (1006) mouse encoding; only then do
    /// front-ends forward mouse events.
    pub fn mouse_sgr(&self) -> bool {
        self.mouse_sgr && self.mouse_mode != MouseMode::None
    }

    /// Whether the remote enabled bracketed paste (2004).
    pub fn bracketed_paste(&self) -> bool {
        self.bracketed_paste
    }

    // --- internals -------------------------------------------------------

    fn respond(&mut self, bytes: &[u8]) {
        self.pending.extend_from_slice(bytes);
    }

    fn save_cursor(&mut self) {
        self.saved = Some(SavedCursor {
            row: self.cursor_row,
            col: self.cursor_col,
            attrs: self.attrs,
        });
    }

    fn restore_cursor(&mut self) {
        if let Some(s) = self.saved {
            self.cursor_row = s.row.min(self.grid.rows() - 1);
            self.cursor_col = s.col.min(self.grid.cols() - 1);
            self.attrs = s.attrs;
            self.wrap_pending = false;
        } else {
            self.cursor_row = if self.origin_mode { self.scroll_top } else { 0 };
            self.cursor_col = 0;
            self.attrs = Attrs::default();
        }
    }

    /// Line feed / index: scroll the region when at the bottom margin.
    fn newline(&mut self) {
        self.wrap_pending = false;
        if self.cursor_row == self.scroll_bottom {
            self.grid
                .scroll_up_in_region(self.scroll_top, self.scroll_bottom);
        } else if self.cursor_row < self.grid.rows() - 1 {
            self.cursor_row += 1;
        }
    }

    fn reverse_index(&mut self) {
        self.wrap_pending = false;
        if self.cursor_row == self.scroll_top {
            self.grid
                .scroll_down_in_region(self.scroll_top, self.scroll_bottom);
        } else {
            self.cursor_row = self.cursor_row.saturating_sub(1);
        }
    }

    fn move_cursor(&mut self, row: u32, col: u32) {
        let (row, col) = if self.origin_mode {
            (
                (row + self.scroll_top).clamp(self.scroll_top, self.scroll_bottom),
                col,
            )
        } else {
            (row.min(self.grid.rows() - 1), col)
        };
        self.cursor_row = row;
        self.cursor_col = col.min(self.grid.cols() - 1);
        self.wrap_pending = false;
    }

    fn set_alt_screen(&mut self, on: bool, save_restore_cursor: bool) {
        if on == self.alt_active {
            return;
        }
        if on {
            if save_restore_cursor {
                self.save_cursor();
            }
            let (cols, rows) = (self.grid.cols(), self.grid.rows());
            std::mem::swap(&mut self.grid, &mut self.alt_grid);
            // The alternate screen is a fresh blank grid with no scrollback;
            // the primary (now in `alt_grid`) is preserved for the switch back.
            self.grid = Grid::new(cols, rows, 0);
            self.alt_active = true;
            if save_restore_cursor {
                self.cursor_row = 0;
                self.cursor_col = 0;
            }
        } else {
            std::mem::swap(&mut self.grid, &mut self.alt_grid);
            self.alt_active = false;
            if save_restore_cursor {
                self.restore_cursor();
            }
        }
        self.scroll_top = 0;
        self.scroll_bottom = self.grid.rows() - 1;
        self.wrap_pending = false;
        self.viewport = 0;
    }

    fn reset_modes(&mut self) {
        self.origin_mode = false;
        self.application_cursor = false;
        self.application_keypad = false;
        self.autowrap = true;
        self.insert_mode = false;
        self.cursor_visible = true;
        self.mouse_mode = MouseMode::None;
        self.mouse_sgr = false;
        self.bracketed_paste = false;
    }

    fn set_private_mode(&mut self, mode: u32, on: bool) {
        match mode {
            1 => self.application_cursor = on,
            6 => {
                self.origin_mode = on;
                self.move_cursor(0, 0);
            }
            7 => self.autowrap = on,
            9 => {
                self.mouse_mode = if on {
                    MouseMode::Click
                } else {
                    MouseMode::None
                }
            }
            25 => self.cursor_visible = on,
            47 | 1047 => self.set_alt_screen(on, false),
            1049 => self.set_alt_screen(on, true),
            1000 => {
                self.mouse_mode = if on {
                    MouseMode::Click
                } else {
                    MouseMode::None
                }
            }
            1002 => self.mouse_mode = if on { MouseMode::Drag } else { MouseMode::None },
            1003 => self.mouse_mode = if on { MouseMode::Any } else { MouseMode::None },
            // 1006 enables SGR encoding; 1005 (UTF-8) is parsed but only SGR
            // is ever forwarded.
            1005 => {}
            1006 => self.mouse_sgr = on,
            2004 => self.bracketed_paste = on,
            _ => {}
        }
    }

    fn next_tab_stop(&self, col: u32) -> u32 {
        ((col / 8) + 1) * 8
    }

    fn prev_tab_stop(&self, col: u32) -> u32 {
        if col.is_multiple_of(8) {
            col.saturating_sub(8)
        } else {
            col - col % 8
        }
    }

    fn erase_cell(&mut self, row: u32, col: u32) {
        let cell = Cell::new(' ', self.attrs);
        self.grid.set_cell(row, col, cell);
    }

    fn erase_line_part(&mut self, row: u32, from: u32, to: u32) {
        for col in from..=to.min(self.grid.cols() - 1) {
            self.erase_cell(row, col);
        }
    }

    fn clear_line(&mut self, row: u32) {
        let blank = Cell::new(' ', self.attrs);
        let cols = self.grid.cols();
        for col in 0..cols {
            self.grid.set_cell(row, col, blank);
        }
        self.grid.set_wrapped(row, false);
    }

    fn erase_display(&mut self, mode: u32) {
        match mode {
            0 => {
                self.erase_line_part(self.cursor_row, self.cursor_col, self.grid.cols() - 1);
                for row in self.cursor_row + 1..self.grid.rows() {
                    self.clear_line(row);
                }
            }
            1 => {
                for row in 0..self.cursor_row {
                    self.clear_line(row);
                }
                self.erase_line_part(self.cursor_row, 0, self.cursor_col);
            }
            2 => {
                for row in 0..self.grid.rows() {
                    self.clear_line(row);
                }
            }
            3 => self.grid.clear_scrollback(),
            _ => {}
        }
    }

    fn insert_cells(&mut self, n: u32) {
        let cols = self.grid.cols();
        let row = self.cursor_row;
        let start = self.cursor_col;
        if start >= cols || n == 0 {
            return;
        }
        let n = n.min(cols - start);
        for col in (start..cols - n).rev() {
            let c = *self.grid.cell(row, col);
            self.grid.set_cell(row, col + n, c);
        }
        for col in start..start + n {
            self.erase_cell(row, col);
        }
    }

    fn delete_cells(&mut self, n: u32) {
        let cols = self.grid.cols();
        let row = self.cursor_row;
        let start = self.cursor_col;
        if start >= cols || n == 0 {
            return;
        }
        let n = n.min(cols - start);
        for col in start + n..cols {
            let c = *self.grid.cell(row, col);
            self.grid.set_cell(row, col - n, c);
        }
        for col in cols - n..cols {
            self.erase_cell(row, col);
        }
    }

    fn erase_cells(&mut self, n: u32) {
        self.erase_line_part(
            self.cursor_row,
            self.cursor_col,
            self.cursor_col.saturating_add(n).saturating_sub(1),
        );
    }

    fn sgr(&mut self, params: &Params) {
        let groups: Vec<&[u16]> = params.iter().collect();
        if groups.is_empty() {
            self.attrs = Attrs::default();
            return;
        }
        let mut i = 0;
        while i < groups.len() {
            let g = groups[i];
            let v = g.first().copied().unwrap_or(0);
            match v {
                0 => self.attrs = Attrs::default(),
                1 => self.attrs.bold = true,
                2 => self.attrs.faint = true,
                3 => self.attrs.italic = true,
                4 => self.attrs.underline = true,
                5 | 6 => self.attrs.blink = true,
                7 => self.attrs.reverse = true,
                8 => self.attrs.hidden = true,
                9 => self.attrs.strikethrough = true,
                21 => self.attrs.underline = true, // double underline ~ underline
                22 => {
                    self.attrs.bold = false;
                    self.attrs.faint = false;
                }
                23 => self.attrs.italic = false,
                24 => self.attrs.underline = false,
                25 => self.attrs.blink = false,
                27 => self.attrs.reverse = false,
                28 => self.attrs.hidden = false,
                29 => self.attrs.strikethrough = false,
                30..=37 => self.attrs.fg = Color::Indexed((v - 30) as u8),
                38 => {
                    let (color, consumed) = parse_color(&groups[i..]);
                    if let Some(c) = color {
                        self.attrs.fg = c;
                    }
                    i += consumed.saturating_sub(1);
                }
                39 => self.attrs.fg = Color::Default,
                40..=47 => self.attrs.bg = Color::Indexed((v - 40) as u8),
                48 => {
                    let (color, consumed) = parse_color(&groups[i..]);
                    if let Some(c) = color {
                        self.attrs.bg = c;
                    }
                    i += consumed.saturating_sub(1);
                }
                49 => self.attrs.bg = Color::Default,
                90..=97 => self.attrs.fg = Color::Indexed((v - 90 + 8) as u8),
                100..=107 => self.attrs.bg = Color::Indexed((v - 100 + 8) as u8),
                _ => {}
            }
            i += 1;
        }
    }
}

/// Parses an extended color specification starting at the `38`/`48` group.
/// Handles both the `:`-subparameter form (`38:5:n`, `38:2:r:g:b`) and the
/// `;` form (`38;5;n`, `38;2;r;g;b`). Returns the color and how many groups
/// were consumed.
fn parse_color(groups: &[&[u16]]) -> (Option<Color>, usize) {
    let head = groups[0];
    if head.len() >= 2 {
        // Colon form: everything is inside one group.
        return match (head[1], head.len()) {
            (5, len) if len >= 3 => (Some(Color::Indexed(head[2] as u8)), 1),
            (2, len) if len >= 5 => (
                Some(Color::Rgb(
                    head[len - 3] as u8,
                    head[len - 2] as u8,
                    head[len - 1] as u8,
                )),
                1,
            ),
            _ => (None, 1),
        };
    }
    // Semicolon form: mode and components are separate groups.
    let mode = groups.get(1).and_then(|g| g.first()).copied();
    match mode {
        Some(5) => {
            let n = groups.get(2).and_then(|g| g.first()).copied();
            (n.map(|n| Color::Indexed(n as u8)), 3)
        }
        Some(2) => {
            // Next three groups are r, g, b (an optional colorspace group
            // before them is skipped). Consume at most five groups total.
            let comps: Vec<u16> = groups[2..groups.len().min(5)]
                .iter()
                .filter_map(|g| g.first().copied())
                .collect();
            if comps.len() >= 3 {
                (
                    Some(Color::Rgb(
                        comps[comps.len() - 3] as u8,
                        comps[comps.len() - 2] as u8,
                        comps[comps.len() - 1] as u8,
                    )),
                    5,
                )
            } else {
                (None, groups.len().min(5))
            }
        }
        _ => (None, 1),
    }
}

impl Default for Terminal {
    fn default() -> Self {
        Self::new(80, 24)
    }
}

impl Perform for Terminal {
    fn print(&mut self, c: char) {
        let width = unicode_width::UnicodeWidthChar::width(c).unwrap_or(0);
        if width == 0 {
            // Combining marks have no standalone cell representation in this
            // model; drop them (precomposed characters render correctly).
            return;
        }
        let cols = self.grid.cols();
        if self.wrap_pending {
            self.wrap_pending = false;
            if self.autowrap {
                let row = self.cursor_row;
                self.grid.set_wrapped(row, true);
                self.newline();
                self.cursor_col = 0;
            }
        }
        let wide = width >= 2;
        let mut effective_wide = wide;
        if wide && self.cursor_col + 2 > cols {
            if self.autowrap && self.cursor_col > 0 {
                let row = self.cursor_row;
                self.grid.set_wrapped(row, true);
                self.newline();
                self.cursor_col = 0;
            } else if cols < 2 {
                return;
            } else {
                effective_wide = false; // no room; degrade to one cell
            }
        }
        if self.insert_mode {
            let n = if effective_wide { 2 } else { 1 };
            self.insert_cells(n);
        }
        let cell = if effective_wide {
            Cell::wide(c, self.attrs)
        } else {
            Cell::new(c, self.attrs)
        };
        self.grid.set_cell(self.cursor_row, self.cursor_col, cell);
        let advance = if effective_wide { 2 } else { 1 };
        if effective_wide && self.cursor_col + 1 < cols {
            let cont = Cell::continuation(self.attrs);
            self.grid
                .set_cell(self.cursor_row, self.cursor_col + 1, cont);
        }
        // Mark the row as soft-wrapped only when the deferred wrap fires; the
        // flag lives on the line the cursor leaves from.
        let next = self.cursor_col + advance;
        if next >= cols {
            self.cursor_col = cols - 1;
            self.wrap_pending = true;
        } else {
            self.cursor_col = next;
        }
        self.last_print = Some((c, advance as u8));
    }

    fn execute(&mut self, byte: u8) {
        match byte {
            0x08 => {
                self.cursor_col = self.cursor_col.saturating_sub(1);
                self.wrap_pending = false;
            }
            0x09 => {
                self.cursor_col = self
                    .next_tab_stop(self.cursor_col)
                    .min(self.grid.cols().saturating_sub(1));
                self.wrap_pending = false;
            }
            0x0a..=0x0c => self.newline(),
            0x0d => {
                self.cursor_col = 0;
                self.wrap_pending = false;
            }
            _ => {} // BEL and friends: acknowledged, no state
        }
    }

    fn esc_dispatch(&mut self, intermediates: &[u8], _ignore: bool, byte: u8) {
        if !intermediates.is_empty() {
            return; // charset designation, DECALN, ... — not supported
        }
        match byte {
            b'7' => self.save_cursor(),
            b'8' => self.restore_cursor(),
            b'D' => self.newline(),
            b'E' => {
                self.newline();
                self.cursor_col = 0;
            }
            b'M' => self.reverse_index(),
            b'Z' => self.respond(b"\x1b[?62;22c"), // DECID = primary DA
            b'c' => {
                // RIS: full reset, keeping dimensions and scrollback bound.
                let cols = self.grid.cols();
                let rows = self.grid.rows();
                let gen = self.generation;
                *self = Self::with_scrollback(cols, rows, DEFAULT_SCROLLBACK);
                self.generation = gen + 1;
            }
            b'=' => self.application_keypad = true,
            b'>' => self.application_keypad = false,
            _ => {}
        }
    }

    fn osc_dispatch(&mut self, params: &[&[u8]], _bell_terminated: bool) {
        let code: &[u8] = params.first().copied().unwrap_or(b"");
        match code {
            b"0" | b"2" => {
                // Set window title: everything after the code, ';'-joined.
                let title: String = params[1..]
                    .iter()
                    .map(|part| String::from_utf8_lossy(part))
                    .collect::<Vec<_>>()
                    .join(";");
                self.title = Some(title);
                self.generation += 1;
            }
            b"104" => {
                self.title = None;
                self.generation += 1;
            }
            // Foreground/background color queries: answer with the defaults.
            b"10" if params.len() == 1 => self.respond(b"\x1b]10;rgb:ffff/ffff/ffff\x1b\\"),
            b"11" if params.len() == 1 => self.respond(b"\x1b]11;rgb:0000/0000/0000\x1b\\"),
            _ => {}
        }
    }

    fn csi_dispatch(&mut self, params: &Params, intermediates: &[u8], ignore: bool, action: char) {
        if ignore {
            return;
        }
        let private = intermediates.contains(&b'?');
        let nth = |index: usize| -> Option<u32> {
            params
                .iter()
                .nth(index)
                .and_then(|p| p.first())
                .map(|&v| v as u32)
        };
        // Movement/erase counts: missing, empty, or 0 all mean 1.
        let count = |index: usize| -> u32 { nth(index).unwrap_or(1).max(1) };

        if private {
            match action {
                'h' => {
                    for p in params.iter() {
                        self.set_private_mode(p.first().copied().unwrap_or(0) as u32, true);
                    }
                }
                'l' => {
                    for p in params.iter() {
                        self.set_private_mode(p.first().copied().unwrap_or(0) as u32, false);
                    }
                }
                'n' => {
                    // DECXCPR: extended cursor position report.
                    if nth(0) == Some(6) {
                        let row = self.report_row() + 1;
                        let col = self.cursor_col + 1;
                        self.respond(format!("\x1b[?{row};{col}R").as_bytes());
                    }
                }
                'c' => self.respond(b"\x1b[?62;22c"), // primary DA
                _ => {}
            }
            return;
        }

        match action {
            'm' => self.sgr(params),
            'H' | 'f' => {
                let row = nth(0).unwrap_or(1).max(1) - 1;
                let col = nth(1).unwrap_or(1).max(1) - 1;
                self.move_cursor(row, col);
            }
            'A' => {
                let floor = if self.cursor_row >= self.scroll_top
                    && self.cursor_row <= self.scroll_bottom
                {
                    self.scroll_top
                } else {
                    0
                };
                self.cursor_row = self.cursor_row.saturating_sub(count(0)).max(floor);
                self.wrap_pending = false;
            }
            'B' | 'e' => {
                let ceil = if self.cursor_row >= self.scroll_top
                    && self.cursor_row <= self.scroll_bottom
                {
                    self.scroll_bottom
                } else {
                    self.grid.rows() - 1
                };
                self.cursor_row = (self.cursor_row + count(0)).min(ceil);
                self.wrap_pending = false;
            }
            'C' | 'a' => {
                self.cursor_col = (self.cursor_col + count(0)).min(self.grid.cols() - 1);
                self.wrap_pending = false;
            }
            'D' => {
                self.cursor_col = self.cursor_col.saturating_sub(count(0));
                self.wrap_pending = false;
            }
            'E' => {
                let row = (self.cursor_row + count(0)).min(self.grid.rows() - 1);
                self.move_cursor_raw(row, 0);
            }
            'F' => {
                let row = self.cursor_row.saturating_sub(count(0));
                self.move_cursor_raw(row, 0);
            }
            'G' | '`' => {
                let col = nth(0).unwrap_or(1).max(1) - 1;
                self.cursor_col = col.min(self.grid.cols() - 1);
                self.wrap_pending = false;
            }
            'd' => {
                let row = nth(0).unwrap_or(1).max(1) - 1;
                self.cursor_row = row.min(self.grid.rows() - 1);
                self.wrap_pending = false;
            }
            'I' => {
                let mut col = self.cursor_col;
                for _ in 0..count(0) {
                    col = self.next_tab_stop(col).min(self.grid.cols() - 1);
                }
                self.cursor_col = col;
                self.wrap_pending = false;
            }
            'Z' => {
                let mut col = self.cursor_col;
                for _ in 0..count(0) {
                    col = self.prev_tab_stop(col);
                }
                self.cursor_col = col;
                self.wrap_pending = false;
            }
            'J' => self.erase_display(nth(0).unwrap_or(0)),
            'K' => {
                let cols = self.grid.cols();
                match nth(0).unwrap_or(0) {
                    0 => self.erase_line_part(self.cursor_row, self.cursor_col, cols - 1),
                    1 => self.erase_line_part(self.cursor_row, 0, self.cursor_col),
                    2 => self.clear_line(self.cursor_row),
                    _ => {}
                }
            }
            '@' => self.insert_cells(count(0)),
            'P' => self.delete_cells(count(0)),
            'X' => self.erase_cells(count(0)),
            'L' => {
                if self.cursor_row <= self.scroll_bottom {
                    for _ in 0..count(0) {
                        self.grid.scroll_down_in_region(
                            self.cursor_row.max(self.scroll_top),
                            self.scroll_bottom,
                        );
                    }
                }
            }
            'M' => {
                if self.cursor_row <= self.scroll_bottom {
                    for _ in 0..count(0) {
                        self.grid.scroll_up_in_region(
                            self.cursor_row.max(self.scroll_top),
                            self.scroll_bottom,
                        );
                    }
                }
            }
            'S' => {
                for _ in 0..count(0) {
                    self.grid
                        .scroll_up_in_region(self.scroll_top, self.scroll_bottom);
                }
            }
            'T' => {
                for _ in 0..count(0) {
                    self.grid
                        .scroll_down_in_region(self.scroll_top, self.scroll_bottom);
                }
            }
            'b' => {
                // REP: repeat the last printed character.
                if let Some((c, _)) = self.last_print {
                    let n = count(0).min(self.grid.cols() * self.grid.rows());
                    for _ in 0..n {
                        self.print(c);
                    }
                }
            }
            'r' => {
                // DECSTBM: set top/bottom margins (1-based, inclusive). An
                // explicit 0 means the default edge; a missing/zero-only list
                // resets the region to the full screen; an invalid range
                // (top >= bottom) is ignored.
                let rows = self.grid.rows();
                let top = nth(0).filter(|&v| v > 0).unwrap_or(1).max(1) - 1;
                let bottom = nth(1).filter(|&v| v > 0).unwrap_or(rows).clamp(1, rows) - 1;
                let has_margin = params.iter().any(|p| p.first().copied().unwrap_or(0) > 0);
                if top < bottom {
                    self.scroll_top = top;
                    self.scroll_bottom = bottom;
                    self.move_cursor(0, 0);
                } else if !has_margin {
                    self.scroll_top = 0;
                    self.scroll_bottom = rows - 1;
                    self.move_cursor(0, 0);
                }
            }
            's' => self.save_cursor(),
            'u' => self.restore_cursor(),
            'h' => {
                // ANSI modes: only insert mode (IRM) is tracked.
                for p in params.iter() {
                    if p.first().copied() == Some(4) {
                        self.insert_mode = true;
                    }
                }
            }
            'l' => {
                for p in params.iter() {
                    if p.first().copied() == Some(4) {
                        self.insert_mode = false;
                    }
                }
            }
            'c' => {
                if nth(0).unwrap_or(0) == 0 {
                    self.respond(b"\x1b[?62;22c");
                }
            }
            'n' => match nth(0) {
                Some(5) => self.respond(b"\x1b[0n"),
                Some(6) => {
                    let row = self.report_row() + 1;
                    let col = self.cursor_col + 1;
                    self.respond(format!("\x1b[{row};{col}R").as_bytes());
                }
                _ => {}
            },
            'p' if intermediates.contains(&b'!') => {
                // DECSTR: soft reset — modes and pen, not content.
                self.reset_modes();
                self.attrs = Attrs::default();
                self.scroll_top = 0;
                self.scroll_bottom = self.grid.rows() - 1;
                self.wrap_pending = false;
            }
            _ => {} // DECSCUSR, window manipulation, DECRQSS, ...: ignored
        }
    }
}

impl Terminal {
    /// Cursor row as reported by CPR: relative to the top margin when origin
    /// mode is active, absolute otherwise.
    fn report_row(&self) -> u32 {
        if self.origin_mode && self.cursor_row >= self.scroll_top {
            self.cursor_row - self.scroll_top
        } else {
            self.cursor_row
        }
    }

    /// Absolute (non-origin) cursor placement used by CNL/CPL.
    fn move_cursor_raw(&mut self, row: u32, col: u32) {
        self.cursor_row = row.min(self.grid.rows() - 1);
        self.cursor_col = col.min(self.grid.cols() - 1);
        self.wrap_pending = false;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn term() -> Terminal {
        Terminal::new(80, 24)
    }

    /// The visible text of live screen row `i`.
    fn row_text(t: &Terminal, i: u32) -> String {
        t.viewport_line(i).text()
    }

    #[test]
    fn plain_text_advances_column() {
        let mut t = term();
        t.feed(b"abc");
        assert_eq!(t.cursor_position(), (0, 3));
        assert_eq!(row_text(&t, 0), "abc");
    }

    #[test]
    fn newline_and_carriage_return() {
        let mut t = term();
        t.feed(b"abc\r\n");
        assert_eq!(t.cursor_position(), (1, 0));
    }

    #[test]
    fn cursor_positioning_csi() {
        let mut t = term();
        t.feed(b"\x1b[5;10H");
        assert_eq!(t.cursor_position(), (4, 9));
    }

    #[test]
    fn cursor_movement_csi() {
        let mut t = term();
        t.feed(b"\x1b[5;5H");
        t.feed(b"\x1b[2A");
        t.feed(b"\x1b[3C");
        assert_eq!(t.cursor_position(), (2, 7));
    }

    #[test]
    fn resize_clamps_cursor_into_bounds() {
        let mut t = term();
        t.feed(b"\x1b[20;70H");
        t.resize(10, 5);
        // Reflow keeps the cursor's line at the bottom of the (empty) screen
        // and clamps the column to the new width.
        assert_eq!(t.cursor_position(), (4, 9));
    }

    #[test]
    fn deferred_wrap_at_right_edge() {
        let mut t = Terminal::new(3, 5);
        t.feed(b"abc");
        // Deferred wrap: the cursor rests on the last column until the next
        // printable character arrives.
        assert_eq!(t.cursor_position(), (0, 2));
        t.feed(b"d");
        assert_eq!(t.cursor_position(), (1, 1));
        assert_eq!(row_text(&t, 0), "abc");
        assert!(t.viewport_line(0).wrapped());
        assert_eq!(row_text(&t, 1), "d");
    }

    #[test]
    fn autowrap_off_overwrites_last_column() {
        let mut t = Terminal::new(3, 5);
        t.feed(b"\x1b[?7l");
        t.feed(b"abcde");
        assert_eq!(t.cursor_position(), (0, 2));
        assert_eq!(row_text(&t, 0), "abe");
    }

    #[test]
    fn scroll_at_bottom_feeds_scrollback() {
        let mut t = Terminal::new(10, 3);
        t.feed(b"l1\r\nl2\r\nl3\r\nl4");
        assert_eq!(t.scrollback_len(), 1);
        assert_eq!(t.grid.scrollback_line(0).text(), "l1");
        assert_eq!(row_text(&t, 0), "l2");
        assert_eq!(row_text(&t, 2), "l4");
    }

    #[test]
    fn viewport_scrollback_view() {
        let mut t = Terminal::new(10, 3);
        t.feed(b"l1\r\nl2\r\nl3\r\nl4");
        t.scroll_up(1);
        assert_eq!(t.viewport_offset(), 1);
        assert_eq!(row_text(&t, 0), "l1");
        assert_eq!(row_text(&t, 2), "l3");
        // New output snaps the view back to live.
        t.feed(b"x");
        assert_eq!(t.viewport_offset(), 0);
    }

    #[test]
    fn scrollback_bound_is_respected() {
        let mut t = Terminal::with_scrollback(10, 2, 3);
        for i in 0..10 {
            t.feed(format!("l{i}\r\n").as_bytes());
        }
        assert_eq!(t.scrollback_len(), 3);
    }

    #[test]
    fn erase_display_and_line() {
        let mut t = Terminal::new(10, 3);
        t.feed(b"aaaa\r\nbbbb\r\ncccc");
        t.feed(b"\x1b[2;3H\x1b[K"); // row 2 (1-based), from col 3 right
        assert_eq!(row_text(&t, 1), "bb");
        t.feed(b"\x1b[2J");
        assert_eq!(row_text(&t, 0), "");
        assert_eq!(row_text(&t, 2), "");
    }

    #[test]
    fn insert_and_delete_cells() {
        let mut t = Terminal::new(10, 2);
        t.feed(b"abcd");
        t.feed(b"\x1b[1;2H\x1b[2@"); // ICH 2 at col 2
        assert_eq!(row_text(&t, 0), "a  bcd");
        t.feed(b"\x1b[1;2H\x1b[2P"); // DCH 2 restores
        assert_eq!(row_text(&t, 0), "abcd");
    }

    #[test]
    fn scroll_region_contains_scrolling() {
        let mut t = Terminal::new(10, 5);
        t.feed(b"l1\r\nl2\r\nl3\r\nl4\r\nl5");
        t.feed(b"\x1b[r"); // home + full region
        t.feed(b"\x1b[2;4r"); // region rows 2-4 (1-based)
        t.feed(b"\x1b[4;1H"); // region bottom
        t.feed(b"\nx"); // line feed inside the region scrolls only it
        assert_eq!(row_text(&t, 0), "l1");
        assert_eq!(row_text(&t, 1), "l3");
        assert_eq!(row_text(&t, 3), "x");
        assert_eq!(row_text(&t, 4), "l5");
        assert_eq!(t.scrollback_len(), 0);
    }

    #[test]
    fn reverse_index_scrolls_region_down() {
        let mut t = Terminal::new(10, 3);
        t.feed(b"a\r\nb\r\nc");
        t.feed(b"\x1b[1;1H\x1bM"); // RI at top margin
        assert_eq!(row_text(&t, 0), "");
        assert_eq!(row_text(&t, 1), "a");
        assert_eq!(row_text(&t, 2), "b"); // "c" pushed off the bottom
    }

    #[test]
    fn sgr_colors_and_attributes() {
        let mut t = term();
        t.feed(b"\x1b[1;31mA\x1b[38;5;200mB\x1b[48;2;10;20;30mC\x1b[0mD");
        assert!(t.grid.cell(0, 0).attrs.bold);
        assert_eq!(t.grid.cell(0, 0).attrs.fg, Color::Indexed(1));
        assert_eq!(t.grid.cell(0, 1).attrs.fg, Color::Indexed(200));
        assert_eq!(t.grid.cell(0, 2).attrs.bg, Color::Rgb(10, 20, 30));
        assert_eq!(t.grid.cell(0, 3).attrs, Attrs::default());
    }

    #[test]
    fn sgr_bright_and_colon_forms() {
        let mut t = term();
        t.feed(b"\x1b[92mG\x1b[38:5:99mH");
        assert_eq!(t.grid.cell(0, 0).attrs.fg, Color::Indexed(10));
        assert_eq!(t.grid.cell(0, 1).attrs.fg, Color::Indexed(99));
    }

    #[test]
    fn save_restore_cursor() {
        let mut t = term();
        t.feed(b"\x1b[3;4H\x1b7\x1b[10;10H\x1b8");
        assert_eq!(t.cursor_position(), (2, 3));
        // CSI s/u alias
        t.feed(b"\x1b[5;6H\x1b[s\x1b[1;1H\x1b[u");
        assert_eq!(t.cursor_position(), (4, 5));
    }

    #[test]
    fn alternate_screen_is_isolated_and_restored() {
        let mut t = Terminal::new(10, 3);
        t.feed(b"main\r\ncontent");
        t.feed(b"\x1b[?1049h");
        assert_eq!(row_text(&t, 0), "");
        t.feed(b"alt");
        t.scroll_up(1); // no-op on the alternate screen
        assert_eq!(t.viewport_offset(), 0);
        t.feed(b"\x1b[?1049l");
        assert_eq!(row_text(&t, 0), "main");
        assert_eq!(row_text(&t, 1), "content");
        assert_eq!(t.cursor_position(), (1, 7)); // restored by ?1049
    }

    #[test]
    fn reflow_on_narrowing_keeps_content() {
        let mut t = Terminal::new(8, 4);
        t.feed(b"abcdefgh"); // wraps into "abcd" + "efgh"
        t.resize(4, 4);
        assert_eq!(row_text(&t, 0), "abcd");
        assert_eq!(row_text(&t, 1), "efgh");
    }

    #[test]
    fn reflow_on_widening_joins_wrapped_lines() {
        let mut t = Terminal::new(4, 4);
        t.feed(b"abcdefgh");
        t.resize(8, 4);
        assert_eq!(row_text(&t, 0), "abcdefgh");
        assert_eq!(row_text(&t, 1), "");
    }

    #[test]
    fn reflow_maps_scrollback_too() {
        let mut t = Terminal::new(4, 2);
        t.feed(b"aabb\r\nccdd\r\neeff"); // scrolls "aabb" into scrollback
        assert_eq!(t.scrollback_len(), 1);
        t.resize(8, 2);
        // "aabb" + "ccdd" were separate logical lines (hard newlines), so
        // widening just re-lays them out.
        t.scroll_up(1);
        assert_eq!(row_text(&t, 0), "aabb");
        t.scroll_down(1);
        assert_eq!(row_text(&t, 1), "eeff");
    }

    #[test]
    fn wide_characters_occupy_two_cells() {
        let mut t = Terminal::new(6, 2);
        t.feed("日本x".as_bytes());
        assert!(t.grid.cell(0, 0).wide);
        assert!(t.grid.cell(0, 1).continuation);
        assert_eq!(t.grid.cell(0, 2).ch, '本');
        assert_eq!(t.grid.cell(0, 4).ch, 'x');
        assert_eq!(row_text(&t, 0), "日本x");
    }

    #[test]
    fn device_attributes_and_cursor_reports() {
        let mut t = term();
        t.feed(b"\x1b[5;7H\x1b[6n\x1b[c");
        let resp = String::from_utf8(t.take_responses()).unwrap();
        assert!(resp.contains("\x1b[5;7R"), "CPR: {resp:?}");
        assert!(resp.contains("\x1b[?62;22c"), "DA: {resp:?}");
        assert!(t.take_responses().is_empty());
    }

    #[test]
    fn osc_sets_title() {
        let mut t = term();
        t.feed(b"\x1b]0;deploy \xe2\x80\x94 prod\x07");
        assert_eq!(t.title(), Some("deploy \u{2014} prod"));
        t.feed(b"\x1b]2;second\x1b\\");
        assert_eq!(t.title(), Some("second"));
    }

    #[test]
    fn application_cursor_mode_is_exposed() {
        let mut t = term();
        assert!(!t.application_cursor_keys());
        t.feed(b"\x1b[?1h");
        assert!(t.application_cursor_keys());
        t.feed(b"\x1b[?1l");
        assert!(!t.application_cursor_keys());
    }

    #[test]
    fn mouse_and_paste_modes_are_exposed() {
        let mut t = term();
        t.feed(b"\x1b[?1000h\x1b[?1006h");
        assert!(t.mouse_reporting());
        assert!(t.mouse_sgr());
        t.feed(b"\x1b[?1000l");
        assert!(!t.mouse_sgr());
        t.feed(b"\x1b[?2004h");
        assert!(t.bracketed_paste());
    }

    #[test]
    fn cursor_visibility_toggle() {
        let mut t = term();
        t.feed(b"\x1b[?25l");
        assert!(!t.cursor_visible());
        t.feed(b"\x1b[?25h");
        assert!(t.cursor_visible());
    }

    #[test]
    fn erase_in_line_variants() {
        let mut t = Terminal::new(10, 2);
        t.feed(b"0123456789");
        t.feed(b"\x1b[1;4H"); // cursor col 3
        t.feed(b"\x1b[1K"); // erase to left, inclusive
        assert_eq!(row_text(&t, 0), "    456789");
        t.feed(b"\x1b[0K"); // erase to right
        assert_eq!(row_text(&t, 0), "");
    }

    #[test]
    fn insert_and_delete_lines_in_region() {
        let mut t = Terminal::new(10, 4);
        t.feed(b"l1\r\nl2\r\nl3\r\nl4");
        t.feed(b"\x1b[2;1H\x1b[L"); // IL at row 2
        assert_eq!(row_text(&t, 1), "");
        assert_eq!(row_text(&t, 2), "l2");
        t.feed(b"\x1b[2;1H\x1b[M"); // DL at row 2 restores
        assert_eq!(row_text(&t, 1), "l2");
        assert_eq!(row_text(&t, 3), "");
    }

    #[test]
    fn rep_repeats_last_character() {
        let mut t = Terminal::new(10, 2);
        t.feed(b"ab\x1b[3b");
        assert_eq!(row_text(&t, 0), "abbbb");
    }

    #[test]
    fn generation_bumps_on_feed_and_scroll() {
        let mut t = term();
        let g0 = t.generation();
        t.feed(b"x");
        assert_ne!(t.generation(), g0);
        let g1 = t.generation();
        t.scroll_up(1);
        assert_ne!(t.generation(), g1);
    }

    #[test]
    fn full_reset_esc_c() {
        let mut t = Terminal::new(10, 3);
        t.feed(b"text\x1b[?1049h\x1b[1;31m");
        t.feed(b"\x1bc");
        assert_eq!(t.cursor_position(), (0, 0));
        assert_eq!(row_text(&t, 0), "");
        assert!(!t.application_cursor_keys());
    }
}
