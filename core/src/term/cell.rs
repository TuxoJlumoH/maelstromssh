//! A single terminal cell: one character plus the SGR attributes it was
//! written with. Front-ends map [`Attrs`] onto their own styling model
//! (ratatui `Style`, GUI text attributes, ...) — core stays UI-agnostic.

/// A terminal color, either the theme default, a 256-palette index, or 24-bit
/// RGB (the SGR `38;5;n` / `38;2;r;g;b` forms).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum Color {
    #[default]
    Default,
    Indexed(u8),
    Rgb(u8, u8, u8),
}

/// SGR attributes carried by each cell. Only the states a front-end can
/// render are tracked; exotic modes (protected area, etc.) are parsed and
/// ignored.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct Attrs {
    pub fg: Color,
    pub bg: Color,
    pub bold: bool,
    pub faint: bool,
    pub italic: bool,
    pub underline: bool,
    pub blink: bool,
    pub reverse: bool,
    pub hidden: bool,
    pub strikethrough: bool,
}

/// One position in the grid.
///
/// Double-width characters occupy two cells: the first holds the character
/// with [`Cell::wide`] set, the second is a [`Cell::continuation`]
/// placeholder that front-ends must skip when rendering.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cell {
    pub ch: char,
    pub attrs: Attrs,
    pub wide: bool,
    pub continuation: bool,
}

impl Default for Cell {
    fn default() -> Self {
        Self {
            ch: ' ',
            attrs: Attrs::default(),
            wide: false,
            continuation: false,
        }
    }
}

impl Cell {
    pub fn new(ch: char, attrs: Attrs) -> Self {
        Self {
            ch,
            attrs,
            wide: false,
            continuation: false,
        }
    }

    pub fn wide(ch: char, attrs: Attrs) -> Self {
        Self {
            ch,
            attrs,
            wide: true,
            continuation: false,
        }
    }

    pub fn continuation(attrs: Attrs) -> Self {
        Self {
            ch: ' ',
            attrs,
            wide: false,
            continuation: true,
        }
    }

    /// True if the cell holds no visible content (blank, default attributes).
    pub fn is_blank(&self) -> bool {
        self.ch == ' ' && !self.continuation && self.attrs == Attrs::default()
    }
}
