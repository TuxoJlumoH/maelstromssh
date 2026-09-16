//! Mapping from the core terminal's styled cells to paint-ready colors and
//! glyph runs. Pure data (no `Painter`) so it is unit-testable; the app layer
//! does the actual drawing.

use egui::Color32;
use vortexssh_core::term::{Attrs, Cell, Color};

/// Terminal default foreground/background. `Color::Default` resolves to these.
#[derive(Clone, Copy)]
pub struct Palette {
    pub fg: Color32,
    pub bg: Color32,
}

impl Default for Palette {
    fn default() -> Self {
        Self {
            fg: Color32::from_gray(220),
            bg: Color32::from_rgb(20, 20, 24),
        }
    }
}

/// A maximal run of cells sharing the same paint style, with their glyphs
/// already concatenated (wide characters are one glyph; continuation cells
/// are skipped but still counted in `cell_len`).
pub struct Run {
    pub start_cell: usize,
    pub cell_len: usize,
    pub text: String,
    pub fg: Color32,
    pub bg: Color32,
    pub underline: bool,
    pub strikethrough: bool,
    pub bold: bool,
}

impl Run {
    fn matches(&self, fg: Color32, bg: Color32, underline: bool, strike: bool, bold: bool) -> bool {
        self.fg == fg
            && self.bg == bg
            && self.underline == underline
            && self.strikethrough == strike
            && self.bold == bold
    }
}

/// Builds the paint runs for one terminal line.
pub fn build_runs(cells: &[Cell], palette: &Palette) -> Vec<Run> {
    let mut runs: Vec<Run> = Vec::new();
    for (i, cell) in cells.iter().enumerate() {
        if cell.continuation {
            continue;
        }
        let (fg, bg) = resolve_colors(&cell.attrs, palette);
        let underline = cell.attrs.underline;
        let strike = cell.attrs.strikethrough;
        let bold = cell.attrs.bold;
        let ch = if cell.attrs.hidden { ' ' } else { cell.ch };
        let width = if cell.wide { 2 } else { 1 };

        match runs.last_mut() {
            Some(run) if run.matches(fg, bg, underline, strike, bold) => {
                run.text.push(ch);
                run.cell_len += width;
            }
            _ => {
                runs.push(Run {
                    start_cell: i,
                    cell_len: width,
                    text: ch.to_string(),
                    fg,
                    bg,
                    underline,
                    strikethrough: strike,
                    bold,
                });
            }
        }
    }
    runs
}

fn resolve_colors(attrs: &Attrs, palette: &Palette) -> (Color32, Color32) {
    let mut fg = map_color(attrs.fg, palette.fg);
    let mut bg = map_color(attrs.bg, palette.bg);
    if attrs.reverse {
        std::mem::swap(&mut fg, &mut bg);
    }
    if attrs.faint {
        fg = fg.gamma_multiply(0.6);
    }
    (fg, bg)
}

pub fn map_color(color: Color, default: Color32) -> Color32 {
    match color {
        Color::Default => default,
        Color::Indexed(n) => {
            let [r, g, b] = indexed_rgb(n);
            Color32::from_rgb(r, g, b)
        }
        Color::Rgb(r, g, b) => Color32::from_rgb(r, g, b),
    }
}

/// The standard xterm 256-color palette: 16 base colors, a 6×6×6 cube, and a
/// 24-step grayscale ramp.
pub fn indexed_rgb(n: u8) -> [u8; 3] {
    match n {
        0..=15 => BASE16[n as usize],
        16..=231 => {
            let i = n - 16;
            let r = i / 36;
            let g = (i / 6) % 6;
            let b = i % 6;
            [cube(r), cube(g), cube(b)]
        }
        _ => {
            let v = 8 + (n - 232) * 10;
            [v, v, v]
        }
    }
}

fn cube(v: u8) -> u8 {
    if v == 0 {
        0
    } else {
        55 + v * 40
    }
}

const BASE16: [[u8; 3]; 16] = [
    [0, 0, 0],
    [205, 49, 49],
    [13, 188, 121],
    [229, 229, 16],
    [36, 114, 200],
    [188, 63, 188],
    [17, 168, 205],
    [229, 229, 229],
    [102, 102, 102],
    [241, 76, 76],
    [35, 209, 139],
    [245, 245, 67],
    [59, 142, 234],
    [214, 112, 214],
    [41, 184, 219],
    [255, 255, 255],
];

#[cfg(test)]
mod tests {
    use super::*;

    fn cell(ch: char) -> Cell {
        Cell {
            ch,
            attrs: Attrs::default(),
            wide: false,
            continuation: false,
        }
    }

    #[test]
    fn default_colors_resolve_to_palette() {
        let (fg, bg) = resolve_colors(&Attrs::default(), &Palette::default());
        assert_eq!(fg, Palette::default().fg);
        assert_eq!(bg, Palette::default().bg);
    }

    #[test]
    fn reverse_swaps_colors() {
        let attrs = Attrs {
            fg: Color::Indexed(1),
            bg: Color::Indexed(2),
            reverse: true,
            ..Attrs::default()
        };
        let (fg, bg) = resolve_colors(&attrs, &Palette::default());
        assert_eq!(fg, map_color(Color::Indexed(2), Palette::default().bg));
        assert_eq!(bg, map_color(Color::Indexed(1), Palette::default().fg));
    }

    #[test]
    fn run_grouping_splits_on_color_change() {
        let mut cells = vec![cell('a'), cell('b'), cell('c')];
        cells[1].attrs.fg = Color::Indexed(1);
        let runs = build_runs(&cells, &Palette::default());
        assert_eq!(runs.len(), 3);
        assert_eq!(runs[0].text, "a");
        assert_eq!(runs[1].text, "b");
        assert_eq!(runs[2].text, "c");
    }

    #[test]
    fn run_grouping_merges_same_style() {
        let cells = vec![cell('x'), cell('y'), cell('z')];
        let runs = build_runs(&cells, &Palette::default());
        assert_eq!(runs.len(), 1);
        assert_eq!(runs[0].text, "xyz");
        assert_eq!(runs[0].cell_len, 3);
    }

    #[test]
    fn wide_char_counts_two_cells() {
        let mut cells = vec![cell('a'), cell('日'), cell('b')];
        cells[1].wide = true;
        cells.insert(2, Cell {
            ch: ' ',
            attrs: Attrs::default(),
            wide: false,
            continuation: true,
        });
        let runs = build_runs(&cells, &Palette::default());
        assert_eq!(runs.len(), 1);
        assert_eq!(runs[0].text, "a日b");
        assert_eq!(runs[0].cell_len, 4);
    }

    #[test]
    fn indexed_palette_extremes() {
        assert_eq!(indexed_rgb(0), [0, 0, 0]);
        assert_eq!(indexed_rgb(15), [255, 255, 255]);
        assert_eq!(indexed_rgb(231), [255, 255, 255]);
        assert_eq!(indexed_rgb(232), [8, 8, 8]);
        assert_eq!(indexed_rgb(255), [238, 238, 238]);
    }
}
