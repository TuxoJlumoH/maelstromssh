//! ratatui rendering: maps core terminal cells onto a `Buffer` and draws the
//! session grid plus a one-line status bar.

use ratatui::buffer::Buffer;
use ratatui::layout::Rect;
use ratatui::style::{Modifier, Style};
use ratatui::widgets::Widget;
use vortexssh_core::term::{Attrs, Color, Terminal};

/// Draws the terminal grid over `area`, translating core [`Attrs`] into
/// ratatui [`Style`]. `show_cursor` positions the block cursor on the live
/// screen cell.
pub struct GridView<'a> {
    pub term: &'a Terminal,
    pub show_cursor: bool,
}

impl Widget for GridView<'_> {
    fn render(self, area: Rect, buf: &mut Buffer) {
        let rows = (self.term.rows() as usize).min(area.height as usize);
        let cols = (self.term.cols() as usize).min(area.width as usize);
        let live = self.term.viewport_offset() == 0;
        let (c_row, c_col) = self.term.cursor_position();
        for row in 0..rows {
            let line = self.term.viewport_line(row as u32);
            for col in 0..cols {
                let cell = &line.cells()[col];
                if cell.continuation {
                    continue;
                }
                let mut style = style_for(&cell.attrs);
                if self.show_cursor && live && row as u32 == c_row && col as u32 == c_col {
                    style = style.add_modifier(Modifier::REVERSED);
                }
                let mut sym = [0u8; 4];
                let s = cell.ch.encode_utf8(&mut sym);
                let target = buf
                    .cell_mut((area.x + col as u16, area.y + row as u16))
                    .expect("cell in bounds");
                target.set_symbol(s).set_style(style);
            }
        }
    }
}

/// The single status line under the grid.
pub struct StatusBar {
    pub left: String,
    pub right: String,
    pub active: bool,
}

impl Widget for StatusBar {
    fn render(self, area: Rect, buf: &mut Buffer) {
        let base = if self.active {
            Style::default().add_modifier(Modifier::REVERSED)
        } else {
            Style::default().add_modifier(Modifier::DIM)
        };
        let left_width = self.left.chars().count();
        let right_width = self.right.chars().count();
        let pad = " ".repeat(area.width.saturating_sub((left_width + right_width) as u16) as usize);
        let spans = vec![
            ratatui::text::Span::styled(self.left, base),
            ratatui::text::Span::styled(pad, base),
            ratatui::text::Span::styled(self.right, base),
        ];
        let line = ratatui::text::Line::from(spans);
        ratatui::widgets::Paragraph::new(line).render(area, buf);
    }
}

fn style_for(attrs: &Attrs) -> Style {
    let mut style = Style::default()
        .fg(map_color(attrs.fg))
        .bg(map_color(attrs.bg));
    if attrs.bold {
        style = style.add_modifier(Modifier::BOLD);
    }
    if attrs.faint {
        style = style.add_modifier(Modifier::DIM);
    }
    if attrs.italic {
        style = style.add_modifier(Modifier::ITALIC);
    }
    if attrs.underline {
        style = style.add_modifier(Modifier::UNDERLINED);
    }
    if attrs.blink {
        style = style.add_modifier(Modifier::SLOW_BLINK);
    }
    if attrs.reverse {
        style = style.add_modifier(Modifier::REVERSED);
    }
    if attrs.hidden {
        style = style.add_modifier(Modifier::HIDDEN);
    }
    if attrs.strikethrough {
        style = style.add_modifier(Modifier::CROSSED_OUT);
    }
    style
}

fn map_color(color: Color) -> ratatui::style::Color {
    match color {
        Color::Default => ratatui::style::Color::Reset,
        Color::Indexed(n) => ratatui::style::Color::Indexed(n),
        Color::Rgb(r, g, b) => ratatui::style::Color::Rgb(r, g, b),
    }
}
