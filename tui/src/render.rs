//! ratatui rendering: maps core terminal cells onto a `Buffer` and draws the
//! session grid plus a one-line status bar.

use maelstromssh_core::term::{Attrs, Color, Terminal};
use ratatui::buffer::Buffer;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Paragraph, Widget};

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

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum OverlayTab {
    Files,
    Forwards,
}

pub struct FileRow {
    pub name: String,
    pub is_dir: bool,
    pub is_symlink: bool,
    pub is_parent: bool,
    pub size: u64,
}

pub struct ForwardRow {
    pub kind_label: &'static str,
    pub listen: String,
    pub dest: String,
}

/// Modal overlay for SFTP file browsing and port forwarding on SSH sessions.
pub struct OverlayView<'a> {
    pub tab: OverlayTab,
    pub sftp_path: &'a str,
    pub files: &'a [FileRow],
    pub file_selected: usize,
    pub forwards: &'a [ForwardRow],
    pub forward_selected: usize,
    pub prompt: Option<(&'a str, &'a str)>,
    pub status: Option<(&'a str, bool)>,
}

impl Widget for OverlayView<'_> {
    fn render(self, area: Rect, buf: &mut Buffer) {
        let modal = centered_rect(86, 82, area);
        Clear.render(modal, buf);

        let block = Block::default()
            .borders(Borders::ALL)
            .title(" SSH Tools — [Tab] switch tab  [Esc/F12] close ");
        let inner = block.inner(modal);
        block.render(modal, buf);
        if inner.height < 4 || inner.width < 20 {
            return;
        }

        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(1),
                Constraint::Length(1),
                Constraint::Min(1),
                Constraint::Length(1),
                Constraint::Length(1),
            ])
            .split(inner);

        let active_tab = Style::default().add_modifier(Modifier::REVERSED | Modifier::BOLD);
        let inactive_tab = Style::default().add_modifier(Modifier::DIM);
        let (files_style, fwds_style) = match self.tab {
            OverlayTab::Files => (active_tab, inactive_tab),
            OverlayTab::Forwards => (inactive_tab, active_tab),
        };
        let header = Line::from(vec![
            Span::raw(" "),
            Span::styled(" SFTP Files ", files_style),
            Span::raw("  "),
            Span::styled(
                format!(" Port Forwards ({}) ", self.forwards.len()),
                fwds_style,
            ),
        ]);
        Paragraph::new(header).render(chunks[0], buf);

        match self.tab {
            OverlayTab::Files => {
                let path_display = if self.sftp_path.is_empty() {
                    "(not loaded)"
                } else {
                    self.sftp_path
                };
                Paragraph::new(Line::from(vec![
                    Span::styled(
                        " Remote path: ",
                        Style::default().add_modifier(Modifier::BOLD),
                    ),
                    Span::raw(path_display),
                ]))
                .render(chunks[1], buf);

                let list_area = chunks[2];
                let vis = list_area.height as usize;
                if self.files.is_empty() {
                    Paragraph::new(" (empty directory)")
                        .style(Style::default().add_modifier(Modifier::DIM))
                        .render(list_area, buf);
                } else if vis > 0 {
                    let sel = self.file_selected.min(self.files.len().saturating_sub(1));
                    let start = sel.saturating_sub(vis.saturating_sub(1));
                    let lines: Vec<Line> = self
                        .files
                        .iter()
                        .enumerate()
                        .skip(start)
                        .take(vis)
                        .map(|(i, row)| {
                            let tag = if row.is_parent {
                                "[UP]  "
                            } else if row.is_dir {
                                "[DIR] "
                            } else if row.is_symlink {
                                "[LNK] "
                            } else {
                                "      "
                            };
                            let suffix = if row.is_dir && !row.is_parent {
                                "/"
                            } else if row.is_symlink {
                                "@"
                            } else {
                                ""
                            };
                            let size_str = if row.is_dir || row.is_parent {
                                String::new()
                            } else {
                                format_size(row.size)
                            };
                            let text = if size_str.is_empty() {
                                format!(" {tag}{}{suffix}", row.name)
                            } else {
                                format!(" {tag}{}{suffix}  ({size_str})", row.name)
                            };
                            let style = if i == sel {
                                Style::default().add_modifier(Modifier::REVERSED)
                            } else if row.is_dir {
                                Style::default().add_modifier(Modifier::BOLD)
                            } else {
                                Style::default()
                            };
                            Line::styled(text, style)
                        })
                        .collect();
                    Paragraph::new(lines).render(list_area, buf);
                }

                Paragraph::new(Line::styled(
                    " Enter: open  Bksp: up  d: download  u: upload  m: mkdir  r: rename  x: del  g: goto  R: refresh",
                    Style::default().add_modifier(Modifier::DIM),
                ))
                .render(chunks[4], buf);
            }
            OverlayTab::Forwards => {
                Paragraph::new(Line::styled(
                    " Active SSH tunnels (-L local, -R remote, -D SOCKS5):",
                    Style::default().add_modifier(Modifier::BOLD),
                ))
                .render(chunks[1], buf);

                let list_area = chunks[2];
                let vis = list_area.height as usize;
                if self.forwards.is_empty() {
                    Paragraph::new(" No active port forwards. Press l, r, or d to start one.")
                        .style(Style::default().add_modifier(Modifier::DIM))
                        .render(list_area, buf);
                } else if vis > 0 {
                    let sel = self
                        .forward_selected
                        .min(self.forwards.len().saturating_sub(1));
                    let start = sel.saturating_sub(vis.saturating_sub(1));
                    let lines: Vec<Line> = self
                        .forwards
                        .iter()
                        .enumerate()
                        .skip(start)
                        .take(vis)
                        .map(|(i, row)| {
                            let text =
                                format!(" [{:<7}] {} -> {}", row.kind_label, row.listen, row.dest);
                            let style = if i == sel {
                                Style::default().add_modifier(Modifier::REVERSED)
                            } else {
                                Style::default()
                            };
                            Line::styled(text, style)
                        })
                        .collect();
                    Paragraph::new(lines).render(list_area, buf);
                }

                Paragraph::new(Line::styled(
                    " l: add local (-L)  r: add remote (-R)  d: add SOCKS5 (-D)  x/Del: stop selected",
                    Style::default().add_modifier(Modifier::DIM),
                ))
                .render(chunks[4], buf);
            }
        }

        if let Some((label, input)) = self.prompt {
            let line = Line::from(vec![
                Span::styled(
                    format!(" {label}"),
                    Style::default().add_modifier(Modifier::BOLD),
                ),
                Span::raw(input),
                Span::styled("█", Style::default().add_modifier(Modifier::SLOW_BLINK)),
            ]);
            Paragraph::new(line).render(chunks[3], buf);
        } else if let Some((msg, is_err)) = self.status {
            let style = if is_err {
                Style::default()
                    .fg(ratatui::style::Color::Red)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(ratatui::style::Color::Green)
            };
            Paragraph::new(Line::styled(format!(" {msg}"), style)).render(chunks[3], buf);
        }
    }
}

fn centered_rect(percent_x: u16, percent_y: u16, area: Rect) -> Rect {
    let w = (area.width.saturating_mul(percent_x) / 100)
        .max(24)
        .min(area.width);
    let h = (area.height.saturating_mul(percent_y) / 100)
        .max(8)
        .min(area.height);
    let x = area.x + (area.width.saturating_sub(w)) / 2;
    let y = area.y + (area.height.saturating_sub(h)) / 2;
    Rect::new(x, y, w, h)
}

pub fn format_size(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = 1024 * KB;
    const GB: u64 = 1024 * MB;
    if bytes >= GB {
        format!("{:.1} GiB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.1} MiB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.1} KiB", bytes as f64 / KB as f64)
    } else {
        format!("{bytes} B")
    }
}
