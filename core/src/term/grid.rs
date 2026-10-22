//! The character grid: a fixed-size screen plus a bounded scrollback
//! history, and the resize logic (reflow-on-width-change, VTE-style
//! height adjustment) that keeps the cursor attached to its content.

use std::collections::VecDeque;

use super::cell::Cell;

/// One physical row of cells, always exactly `cols` wide.
///
/// `wrapped` records that the row was soft-wrapped: its content continues on
/// the next row. Reflow uses the flag to rebuild logical lines.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Line {
    cells: Vec<Cell>,
    wrapped: bool,
}

impl Line {
    pub fn blank(cols: usize) -> Self {
        Self {
            cells: vec![Cell::default(); cols],
            wrapped: false,
        }
    }

    fn from_cells(cells: Vec<Cell>, wrapped: bool) -> Self {
        Self { cells, wrapped }
    }

    pub fn cells(&self) -> &[Cell] {
        &self.cells
    }

    pub fn wrapped(&self) -> bool {
        self.wrapped
    }

    /// True if the row holds nothing but blank cells.
    pub fn is_blank(&self) -> bool {
        self.cells.iter().all(Cell::is_blank)
    }

    /// The visible text of the row, with trailing blanks trimmed.
    pub fn text(&self) -> String {
        let s: String = self
            .cells
            .iter()
            .filter(|c| !c.continuation)
            .map(|c| c.ch)
            .collect();
        s.trim_end().to_string()
    }
}

/// Screen rows plus bounded scrollback. The screen always holds exactly
/// `rows` lines; scrolled-off lines move into `scrollback` (oldest dropped
/// once the bound is reached).
#[derive(Debug)]
pub struct Grid {
    cols: u32,
    rows: u32,
    screen: Vec<Line>,
    scrollback: VecDeque<Line>,
    max_scrollback: usize,
}

impl Grid {
    pub fn new(cols: u32, rows: u32, max_scrollback: usize) -> Self {
        let cols = cols.max(1);
        let rows = rows.max(1);
        Self {
            cols,
            rows,
            screen: vec![Line::blank(cols as usize); rows as usize],
            scrollback: VecDeque::new(),
            max_scrollback,
        }
    }

    pub fn cols(&self) -> u32 {
        self.cols
    }

    pub fn rows(&self) -> u32 {
        self.rows
    }

    /// Screen row `i` (0-based, excludes scrollback).
    pub fn line(&self, i: u32) -> &Line {
        &self.screen[i as usize]
    }

    pub fn line_mut(&mut self, i: u32) -> &mut Line {
        &mut self.screen[i as usize]
    }

    pub fn cell(&self, row: u32, col: u32) -> &Cell {
        &self.screen[row as usize].cells[col as usize]
    }

    pub fn set_cell(&mut self, row: u32, col: u32, cell: Cell) {
        self.screen[row as usize].cells[col as usize] = cell;
    }

    /// Clears a cell without disturbing the row's wrap flag.
    pub fn clear_cell(&mut self, row: u32, col: u32) {
        self.screen[row as usize].cells[col as usize] = Cell::default();
    }

    pub fn set_wrapped(&mut self, row: u32, wrapped: bool) {
        self.screen[row as usize].wrapped = wrapped;
    }

    pub fn scrollback_len(&self) -> usize {
        self.scrollback.len()
    }

    /// Scrollback row `i`, 0 = oldest retained line.
    pub fn scrollback_line(&self, i: usize) -> &Line {
        &self.scrollback[i]
    }

    /// Scrolls the screen up by one line within `[top, bottom]` (inclusive,
    /// 0-based). When the region covers the full screen, the line scrolled
    /// off the top joins the scrollback.
    pub fn scroll_up_in_region(&mut self, top: u32, bottom: u32) {
        if top > bottom || bottom >= self.rows {
            return;
        }
        let line = self.screen.remove(top as usize);
        if top == 0 && bottom == self.rows - 1 {
            self.push_scrollback(line);
        }
        self.screen
            .insert(bottom as usize, Line::blank(self.cols as usize));
    }

    /// Scrolls the screen down by one line within `[top, bottom]` (reverse
    /// index). The line pushed off the bottom is discarded; scrollback is
    /// never populated downwards.
    pub fn scroll_down_in_region(&mut self, top: u32, bottom: u32) {
        if top > bottom || bottom >= self.rows {
            return;
        }
        self.screen.remove(bottom as usize);
        self.screen
            .insert(top as usize, Line::blank(self.cols as usize));
    }

    fn push_scrollback(&mut self, line: Line) {
        if self.max_scrollback == 0 {
            return;
        }
        if self.scrollback.len() >= self.max_scrollback {
            self.scrollback.pop_front();
        }
        self.scrollback.push_back(line);
    }

    /// Drops all scrollback (ED 3).
    pub fn clear_scrollback(&mut self) {
        self.scrollback.clear();
    }

    /// Resizes the grid. `cursor` is remapped to stay attached to its
    /// content. Width changes trigger a full reflow (logical lines are
    /// rebuilt and rewrapped at the new width); height-only changes follow
    /// VTE semantics: growing pulls lines back out of the scrollback,
    /// shrinking pushes only as many top lines into the scrollback as the
    /// cursor requires. Scrollback itself never reflows height-wise beyond
    /// what rewrapping produces.
    pub fn resize(&mut self, cols: u32, rows: u32, cursor: &mut (u32, u32), reflow: bool) {
        let cols = cols.max(1);
        let rows = rows.max(1);
        if cols == self.cols && rows == self.rows {
            return;
        }
        if cols != self.cols && reflow {
            self.rewrap(cols, rows, cursor);
        } else {
            self.resize_height(rows, cursor);
            self.resize_width_no_reflow(cols);
        }
    }

    fn resize_height(&mut self, rows: u32, cursor: &mut (u32, u32)) {
        if rows > self.rows {
            let grow = (rows - self.rows) as usize;
            let pulled = grow.min(self.scrollback.len());
            for _ in 0..pulled {
                if let Some(line) = self.scrollback.pop_back() {
                    self.screen.insert(0, line);
                }
            }
            cursor.0 = (cursor.0 + pulled as u32).min(rows - 1);
            while self.screen.len() < rows as usize {
                self.screen.push(Line::blank(self.cols as usize));
            }
        } else if rows < self.rows {
            let shrink = (self.rows - rows) as usize;
            // Push only as many top lines into the scrollback as needed to
            // keep the cursor on screen; discard blank bottom rows otherwise.
            let push_top = (cursor.0 as usize + 1).saturating_sub(rows as usize);
            let push_top = push_top.min(shrink);
            for _ in 0..push_top {
                let line = self.screen.remove(0);
                self.push_scrollback(line);
            }
            self.screen.truncate(rows as usize);
            cursor.0 = cursor.0.saturating_sub(push_top as u32);
            while self.screen.len() < rows as usize {
                self.screen.push(Line::blank(self.cols as usize));
            }
        }
        self.rows = rows;
        if cursor.0 >= rows {
            cursor.0 = rows - 1;
        }
    }

    /// Width change without reflow (alternate screen): clip or pad each row.
    fn resize_width_no_reflow(&mut self, cols: u32) {
        if cols == self.cols {
            return;
        }
        for line in &mut self.screen {
            line.cells.truncate(cols as usize);
            while line.cells.len() < cols as usize {
                line.cells.push(Cell::default());
            }
        }
        self.cols = cols;
    }

    /// Full reflow: rebuild logical lines from scrollback + screen, rewrap
    /// them at the new width, and repartition into scrollback / screen.
    fn rewrap(&mut self, cols: u32, rows: u32, cursor: &mut (u32, u32)) {
        let new_cols = cols as usize;
        let cursor_abs = self.scrollback.len() + cursor.0 as usize;

        // 1. Unwrap into logical lines, tracking where the cursor sits.
        let mut logical: Vec<Vec<Cell>> = Vec::new();
        let mut cursor_logical = 0usize;
        let mut cursor_offset = 0usize;
        let mut run_offset = 0usize;

        let all: Vec<&Line> = self.scrollback.iter().chain(self.screen.iter()).collect();
        for (i, line) in all.iter().enumerate() {
            let starts_new = i == 0 || !all[i - 1].wrapped;
            if starts_new {
                logical.push(Vec::new());
                run_offset = 0;
            }
            if i == cursor_abs {
                cursor_logical = logical.len() - 1;
                cursor_offset = run_offset + (cursor.1 as usize).min(line.cells.len());
            }
            logical.last_mut().unwrap().extend_from_slice(&line.cells);
            run_offset += line.cells.len();
        }

        // Trailing blanks of a logical line are not displayable; trimming
        // them keeps rewraps at wider widths from fabricating blank rows.
        // The cursor keeps its raw offset: it may legitimately sit past the
        // printed content (e.g. positioned there by CUP).
        for cells in &mut logical {
            while cells.last().is_some_and(Cell::is_blank) {
                cells.pop();
            }
        }

        // 2. Rewrap into physical lines at the new width, remapping cursor.
        let mut physical: Vec<Line> = Vec::new();
        let mut new_cursor_abs = 0usize;
        for (li, cells) in logical.iter().enumerate() {
            if cells.is_empty() {
                if li == cursor_logical {
                    new_cursor_abs = physical.len();
                }
                physical.push(Line::blank(new_cols));
                continue;
            }
            let chunks = cells.len().div_ceil(new_cols);
            let first_row = physical.len();
            for part in 0..chunks {
                let start = part * new_cols;
                let end = (start + new_cols).min(cells.len());
                let mut row = vec![Cell::default(); new_cols];
                row[..end - start].clone_from_slice(&cells[start..end]);
                if li == cursor_logical && cursor_offset >= start && cursor_offset < end {
                    new_cursor_abs = physical.len();
                    cursor.1 = (cursor_offset - start) as u32;
                }
                physical.push(Line::from_cells(row, end < cells.len()));
            }
            if li == cursor_logical && cursor_offset >= cells.len() {
                // Cursor sits past the printed content of its logical line
                // (trailing blanks were trimmed): keep it on the line's last
                // physical row at its clamped raw offset.
                let last_start = (chunks - 1) * new_cols;
                new_cursor_abs = first_row + chunks - 1;
                cursor.1 = cursor_offset.saturating_sub(last_start).min(new_cols - 1) as u32;
            }
        }

        // 3. Repartition: pick the topmost window of `rows` physical lines
        //    that still contains the cursor. Lines above it become scrollback
        //    (bounded); lines below it are dropped (VTE-like shrink behavior).
        //    If everything fits, content is anchored at the top with blank
        //    rows below.
        let total = physical.len();
        let screen_len = total.min(rows as usize);
        let screen_start = (new_cursor_abs + 1).saturating_sub(rows as usize);
        let cursor_row = (new_cursor_abs - screen_start) as u32;

        self.scrollback = physical.drain(..screen_start).collect();
        while self.scrollback.len() > self.max_scrollback {
            self.scrollback.pop_front();
        }
        let mut screen: Vec<Line> = physical.drain(..screen_len).collect();
        // Any lines remaining in `physical` sat below the re-anchored window
        // and are dropped, mirroring VTE's shrink behavior.
        for line in &mut screen {
            line.cells.truncate(new_cols);
            while line.cells.len() < new_cols {
                line.cells.push(Cell::default());
            }
        }
        while screen.len() < rows as usize {
            screen.push(Line::blank(new_cols));
        }
        self.screen = screen;
        self.cols = cols;
        self.rows = rows;
        *cursor = (cursor_row, cursor.1.min(cols - 1));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::term::cell::Attrs;

    fn put_text(line: &mut Line, text: &str) {
        for (i, c) in text.chars().enumerate() {
            line.cells[i] = Cell::new(c, Attrs::default());
        }
    }

    #[test]
    fn line_text_trims_trailing_blanks() {
        let mut line = Line::blank(10);
        put_text(&mut line, "hi   ");
        assert_eq!(line.text(), "hi");
    }

    #[test]
    fn scroll_up_pushes_to_scrollback() {
        let mut g = Grid::new(10, 3, 100);
        put_text(g.line_mut(0), "top");
        g.scroll_up_in_region(0, 2);
        assert_eq!(g.scrollback_len(), 1);
        assert_eq!(g.scrollback_line(0).text(), "top");
        assert!(g.line(2).is_blank());
    }

    #[test]
    fn scrollback_is_bounded() {
        let mut g = Grid::new(4, 2, 3);
        for i in 0..10 {
            put_text(g.line_mut(0), &format!("l{i}"));
            g.scroll_up_in_region(0, 1);
        }
        assert_eq!(g.scrollback_len(), 3);
        assert_eq!(g.scrollback_line(2).text(), "l9");
    }

    #[test]
    fn region_scroll_does_not_touch_scrollback() {
        let mut g = Grid::new(10, 5, 100);
        g.scroll_up_in_region(1, 3);
        assert_eq!(g.scrollback_len(), 0);
    }

    #[test]
    fn grow_pulls_from_scrollback() {
        let mut g = Grid::new(10, 2, 100);
        put_text(g.line_mut(0), "a");
        put_text(g.line_mut(1), "b");
        g.scroll_up_in_region(0, 1); // "a" -> scrollback, "b" at row 0
        put_text(g.line_mut(1), "c");
        let mut cursor = (1, 0);
        g.resize(10, 3, &mut cursor, true);
        assert_eq!(g.scrollback_len(), 0);
        assert_eq!(g.line(0).text(), "a");
        assert_eq!(g.line(1).text(), "b");
        assert_eq!(g.line(2).text(), "c");
        assert_eq!(cursor, (2, 0));
    }

    #[test]
    fn shrink_keeps_cursor_visible() {
        let mut g = Grid::new(10, 5, 100);
        for (i, t) in ["a", "b", "c", "d", "e"].iter().enumerate() {
            put_text(g.line_mut(i as u32), t);
        }
        let mut cursor = (4, 0);
        g.resize(10, 2, &mut cursor, true);
        assert_eq!(cursor, (1, 0));
        assert_eq!(g.line(1).text(), "e");
        assert_eq!(g.scrollback_len(), 3);
        assert_eq!(g.scrollback_line(0).text(), "a");
    }

    #[test]
    fn shrink_with_roomy_cursor_keeps_content_anchored() {
        let mut g = Grid::new(10, 5, 100);
        put_text(g.line_mut(0), "x");
        let mut cursor = (0, 1);
        g.resize(10, 3, &mut cursor, true);
        assert_eq!(cursor, (0, 1));
        assert_eq!(g.line(0).text(), "x");
        assert_eq!(g.scrollback_len(), 0);
    }

    #[test]
    fn rewrap_wider_joins_wrapped_lines() {
        let mut g = Grid::new(4, 3, 100);
        // Logical line "abcdefgh" wrapped across rows 0-1.
        put_text(g.line_mut(0), "abcd");
        g.set_wrapped(0, true);
        put_text(g.line_mut(1), "efgh");
        let mut cursor = (1, 3);
        g.resize(8, 3, &mut cursor, true);
        assert_eq!(g.line(0).text(), "abcdefgh");
        assert!(g.line(1).is_blank());
        assert_eq!(cursor, (0, 7));
    }

    #[test]
    fn rewrap_narrower_splits_lines() {
        let mut g = Grid::new(8, 2, 100);
        put_text(g.line_mut(0), "abcdefgh");
        let mut cursor = (0, 5);
        g.resize(4, 3, &mut cursor, true);
        assert_eq!(g.line(0).text(), "abcd");
        assert_eq!(g.line(1).text(), "efgh");
        assert!(g.line(0).wrapped());
        assert_eq!(cursor, (1, 1));
    }

    #[test]
    fn rewrap_preserves_attributes() {
        let mut g = Grid::new(4, 2, 100);
        {
            let line = g.line_mut(0);
            line.cells[0] = Cell {
                ch: 'x',
                attrs: Attrs {
                    bold: true,
                    ..Attrs::default()
                },
                wide: false,
                continuation: false,
            };
            line.wrapped = true;
        }
        let mut cursor = (0, 0);
        g.resize(8, 2, &mut cursor, true);
        assert!(g.cell(0, 0).attrs.bold);
    }
}
