//! Palette from the design mockup (`docs/design/sentry-tui.dc.html`, the `C` object).
//! Truecolor when the terminal advertises it, nearest ANSI colors otherwise.

use ratatui::style::{Color, Style};

#[derive(Debug, Clone, Copy)]
pub struct Theme {
    pub fg: Color,
    pub dim: Color,
    pub red: Color,
    pub green: Color,
    pub yellow: Color,
    pub blue: Color,
    pub mag: Color,
    pub cyan: Color,
    pub sel_bg: Color,
    pub border: Color,
    pub rule: Color,
    pub track: Color,
    pub banner_bg: Color,
    pub ink: Color,
    pub chip_fg: Color,
    pub hint: Color,
}

impl Theme {
    pub fn detect() -> Self {
        let truecolor = std::env::var("COLORTERM").is_ok_and(|v| v == "truecolor" || v == "24bit");
        if truecolor { Self::truecolor() } else { Self::ansi() }
    }

    pub fn truecolor() -> Self {
        let rgb = |h: u32| Color::Rgb((h >> 16) as u8, (h >> 8) as u8, h as u8);
        Self {
            fg: rgb(0xd4d4d4),
            dim: rgb(0x7d8590),
            red: rgb(0xef6b73),
            green: rgb(0x8fcf7a),
            yellow: rgb(0xe8c46b),
            blue: rgb(0x78a9e6),
            mag: rgb(0xc792ea),
            cyan: rgb(0x6fd0c9),
            sel_bg: rgb(0x22303f),
            border: rgb(0x3a3e44),
            rule: rgb(0x2a2d31),
            track: rgb(0x30343a),
            banner_bg: rgb(0x2e2a1c),
            ink: rgb(0x131415),
            chip_fg: rgb(0x131415),
            hint: rgb(0xa9b0b8),
        }
    }

    pub fn ansi() -> Self {
        Self {
            fg: Color::Reset,
            dim: Color::DarkGray,
            red: Color::LightRed,
            green: Color::Green,
            yellow: Color::Yellow,
            blue: Color::Blue,
            mag: Color::Magenta,
            cyan: Color::Cyan,
            sel_bg: Color::Indexed(236),
            border: Color::DarkGray,
            rule: Color::DarkGray,
            track: Color::Indexed(238),
            banner_bg: Color::Indexed(58),
            ink: Color::Black,
            chip_fg: Color::Black,
            hint: Color::Gray,
        }
    }

    pub fn s(&self, c: Color) -> Style {
        Style::new().fg(c)
    }

    pub fn fg(&self) -> Style {
        self.s(self.fg)
    }

    pub fn dim(&self) -> Style {
        self.s(self.dim)
    }

    pub fn chip(&self, bg: Color) -> Style {
        Style::new().fg(self.chip_fg).bg(bg)
    }

    /// Bar / core color by load, mockup thresholds.
    pub fn load(&self, pct: f64) -> Color {
        if pct > 75.0 {
            self.red
        } else if pct > 45.0 {
            self.yellow
        } else {
            self.cyan
        }
    }
}
