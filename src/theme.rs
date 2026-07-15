//! Design tokens and embedded IBM Plex fonts, per the design handoff
//! ("Firebreak UI Concept"). Each color has exactly one job — see the
//! handoff's system sheet. All machine truth renders in Plex Mono;
//! explanatory/provenance asides in Plex Sans Italic.

use eframe::egui::{self, Color32, FontFamily, FontId};

// ---- semantic palette ----
pub const ACCENT: Color32 = Color32::from_rgb(0x29, 0x80, 0xB9); // pending intent + primary action only
pub const ACCENT_TINT: Color32 = Color32::from_rgb(0xEA, 0xF3, 0xFC);
pub const ACCENT_TINT_BORDER: Color32 = Color32::from_rgb(0xB9, 0xD4, 0xEE);
pub const SELECTED_ROW: Color32 = Color32::from_rgb(0xE7, 0xF0, 0xFA);
pub const DESTRUCTIVE: Color32 = Color32::from_rgb(0xC0, 0x39, 0x2B);
pub const DESTRUCTIVE_DARK: Color32 = Color32::from_rgb(0x92, 0x2B, 0x21);
pub const FAIL_BG: Color32 = Color32::from_rgb(0xFB, 0xEF, 0xED);
pub const FAIL_BORDER: Color32 = Color32::from_rgb(0xE3, 0xB8, 0xB1);
pub const BLOCK: Color32 = Color32::from_rgb(0xB0, 0x3A, 0x2E);
pub const LIVE: Color32 = Color32::from_rgb(0x27, 0xAE, 0x60);
pub const LIVE_TEXT: Color32 = Color32::from_rgb(0x1E, 0x84, 0x49);
pub const LIVE_BG: Color32 = Color32::from_rgb(0xEA, 0xF7, 0xEF);
pub const LIVE_BORDER: Color32 = Color32::from_rgb(0xC5, 0xE8, 0xD2);
pub const ADVISORY: Color32 = Color32::from_rgb(0xB7, 0x95, 0x0B);
pub const ADVISORY_BG: Color32 = Color32::from_rgb(0xFD, 0xF6, 0xDE);
pub const ADVISORY_BORDER: Color32 = Color32::from_rgb(0xEB, 0xD9, 0x8A);
pub const ADVISORY_TEXT: Color32 = Color32::from_rgb(0x7D, 0x66, 0x08);
pub const ADVISORY_HEADER: Color32 = Color32::from_rgb(0x9A, 0x7D, 0x0A);

pub const INK: Color32 = Color32::from_rgb(0x2C, 0x3E, 0x50);
pub const SECONDARY: Color32 = Color32::from_rgb(0x5D, 0x6D, 0x7E);
pub const TERTIARY: Color32 = Color32::from_rgb(0x76, 0x83, 0x8F);
pub const FAINT: Color32 = Color32::from_rgb(0x8B, 0x96, 0xA0);
pub const DISABLED: Color32 = Color32::from_rgb(0xA9, 0xB4, 0xBE);
pub const HAIRLINE_TEXT: Color32 = Color32::from_rgb(0xC3, 0xCC, 0xD4);

pub const CHROME: Color32 = Color32::from_rgb(0xF4, 0xF6, 0xF8);
pub const RAISED: Color32 = Color32::from_rgb(0xFA, 0xFB, 0xFC);
pub const TITLEBAR: Color32 = Color32::from_rgb(0xEB, 0xEE, 0xF1);
pub const BORDER: Color32 = Color32::from_rgb(0xD5, 0xDC, 0xE2);
pub const BORDER_LIGHT: Color32 = Color32::from_rgb(0xE1, 0xE6, 0xEA);
pub const ROW_BORDER: Color32 = Color32::from_rgb(0xEE, 0xF1, 0xF4);
pub const CONTROL_BORDER: Color32 = Color32::from_rgb(0xC3, 0xCC, 0xD3);
pub const DARK_SEGMENT: Color32 = Color32::from_rgb(0x34, 0x49, 0x5E);
pub const HOVER_WASH: Color32 = Color32::from_rgb(0xF5, 0xF8, 0xFB);
pub const LOGO_RED: Color32 = Color32::from_rgb(0xC0, 0x39, 0x2B);
pub const ENABLE_GREEN: Color32 = Color32::from_rgb(0x1E, 0x84, 0x49);
pub const BACKUP_BG: Color32 = Color32::from_rgb(0xF0, 0xF8, 0xF2);
pub const BACKUP_BORDER: Color32 = Color32::from_rgb(0xC8, 0xE4, 0xCE);
pub const BACKUP_TEXT: Color32 = Color32::from_rgb(0x19, 0x6F, 0x3D);
pub const VERB_DISABLE_BG: Color32 = Color32::from_rgb(0xFB, 0xF4, 0xF2);
pub const CB_SAVED_BORDER: Color32 = Color32::from_rgb(0x6C, 0x7A, 0x89);
pub const CB_EMPTY_BORDER: Color32 = Color32::from_rgb(0xB6, 0xC0, 0xC9);
pub const PROGRESS_TRACK: Color32 = Color32::from_rgb(0xD3, 0xE4, 0xF5);
pub const FIRSTRUN_DASH: Color32 = Color32::from_rgb(0xD3, 0xDA, 0xE0);

// profile chips: (text, fg, bg, border)
pub const CHIP_DOM: (&str, Color32, Color32, Color32) = (
    "DOM",
    Color32::from_rgb(0x29, 0x80, 0xB9),
    Color32::from_rgb(0xEA, 0xF4, 0xFB),
    Color32::from_rgb(0xBC, 0xD9, 0xEE),
);
pub const CHIP_PRV: (&str, Color32, Color32, Color32) = (
    "PRV",
    Color32::from_rgb(0x16, 0xA0, 0x85),
    Color32::from_rgb(0xE8, 0xF6, 0xF3),
    Color32::from_rgb(0xBA, 0xE2, 0xD9),
);
pub const CHIP_PUB: (&str, Color32, Color32, Color32) = (
    "PUB",
    Color32::from_rgb(0xB9, 0x77, 0x0E),
    Color32::from_rgb(0xFD, 0xF3, 0xE3),
    Color32::from_rgb(0xF0, 0xD5, 0xA8),
);
pub const CHIP_ANY: (&str, Color32, Color32, Color32) = (
    "ANY",
    Color32::from_rgb(0x76, 0x83, 0x8F),
    Color32::from_rgb(0xEE, 0xF1, 0xF3),
    Color32::from_rgb(0xD3, 0xDA, 0xE0),
);

// ---- fonts ----

const SANS: &str = "plex-sans";
const SANS_MEDIUM: &str = "plex-sans-medium";
const SANS_SEMIBOLD: &str = "plex-sans-semibold";
const SANS_ITALIC: &str = "plex-sans-italic";
const MONO: &str = "plex-mono";
const MONO_MEDIUM: &str = "plex-mono-medium";

pub fn install_fonts(ctx: &egui::Context) {
    let mut fonts = egui::FontDefinitions::default();
    let faces: [(&str, &[u8]); 6] = [
        (SANS, include_bytes!("../assets/fonts/IBMPlexSans-Regular.ttf")),
        (SANS_MEDIUM, include_bytes!("../assets/fonts/IBMPlexSans-Medium.ttf")),
        (SANS_SEMIBOLD, include_bytes!("../assets/fonts/IBMPlexSans-SemiBold.ttf")),
        (SANS_ITALIC, include_bytes!("../assets/fonts/IBMPlexSans-Italic.ttf")),
        (MONO, include_bytes!("../assets/fonts/IBMPlexMono-Regular.ttf")),
        (MONO_MEDIUM, include_bytes!("../assets/fonts/IBMPlexMono-Medium.ttf")),
    ];
    for (name, bytes) in faces {
        fonts
            .font_data
            .insert(name.to_string(), egui::FontData::from_static(bytes));
    }
    // egui's bundled fonts stay as fallback for glyphs outside Plex's latin
    // subset (▲ ✓ ✕ ⌕ ▾ · —)
    let default_stack: Vec<String> = fonts
        .families
        .get(&FontFamily::Proportional)
        .cloned()
        .unwrap_or_default();
    for name in [SANS, SANS_MEDIUM, SANS_SEMIBOLD, SANS_ITALIC, MONO, MONO_MEDIUM] {
        let mut stack = vec![name.to_string()];
        stack.extend(default_stack.iter().cloned());
        fonts
            .families
            .insert(FontFamily::Name(name.into()), stack);
    }
    // defaults so stray widgets look right too
    fonts
        .families
        .get_mut(&FontFamily::Proportional)
        .unwrap()
        .insert(0, SANS.to_string());
    fonts
        .families
        .get_mut(&FontFamily::Monospace)
        .unwrap()
        .insert(0, MONO.to_string());
    ctx.set_fonts(fonts);
}

pub fn sans(size: f32) -> FontId {
    FontId::new(size, FontFamily::Name(SANS.into()))
}
pub fn medium(size: f32) -> FontId {
    FontId::new(size, FontFamily::Name(SANS_MEDIUM.into()))
}
pub fn semibold(size: f32) -> FontId {
    FontId::new(size, FontFamily::Name(SANS_SEMIBOLD.into()))
}
pub fn italic(size: f32) -> FontId {
    FontId::new(size, FontFamily::Name(SANS_ITALIC.into()))
}
pub fn mono(size: f32) -> FontId {
    FontId::new(size, FontFamily::Name(MONO.into()))
}
pub fn mono_medium(size: f32) -> FontId {
    FontId::new(size, FontFamily::Name(MONO_MEDIUM.into()))
}

pub fn apply_style(ctx: &egui::Context) {
    install_fonts(ctx);
    let mut visuals = egui::Visuals::light();
    visuals.panel_fill = CHROME;
    visuals.window_fill = Color32::WHITE;
    visuals.extreme_bg_color = Color32::WHITE;
    visuals.faint_bg_color = RAISED;
    visuals.selection.bg_fill = ACCENT.gamma_multiply(0.35);
    visuals.hyperlink_color = ACCENT;
    visuals.override_text_color = Some(INK);
    // square corners everywhere; no shadows inside the window
    for w in [
        &mut visuals.widgets.noninteractive,
        &mut visuals.widgets.inactive,
        &mut visuals.widgets.hovered,
        &mut visuals.widgets.active,
        &mut visuals.widgets.open,
    ] {
        w.rounding = egui::Rounding::ZERO;
    }
    visuals.window_rounding = egui::Rounding::ZERO;
    visuals.menu_rounding = egui::Rounding::ZERO;
    visuals.window_shadow = egui::epaint::Shadow {
        offset: egui::vec2(0.0, 12.0),
        blur: 40.0,
        spread: 0.0,
        color: Color32::from_black_alpha(76),
    };
    visuals.popup_shadow = egui::epaint::Shadow {
        offset: egui::vec2(0.0, 4.0),
        blur: 12.0,
        spread: 0.0,
        color: Color32::from_black_alpha(40),
    };
    ctx.set_visuals(visuals);
    ctx.style_mut(|s| {
        s.spacing.item_spacing = egui::vec2(8.0, 4.0);
        s.spacing.button_padding = egui::vec2(12.0, 5.0);
    });
}

/// "1,482,306"
pub fn fmt_thousands(n: i64) -> String {
    let s = n.abs().to_string();
    let mut out = String::new();
    for (i, c) in s.chars().enumerate() {
        if i > 0 && (s.len() - i) % 3 == 0 {
            out.push(',');
        }
        out.push(c);
    }
    if n < 0 {
        format!("-{out}")
    } else {
        out
    }
}

#[cfg(test)]
mod tests {
    use super::fmt_thousands;

    #[test]
    fn thousands_formatting() {
        assert_eq!(fmt_thousands(0), "0");
        assert_eq!(fmt_thousands(999), "999");
        assert_eq!(fmt_thousands(1204), "1,204");
        assert_eq!(fmt_thousands(1_482_306), "1,482,306");
    }
}
