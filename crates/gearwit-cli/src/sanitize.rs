//! Paste-safe token checks for local CLI faces.
//!
//! Control characters, newlines, and ANSI introducers can forge receipt fields
//! or drive a terminal. Reject them; do not echo raw untrusted strings.

/// Maximum length for a terminal program name.
pub const MAX_TERM: usize = 32;
/// Maximum length for channel, team, or cursor tokens.
pub const MAX_ID: usize = 128;
/// Maximum length for a timeout token (`20m`, `60s`).
pub const MAX_TIMEOUT: usize = 16;

/// Return the token when it is bounded and free of control characters.
#[must_use]
pub fn paste_token(raw: &str, max: usize) -> Option<&str> {
    if raw.is_empty() || raw.len() > max {
        return None;
    }
    if raw.chars().any(char::is_control) {
        return None;
    }
    Some(raw)
}

/// Render a token or `rejected` when it cannot appear on a paste-safe face.
#[must_use]
pub fn paste_field(raw: &str, max: usize) -> String {
    paste_token(raw, max).map_or_else(|| "rejected".to_owned(), ToOwned::to_owned)
}

#[cfg(test)]
mod tests {
    use super::{MAX_TERM, paste_field, paste_token};

    #[test]
    fn newline_is_rejected() {
        assert_eq!(paste_token("ghostty\nwait_result: matched", MAX_TERM), None);
        assert_eq!(
            paste_field("ghostty\nwait_result: matched", MAX_TERM),
            "rejected"
        );
    }

    #[test]
    fn ansi_escape_is_rejected() {
        assert_eq!(paste_token("\u{1b}[31mghostty", MAX_TERM), None);
    }

    #[test]
    fn ordinary_term_is_kept() {
        assert_eq!(paste_token("ghostty", MAX_TERM), Some("ghostty"));
    }
}
