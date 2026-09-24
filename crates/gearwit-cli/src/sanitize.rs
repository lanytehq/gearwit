//! Paste-safe token checks for local CLI faces.
//!
//! Control characters, newlines, and ANSI introducers can forge receipt fields
//! or drive a terminal. Reject them; do not echo raw untrusted strings.

use std::fmt;

use unicode_segmentation::UnicodeSegmentation;

/// Maximum length for a terminal program name.
pub const MAX_TERM: usize = 32;
/// Maximum length for channel, team, or cursor tokens.
pub const MAX_ID: usize = 128;
/// Maximum length for a timeout token (`20m`, `60s`).
pub const MAX_TIMEOUT: usize = 16;
/// Maximum length for a drained message body on the local face.
pub const MAX_BODY: usize = 4096;
/// Maximum UTF-8 byte length for a body on the current host path.
pub const MAX_BODY_BYTES: usize = 4096;

/// Fixed, untrusted notice used only when this process measures local loss.
pub const PARTIAL_BODY_ADVISORY: &str = "Partial body; full post at source.";

/// Locally measured loss while preparing a displayed provider body.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LocalBodyLoss {
    /// Disallowed control scalars omitted by this process.
    pub controls_removed: usize,
    /// Non-control scalars omitted to reserve the advisory and satisfy limits.
    pub scalars_clipped: usize,
    /// UTF-8 bytes in the final displayed body, including the advisory.
    pub displayed_bytes: usize,
}

/// A body prepared for the current seat and host bounds.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreparedBody {
    /// Exact display text, except for locally removed controls and any clipped suffix.
    pub body: String,
    /// Present only when this process measured a local transformation loss.
    pub local_loss: Option<LocalBodyLoss>,
}

/// Measured loss when an untrusted partial-body advisory cannot fit safely.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BodyPrepareError {
    /// Disallowed control scalars omitted before display preparation.
    pub controls_removed: usize,
    /// Non-control scalars that would have to be clipped to show the advisory.
    pub scalars_clipped: usize,
}

impl fmt::Display for BodyPrepareError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "partial-body advisory cannot fit (controls_removed={}, scalars_clipped={})",
            self.controls_removed, self.scalars_clipped
        )
    }
}

impl std::error::Error for BodyPrepareError {}

/// Prepare a provider body without silently losing locally observed content.
///
/// The warning-only transition preserves allowed tab/LF, strips disallowed
/// controls only with a visible advisory, and reserves space for that advisory
/// before clipping at both the scalar and UTF-8 byte bounds. Grapheme boundaries
/// use the version-pinned `unicode-segmentation` 1.12.0 implementation of UAX #29.
///
/// # Errors
///
/// Returns [`BodyPrepareError`] with measured input loss when no useful
/// grapheme, required fence closure, and advisory fit within both bounds.
pub fn prepare_body(raw: &str) -> Result<PreparedBody, BodyPrepareError> {
    prepare_body_with_limits(raw, MAX_BODY, MAX_BODY_BYTES)
}

/// Prepare a provider body using explicit limits.
///
/// This is public for exact boundary tests; product callers use
/// [`prepare_body`] so wire and host bounds stay paired.
///
/// # Errors
///
/// Returns [`BodyPrepareError`] when safe disclosure is impossible under
/// either limit.
pub fn prepare_body_with_limits(
    raw: &str,
    max_scalars: usize,
    max_bytes: usize,
) -> Result<PreparedBody, BodyPrepareError> {
    let mut clean = String::with_capacity(raw.len());
    let mut controls_removed = 0;
    for character in raw.chars() {
        if is_disallowed_control(character) {
            controls_removed += 1;
        } else {
            clean.push(character);
        }
    }

    let clean_scalars = clean.chars().count();
    let already_fits = clean_scalars <= max_scalars && clean.len() <= max_bytes;
    if controls_removed == 0 && already_fits {
        return Ok(PreparedBody {
            body: clean,
            local_loss: None,
        });
    }

    let minimum_extra_scalars = 2 + PARTIAL_BODY_ADVISORY.chars().count();
    let minimum_extra_bytes = 2 + PARTIAL_BODY_ADVISORY.len();
    let mut retained_ends = Vec::new();
    let mut retained_scalars = 0;
    let mut retained_bytes = 0;

    for grapheme in clean.graphemes(true) {
        let grapheme_scalars = grapheme.chars().count();
        if retained_scalars + grapheme_scalars + minimum_extra_scalars > max_scalars
            || retained_bytes + grapheme.len() + minimum_extra_bytes > max_bytes
        {
            break;
        }
        retained_scalars += grapheme_scalars;
        retained_bytes += grapheme.len();
        retained_ends.push((retained_bytes, retained_scalars));
    }

    while let Some((byte_end, scalar_end)) = retained_ends.pop() {
        let prefix = &clean[..byte_end];
        if !prefix.chars().any(|character| !character.is_whitespace()) {
            continue;
        }

        let mut body = prefix.to_owned();
        if let Some((marker, length)) = unclosed_fence(prefix) {
            if !body.ends_with('\n') {
                body.push('\n');
            }
            body.extend(std::iter::repeat_n(marker, length));
            body.push('\n');
        }
        if !body.ends_with('\n') {
            body.push('\n');
        }
        body.push('\n');
        body.push_str(PARTIAL_BODY_ADVISORY);

        if body.chars().count() <= max_scalars && body.len() <= max_bytes {
            let local_loss = LocalBodyLoss {
                controls_removed,
                scalars_clipped: clean_scalars.saturating_sub(scalar_end),
                displayed_bytes: body.len(),
            };
            return Ok(PreparedBody {
                body,
                local_loss: Some(local_loss),
            });
        }
    }

    Err(BodyPrepareError {
        controls_removed,
        scalars_clipped: clean_scalars,
    })
}

fn is_disallowed_control(character: char) -> bool {
    character.is_control() && character != '\t' && character != '\n'
}

/// Whether a body can pass through both local renderers without transformation.
#[must_use]
pub fn body_is_displayable(body: &str) -> bool {
    body.chars().count() <= MAX_BODY
        && body.len() <= MAX_BODY_BYTES
        && !body.chars().any(is_disallowed_control)
}

fn unclosed_fence(text: &str) -> Option<(char, usize)> {
    let mut open: Option<(char, usize)> = None;
    for line in text.split('\n') {
        let Some((marker, length, remainder)) = fence_marker(line) else {
            continue;
        };
        match open {
            Some((open_marker, open_length))
                if marker == open_marker
                    && length >= open_length
                    && remainder.trim().is_empty() =>
            {
                open = None;
            }
            None if marker != '`' || !remainder.contains('`') => {
                open = Some((marker, length));
            }
            Some(_) | None => {}
        }
    }
    open
}

fn fence_marker(line: &str) -> Option<(char, usize, &str)> {
    let indent = line
        .chars()
        .take_while(|character| *character == ' ')
        .count();
    if indent > 3 {
        return None;
    }
    let rest = &line[indent..];
    let marker = rest.chars().next()?;
    if marker != '`' && marker != '~' {
        return None;
    }
    let length = rest
        .chars()
        .take_while(|character| *character == marker)
        .count();
    (length >= 3).then(|| (marker, length, &rest[length..]))
}

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
    use super::{
        MAX_BODY, MAX_BODY_BYTES, MAX_TERM, PARTIAL_BODY_ADVISORY, paste_field, paste_token,
        prepare_body, prepare_body_with_limits,
    };
    use unicode_segmentation::UnicodeSegmentation;

    #[test]
    fn body_preserves_allowed_tabs_and_line_feeds() {
        let prepared = prepare_body("first\tcolumn\nsecond").expect("body fits");
        assert_eq!(prepared.body, "first\tcolumn\nsecond");
        assert_eq!(prepared.local_loss, None);
    }

    #[test]
    fn disallowed_control_loss_is_disclosed_and_counted() {
        let prepared = prepare_body("left\u{001b}right").expect("advisory fits");
        assert_eq!(
            prepared
                .local_loss
                .expect("loss is measured")
                .controls_removed,
            1
        );
        assert!(prepared.body.starts_with("leftright\n\n"));
        assert!(prepared.body.ends_with(PARTIAL_BODY_ADVISORY));
        assert!(!prepared.body.contains('\u{001b}'));
    }

    #[test]
    fn clipping_reserves_advisory_within_scalar_and_byte_limits() {
        let raw = "🧪".repeat(1100);
        let prepared = prepare_body(&raw).expect("useful grapheme plus advisory fits");
        let loss = prepared.local_loss.expect("clipping is disclosed");
        assert!(prepared.body.chars().count() <= MAX_BODY);
        assert!(prepared.body.len() <= MAX_BODY_BYTES);
        assert!(loss.scalars_clipped > 0);
        assert_eq!(loss.displayed_bytes, prepared.body.len());
        assert!(prepared.body.ends_with(PARTIAL_BODY_ADVISORY));
    }

    #[test]
    fn clipping_keeps_or_omits_a_combining_cluster_at_the_cutoff() {
        assert_cluster_at_fenced_cutoff("e\u{301}");
    }

    #[test]
    fn clipping_keeps_or_omits_a_zwj_cluster_at_the_cutoff() {
        assert_cluster_at_fenced_cutoff("👩\u{200d}💻");
    }

    fn assert_cluster_at_fenced_cutoff(cluster: &str) {
        assert_eq!(cluster.graphemes(true).count(), 1);
        let before_cluster = format!("```rust\n{}", "x".repeat(12));
        let raw = format!("{before_cluster}{cluster}{}", "y".repeat(100));

        for (retained_prefix, expected_clipped) in [
            (format!("{before_cluster}{cluster}"), 100),
            (before_cluster.clone(), 100 + cluster.chars().count()),
        ] {
            // The actual fence closure and advisory, not merely the source
            // prefix, exactly fill each scalar and UTF-8 byte budget.
            let expected = format!("{retained_prefix}\n```\n\n{PARTIAL_BODY_ADVISORY}");
            let max_scalars = expected.chars().count();
            let max_bytes = expected.len();
            let prepared = prepare_body_with_limits(&raw, max_scalars, max_bytes)
                .expect("whole cluster and visible fence/advisory fit");
            assert_eq!(prepared.body, expected);
            assert_eq!(prepared.body.chars().count(), max_scalars);
            assert_eq!(prepared.body.len(), max_bytes);
            assert!(max_scalars <= MAX_BODY);
            assert!(max_bytes <= MAX_BODY_BYTES);
            assert_eq!(
                prepared.local_loss.expect("loss measured").scalars_clipped,
                expected_clipped
            );
        }
    }

    #[test]
    fn an_open_code_fence_is_closed_before_the_advisory() {
        let raw = format!("```rust\n{}", "x".repeat(5000));
        let prepared = prepare_body(&raw).expect("advisory fits");
        assert!(
            prepared
                .body
                .ends_with("\n```\n\nPartial body; full post at source.")
        );
    }

    #[test]
    fn source_supplied_advisory_text_does_not_create_a_diagnostic() {
        let prepared = prepare_body(PARTIAL_BODY_ADVISORY).expect("body fits");
        assert_eq!(prepared.local_loss, None);
    }

    #[test]
    fn body_is_refused_when_no_grapheme_and_advisory_fit() {
        let raw = "\u{301}".repeat(16);
        assert!(prepare_body_with_limits(&raw, 10, 10).is_err());
    }

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
