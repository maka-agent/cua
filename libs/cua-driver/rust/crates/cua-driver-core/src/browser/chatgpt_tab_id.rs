// SPDX-License-Identifier: MIT

//! Extension public tab-ID conversion at the external identifier boundary.
//!
//! Matches the supported positive-safe-integer portion of ECMAScript
//! Number(string), without evaluating scripts or introducing a JS runtime.

const MAX_SAFE_ID: u64 = 9_007_199_254_740_991;

/// Convert the supported positive-safe-integer ECMAScript Number(string) tab ID.
/// This pure identifier conversion performs no extension lookup or authorization.
pub fn parse_browser_tab_id(raw: &str) -> Option<u64> {
    let text = raw.trim_matches(ecma_space);
    if text.is_empty() {
        return None;
    }
    for (prefixes, radix) in [(["0x", "0X"], 16), (["0o", "0O"], 8), (["0b", "0B"], 2)] {
        if let Some(digits) = prefixes
            .into_iter()
            .find_map(|prefix| text.strip_prefix(prefix))
        {
            if digits.is_empty()
                || !digits.bytes().all(|byte| match byte {
                    b'0'..=b'9' => u32::from(byte - b'0') < radix,
                    b'a'..=b'f' => u32::from(byte - b'a') + 10 < radix,
                    b'A'..=b'F' => u32::from(byte - b'A') + 10 < radix,
                    _ => false,
                })
            {
                return None;
            }
            return u64::from_str_radix(digits, radix)
                .ok()
                .filter(|id| *id > 0 && *id <= MAX_SAFE_ID);
        }
    }
    if !decimal_literal(text) {
        return None;
    }
    let number = text.parse::<f64>().ok()?;
    if !number.is_finite() || number <= 0.0 || number.fract() != 0.0 || number > MAX_SAFE_ID as f64
    {
        return None;
    }
    // Range/integrality checks above make this boundary conversion exact.
    Some(number as u64)
}

fn decimal_literal(text: &str) -> bool {
    let unsigned = text
        .strip_prefix('+')
        .or_else(|| text.strip_prefix('-'))
        .unwrap_or(text);
    let mut exponent = unsigned.split(['e', 'E']);
    let mantissa = exponent.next().unwrap_or("");
    if let Some(power) = exponent.next() {
        if exponent.next().is_some() {
            return false;
        }
        let digits = power
            .strip_prefix('+')
            .or_else(|| power.strip_prefix('-'))
            .unwrap_or(power);
        if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
            return false;
        }
    }
    let mut points = 0usize;
    let mut digits = 0usize;
    for byte in mantissa.bytes() {
        if byte == b'.' {
            points += 1;
            if points > 1 {
                return false;
            }
        } else if byte.is_ascii_digit() {
            digits += 1;
        } else {
            return false;
        }
    }
    digits > 0
}

fn ecma_space(value: char) -> bool {
    matches!(
        value,
        '\u{0009}'
            | '\u{000a}'
            | '\u{000b}'
            | '\u{000c}'
            | '\u{000d}'
            | '\u{0020}'
            | '\u{00a0}'
            | '\u{1680}'
            | '\u{2000}'
            ..='\u{200a}'
                | '\u{2028}'
                | '\u{2029}'
                | '\u{202f}'
                | '\u{205f}'
                | '\u{3000}'
                | '\u{feff}'
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn native_number_spellings_resolve_the_same_actual_id() {
        for text in [
            "100",
            "1e2",
            "0x64",
            "0X64",
            "0o144",
            "0b1100100",
            "+100",
            "100.0",
            "1.e2",
            "\u{feff}\u{2009}100\u{2029}",
        ] {
            assert_eq!(parse_browser_tab_id(text), Some(100), "{text:?}");
        }
    }
    #[test]
    fn invalid_unsigned_prefixes_unicode_and_noninteger_ids_are_refused() {
        for text in [
            "",
            " ",
            "0",
            "-1",
            "1.5",
            "+0x64",
            "0x+64",
            "-0b1",
            "1_00",
            "100junk",
            "\u{0085}100",
            "\u{180e}100",
            "Infinity",
            "NaN",
            "9007199254740992",
        ] {
            assert_eq!(parse_browser_tab_id(text), None, "{text:?}");
        }
    }
}
