// SPDX-License-Identifier: MIT
//! Original native key names resolved through Cua's existing Xlib connection.

use std::ptr::NonNull;

use cua_driver_core::interactive_input::TargetedInputError;

use super::targeted;

const SHIFT_LEFT: u32 = 0xffe1;
const SHIFT_RIGHT: u32 = 0xffe2;

/// Parse the original chord grammar without broadening its named-key set.
pub(crate) fn symbols(key: Option<&str>) -> Result<Vec<u32>, TargetedInputError> {
    let mut symbols = Vec::new();
    let mut empty = false;
    for token in key.into_iter().flat_map(|key| key.split('+')) {
        let token = token.trim();
        if token.is_empty() {
            if empty {
                symbols.push(u32::from(b'+'));
            }
            empty = !empty;
            continue;
        }
        empty = false;
        let lower = token.to_ascii_lowercase();
        let name = lower.strip_prefix("xk_").unwrap_or(&lower);
        symbols
            .push(symbol(name).ok_or_else(|| targeted::failed(format!("unsupported key={name}")))?);
    }
    Ok(symbols)
}

fn symbol(name: &str) -> Option<u32> {
    let named = match name {
        "enter" | "return" => 0xff0d,
        "bsp" | "backspace" => 0xff08,
        "tab" => 0xff09,
        "esc" | "escape" => 0xff1b,
        "del" | "delete" => 0xffff,
        "pause" => 0xff13,
        "scrlk" | "scroll_lock" => 0xff14,
        "sysrq" | "sys_req" => 0xff15,
        "home" => 0xff50,
        "left" => 0xff51,
        "up" => 0xff52,
        "right" => 0xff53,
        "down" => 0xff54,
        "pgup" | "page_up" => 0xff55,
        "pgdn" | "page_down" => 0xff56,
        "end" => 0xff57,
        "ins" | "insert" => 0xff63,
        "numlk" | "num_lock" => 0xff7f,
        "kpenter" | "kp_enter" => 0xff8d,
        "shift" | "lshift" | "shift_l" => SHIFT_LEFT,
        "rshift" | "shift_r" => SHIFT_RIGHT,
        "ctrl" | "lctrl" | "control_l" => 0xffe3,
        "rctrl" | "control_r" => 0xffe4,
        "caplk" | "caps_lock" => 0xffe5,
        "meta" | "lmeta" | "meta_l" => 0xffe7,
        "rmeta" | "meta_r" => 0xffe8,
        "alt" | "lalt" | "alt_l" => 0xffe9,
        "ralt" | "alt_r" => 0xffea,
        "super" | "lsuper" | "super_l" => 0xffeb,
        "rsuper" | "super_r" => 0xffec,
        "space" | "spacebar" | "sb" => 0x20,
        "exclam" => 0x21,
        "quotedbl" => 0x22,
        "numbersign" => 0x23,
        "dollar" => 0x24,
        "percent" => 0x25,
        "ampersand" => 0x26,
        "apostrophe" => 0x27,
        "parenleft" => 0x28,
        "parenright" => 0x29,
        "asterisk" => 0x2a,
        "plus" => 0x2b,
        "comma" => 0x2c,
        "minus" => 0x2d,
        "period" => 0x2e,
        "slash" | "fslash" => 0x2f,
        "colon" => 0x3a,
        "semicolon" => 0x3b,
        "less" => 0x3c,
        "equal" => 0x3d,
        "greater" => 0x3e,
        "question" => 0x3f,
        "at" => 0x40,
        "bracketleft" => 0x5b,
        "bslash" | "backslash" => 0x5c,
        "bracketright" => 0x5d,
        "asciicircum" => 0x5e,
        "underscore" => 0x5f,
        "grave" => 0x60,
        "braceleft" => 0x7b,
        "bar" => 0x7c,
        "braceright" => 0x7d,
        "asciitilde" => 0x7e,
        _ => {
            if let Some(number) = name.strip_prefix('f') {
                let number: u8 = number.parse().ok()?;
                if (1..=20).contains(&number) && name == format!("f{number}") {
                    return Some(0xffbd + u32::from(number));
                }
            }
            if let Some(number) = name.strip_prefix("kp_").or_else(|| name.strip_prefix("kp")) {
                if let [digit @ b'0'..=b'9'] = number.as_bytes() {
                    return Some(0xffb0 + u32::from(digit - b'0'));
                }
            }
            let [byte @ b'!'..=b'~'] = name.as_bytes() else {
                return None;
            };
            return Some(u32::from(byte.to_ascii_uppercase()));
        }
    };
    Some(named)
}

/// Per-chord mapping lifetime; input delivery stays in the existing engines.
pub(crate) struct NativeKeys {
    display: NonNull<x11::xlib::Display>,
    symbols: std::vec::IntoIter<u32>,
    pending: Option<u8>,
    shift: bool,
}

impl NativeKeys {
    pub(crate) fn new(key: Option<&str>) -> Result<Self, TargetedInputError> {
        let symbols = symbols(key)?;
        let display = super::open_display().map_err(|error| {
            if error.to_string() == "XOpenDisplay returned null" {
                targeted::failed("Keypresser::new failed xlib::XOpenDisplay")
            } else {
                targeted::failed(error)
            }
        })?;
        let display =
            NonNull::new(display).ok_or_else(|| targeted::failed("XOpenDisplay returned null"))?;
        Ok(Self {
            display,
            symbols: symbols.into_iter(),
            pending: None,
            shift: false,
        })
    }

    /// Resolve the next actual edge lazily, preserving partial-chord custody.
    pub(crate) fn next_code(&mut self) -> Result<Option<u8>, TargetedInputError> {
        if let Some(code) = self.pending.take() {
            return Ok(Some(code));
        }
        let Some(symbol) = self.symbols.next() else {
            return Ok(None);
        };
        let key_symbol = x11::xlib::KeySym::from(symbol);
        // SAFETY: this non-null display is owned here, used only by this
        // admitted blocking worker, and closed after all borrowed calls end.
        let code = unsafe { x11::xlib::XKeysymToKeycode(self.display.as_ptr(), key_symbol) };
        if code == 0 {
            return Err(targeted::failed(format!(
                "Keypresser::new failed xlib::XKeysymToKeycode keysym=0x{symbol:x}"
            )));
        }
        // SAFETY: the same live owned display and the server-provided keycode
        // are valid for Xlib's two source-defined column queries.
        let (plain, shifted) = unsafe {
            (
                x11::xlib::XKeycodeToKeysym(self.display.as_ptr(), code, 0),
                x11::xlib::XKeycodeToKeysym(self.display.as_ptr(), code, 1),
            )
        };
        if !(u32::from(b'A')..=u32::from(b'Z')).contains(&symbol)
            && !self.shift
            && plain != key_symbol
            && shifted == key_symbol
        {
            // SAFETY: query the source-defined Shift_L on the same live display.
            let shift =
                unsafe { x11::xlib::XKeysymToKeycode(self.display.as_ptr(), SHIFT_LEFT.into()) };
            if shift == 0 {
                return Err(targeted::failed(
                    "Keypresser::new failed xlib::XKeysymToKeycode for synthesized Shift",
                ));
            }
            self.shift = true;
            self.pending = Some(code);
            return Ok(Some(shift));
        }
        self.shift |= matches!(symbol, SHIFT_LEFT | SHIFT_RIGHT);
        Ok(Some(code))
    }
}

impl Drop for NativeKeys {
    fn drop(&mut self) {
        // SAFETY: this object is the unique owner of the display and cannot be
        // sent to another worker; no call survives this synchronous drop.
        unsafe {
            x11::xlib::XCloseDisplay(self.display.as_ptr());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_aliases_preserve_edges_and_refuse_generic_only_names() {
        assert_eq!(
            symbols(Some("XK_Control_L + Ctrl + a + A + XK_plus")).unwrap(),
            [0xffe3, 0xffe3, 0x41, 0x41, 0x2b]
        );
        assert_eq!(symbols(Some("++ + +")).unwrap(), [0x2b, 0x2b]);
        assert_eq!(symbols(Some("Ctrl+")).unwrap(), [0xffe3]);
        assert_eq!(symbols(Some("Ctrl++")).unwrap(), [0xffe3, 0x2b]);
        for name in [
            "cmd", "command", "control", "option", "capslock", "pageup", "arrowup", "F21", "F01",
            "KP10", "世界",
        ] {
            assert!(
                symbols(Some(name)).is_err(),
                "generic alias {name} must not broaden native input"
            );
        }
        assert_eq!(
            symbols(Some("F1+F20+KP_0+KP9")).unwrap(),
            [0xffbe, 0xffd1, 0xffb0, 0xffb9]
        );
        assert!(symbols(None).unwrap().is_empty());
        assert!(symbols(Some("  ")).unwrap().is_empty());
    }
}
