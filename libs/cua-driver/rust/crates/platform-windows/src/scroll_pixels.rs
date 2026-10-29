//! Numeric conversion for the Windows coordinate-scroll wheel route.
//!
//! This is separate from the portable line/page detent contract. The original
//! native parser's full JSON integer range is not established; this adapter
//! accepts the rounded signed 32-bit domain used by the observed wheel caller.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct WheelPacket {
    pub delta: i32,
    pub horizontal: bool,
}

/// JavaScript Math.round rounds a negative half toward positive infinity.
/// Testing the fractional part also avoids rounding 0.49999999999999994 up.
pub(crate) fn js_round_i32(value: f64) -> Result<i32, &'static str> {
    if !value.is_finite() {
        return Err("scroll coordinates and pixels must be finite numbers");
    }
    let floor = value.floor();
    let rounded = if value - floor >= 0.5 {
        floor + 1.0
    } else {
        floor
    };
    if !(f64::from(i32::MIN)..=f64::from(i32::MAX)).contains(&rounded) {
        return Err(
            "unsupported: rounded scroll input is outside the supported signed 32-bit domain",
        );
    }
    Ok(rounded as i32)
}

/// Sign the public distance before rounding, then use the Win32 wheel Y sign.
pub(crate) fn directional_deltas(direction: &str, pixels: f64) -> Result<(i32, i32), &'static str> {
    match direction {
        "up" => Ok((0, js_round_i32(-pixels)?.wrapping_neg())),
        "down" => Ok((0, js_round_i32(pixels)?.wrapping_neg())),
        "left" => Ok((js_round_i32(-pixels)?, 0)),
        "right" => Ok((js_round_i32(pixels)?, 0)),
        _ => Err("scroll direction must be up, down, left, or right"),
    }
}

/// Preserve the Windows raw client's signed two-axis request in one wheel batch.
/// Its Y coordinate convention is opposite to the Win32 vertical wheel sign.
#[cfg(target_os = "windows")]
pub(crate) fn signed_deltas(scroll_x: f64, scroll_y: f64) -> Result<(i32, i32), &'static str> {
    Ok((
        js_round_i32(scroll_x)?,
        js_round_i32(scroll_y)?.wrapping_neg(),
    ))
}

/// One native submission, with vertical before horizontal and no detent scale.
pub(crate) fn wheel_packets(delta_x: i32, delta_y: i32) -> Vec<WheelPacket> {
    [(delta_y, false), (delta_x, true)]
        .into_iter()
        .filter(|(delta, _)| *delta != 0)
        .map(|(delta, horizontal)| WheelPacket {
            delta: delta.clamp(-32768, 32767),
            horizontal,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rounds_signed_distances_before_win32_direction_conversion() {
        assert_eq!(directional_deltas("down", 0.5), Ok((0, -1)));
        assert_eq!(directional_deltas("up", 0.5), Ok((0, 0)));
        assert_eq!(directional_deltas("right", 0.5), Ok((1, 0)));
        assert_eq!(directional_deltas("left", 0.5), Ok((0, 0)));
        assert_eq!(directional_deltas("down", -1.5), Ok((0, 1)));
        assert_eq!(directional_deltas("right", -1.5), Ok((-1, 0)));
        assert_eq!(directional_deltas("up", 800.0), Ok((0, 800)));
        assert_eq!(js_round_i32(0.49999999999999994), Ok(0));
        assert_eq!(js_round_i32(-0.0), Ok(0));
        assert_eq!(js_round_i32(-0.5), Ok(0));
        assert_eq!(js_round_i32(-1.5), Ok(-1));
    }

    #[test]
    fn refuses_unestablished_numeric_domain_without_an_arbitrary_pixel_cap() {
        for value in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
            assert!(js_round_i32(value).is_err());
        }
        assert_eq!(js_round_i32(f64::from(i32::MIN)), Ok(i32::MIN));
        assert_eq!(js_round_i32(f64::from(i32::MAX)), Ok(i32::MAX));
        assert!(js_round_i32(f64::from(i32::MAX) + 0.5).is_err());
        assert!(js_round_i32(f64::from(i32::MIN) - 1.0).is_err());
        assert!(directional_deltas("diagonal", 1.0).is_err());
    }

    #[test]
    fn plans_one_vertical_then_horizontal_batch_with_native_delta_bounds() {
        assert_eq!(
            wheel_packets(800, -800),
            vec![
                WheelPacket {
                    delta: -800,
                    horizontal: false
                },
                WheelPacket {
                    delta: 800,
                    horizontal: true
                },
            ]
        );
        assert_eq!(
            wheel_packets(i32::MAX, i32::MIN),
            vec![
                WheelPacket {
                    delta: -32768,
                    horizontal: false
                },
                WheelPacket {
                    delta: 32767,
                    horizontal: true
                },
            ]
        );
        assert!(wheel_packets(0, 0).is_empty());
        assert_eq!(
            wheel_packets(-1, 0),
            vec![WheelPacket {
                delta: -1,
                horizontal: true
            }]
        );
    }
}
