//! Floating page distances for the native macOS event path.

use std::fmt;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PageDirection {
    Up,
    Down,
    Left,
    Right,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeltaError {
    InvalidPages,
    UnrepresentableDelta,
}

impl fmt::Display for DeltaError {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        output.write_str(match self {
            Self::InvalidPages => "page distance must be positive and finite",
            Self::UnrepresentableDelta => {
                "unsupported_native_delta: page distance cannot be represented by native scroll event fields"
            }
        })
    }
}

impl std::error::Error for DeltaError {}

/// Convert positive finite pages into one native `(delta_x, delta_y)` pair.
///
/// `extent` is the selected frame's height for vertical input and width for
/// horizontal input. The native recipe rounds the product to the nearest
/// integer, with ties away from zero. Representability is checked after the
/// direction is applied: the negative Int32 endpoint has one extra magnitude.
pub fn page_deltas(
    direction: PageDirection,
    pages: f64,
    extent: f64,
) -> Result<(i32, i32), DeltaError> {
    if !pages.is_finite() || pages <= 0.0 {
        return Err(DeltaError::InvalidPages);
    }
    if !extent.is_finite() {
        return Err(DeltaError::UnrepresentableDelta);
    }
    let rounded = (pages * extent.max(100.0)).round();
    // i64::MAX rounds up to 2^63 when converted to f64. Use that exclusive
    // endpoint explicitly before Rust's saturating float-to-integer cast.
    if !rounded.is_finite() || rounded >= 9_223_372_036_854_775_808.0 {
        return Err(DeltaError::UnrepresentableDelta);
    }
    let magnitude = rounded as i64;
    let (x, y) = match direction {
        PageDirection::Up => (0, magnitude),
        PageDirection::Down => (0, -magnitude),
        PageDirection::Left => (-magnitude, 0),
        PageDirection::Right => (magnitude, 0),
    };
    Ok((
        i32::try_from(x).map_err(|_| DeltaError::UnrepresentableDelta)?,
        i32::try_from(y).map_err(|_| DeltaError::UnrepresentableDelta)?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fractional_pages_keep_zero_and_round_half_away_from_zero() {
        assert_eq!(page_deltas(PageDirection::Up, 0.0049, 100.0), Ok((0, 0)));
        assert_eq!(page_deltas(PageDirection::Up, 0.005, 100.0), Ok((0, 1)));
        assert_eq!(page_deltas(PageDirection::Down, 0.015, 100.0), Ok((0, -2)));
        assert_eq!(page_deltas(PageDirection::Left, 0.5, 1080.0), Ok((-540, 0)));
    }

    #[test]
    fn selected_extent_has_a_hundred_point_floor_without_a_page_cap() {
        assert_eq!(page_deltas(PageDirection::Up, 0.25, 20.0), Ok((0, 25)));
        assert_eq!(page_deltas(PageDirection::Up, 0.25, 200.0), Ok((0, 50)));
        assert_eq!(page_deltas(PageDirection::Up, 51.0, 100.0), Ok((0, 5100)));
    }

    #[test]
    fn all_four_directions_preserve_native_axis_and_sign() {
        assert_eq!(page_deltas(PageDirection::Up, 0.5, 200.0), Ok((0, 100)));
        assert_eq!(page_deltas(PageDirection::Down, 0.5, 200.0), Ok((0, -100)));
        assert_eq!(page_deltas(PageDirection::Left, 0.5, 200.0), Ok((-100, 0)));
        assert_eq!(page_deltas(PageDirection::Right, 0.5, 200.0), Ok((100, 0)));
    }

    #[test]
    fn int32_negative_endpoint_is_available_only_in_negative_directions() {
        let pages = 21_474_836.48;
        assert_eq!(
            page_deltas(PageDirection::Down, pages, 100.0),
            Ok((0, i32::MIN))
        );
        assert_eq!(
            page_deltas(PageDirection::Left, pages, 100.0),
            Ok((i32::MIN, 0))
        );
        assert_eq!(
            page_deltas(PageDirection::Up, pages, 100.0),
            Err(DeltaError::UnrepresentableDelta)
        );
        assert_eq!(
            page_deltas(PageDirection::Right, pages, 100.0),
            Err(DeltaError::UnrepresentableDelta)
        );
    }

    #[test]
    fn valid_positive_pages_can_exceed_native_representation() {
        for pages in [f64::MAX, 92_233_720_368_547_760.0] {
            assert_eq!(
                page_deltas(PageDirection::Down, pages, 100.0),
                Err(DeltaError::UnrepresentableDelta)
            );
        }
        for extent in [f64::NAN, f64::INFINITY] {
            assert_eq!(
                page_deltas(PageDirection::Up, 1.0, extent),
                Err(DeltaError::UnrepresentableDelta)
            );
        }
    }

    #[test]
    fn nonpositive_or_nonfinite_pages_have_the_domain_error() {
        for pages in [0.0, -0.0, -1.0, f64::NAN, f64::INFINITY] {
            assert_eq!(
                page_deltas(PageDirection::Up, pages, 100.0),
                Err(DeltaError::InvalidPages)
            );
        }
    }
}
