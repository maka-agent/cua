//! Ordered screen selection after native rectangle intersections are measured.

pub(super) fn largest_area_index(areas: impl IntoIterator<Item = f64>) -> Option<usize> {
    let mut winner = None;
    for (index, area) in areas.into_iter().enumerate() {
        if winner.is_none_or(|(_, best)| area > best) {
            winner = Some((index, area));
        }
    }
    winner.map(|(index, _)| index)
}

#[cfg(test)]
mod tests {
    use super::largest_area_index;

    #[test]
    fn greatest_intersection_wins_and_ties_keep_the_first_screen() {
        assert_eq!(largest_area_index([60.0, 180.0, 120.0]), Some(1));
        assert_eq!(largest_area_index([180.0, 180.0, 60.0]), Some(0));
        assert_eq!(largest_area_index([60.0, 180.0, 180.0]), Some(1));
    }

    #[test]
    fn no_overlap_keeps_first_screen_but_no_screens_has_no_winner() {
        assert_eq!(largest_area_index([0.0, 0.0, 0.0]), Some(0));
        assert_eq!(largest_area_index([]), None);
    }

    #[test]
    fn unordered_areas_do_not_replace_the_current_winner() {
        assert_eq!(largest_area_index([20.0, f64::NAN, 40.0]), Some(2));
        assert_eq!(largest_area_index([f64::NAN, 40.0]), Some(0));
    }
}
