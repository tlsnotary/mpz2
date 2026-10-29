use rangeset::ops::Set;
use serde::{Deserialize, Serialize};

use crate::{Range, RangeSet};

/// Visibility of memory.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VisibilityView {
    len: usize,
    uninit: RangeSet,
    public: RangeSet,
    private: RangeSet,
    blind: RangeSet,
    visible: RangeSet,
}

impl VisibilityView {
    /// Creates a new view.
    pub fn new() -> Self {
        Self::default()
    }

    /// Allocates memory.
    pub fn alloc(&mut self, len: usize) {
        let end = self.len;
        self.len += len;
        self.uninit |= end..end + len;
    }

    /// Returns the public ranges.
    pub fn public(&self) -> &RangeSet {
        &self.public
    }

    /// Returns the private ranges.
    pub fn private(&self) -> &RangeSet {
        &self.private
    }

    /// Returns the blind ranges.
    pub fn blind(&self) -> &RangeSet {
        &self.blind
    }

    /// Returns the visible ranges (i.e. all the ranges except for the blind
    /// ones).
    pub fn visible(&self) -> &RangeSet {
        &self.visible
    }

    /// Returns `true` if all data in the range is allocated and set.
    pub fn is_set(&self, range: Range) -> bool {
        range.end <= self.len && range.is_disjoint(&self.uninit)
    }

    /// Returns `true` if any allocated data in the range is set.
    pub fn is_set_any(&self, range: Range) -> bool {
        let start = range.start.min(self.len);
        let end = range.end.min(self.len);

        start < end && (start..end).difference(&self.uninit).next().is_some()
    }

    /// Returns `true` if all data in the range is visible.
    pub fn is_visible(&self, range: Range) -> bool {
        range.is_subset(&self.visible)
    }

    /// Returns `true` if any data in the range is visible.
    pub fn is_visible_any(&self, range: Range) -> bool {
        !range.is_disjoint(&self.visible)
    }

    /// Returns `true` if all data in the range is public.
    pub fn is_public(&self, range: Range) -> bool {
        range.is_subset(&self.public)
    }

    /// Returns `true` if any data in the range is public.
    pub fn is_public_any(&self, range: Range) -> bool {
        !range.is_disjoint(&self.public)
    }

    /// Returns `true` if all data in the range is private.
    pub fn is_private(&self, range: Range) -> bool {
        range.is_subset(&self.private)
    }

    /// Returns `true` if any data in the range is private.
    pub fn is_private_any(&self, range: Range) -> bool {
        !range.is_disjoint(&self.private)
    }

    /// Returns `true` if all data in the range is blind.
    pub fn is_blind(&self, range: Range) -> bool {
        range.is_subset(&self.blind)
    }

    /// Returns `true` if any data in the range is blind.
    pub fn is_blind_any(&self, range: Range) -> bool {
        !range.is_disjoint(&self.blind)
    }

    /// Asserts that the range is within allocated memory.
    fn assert_allocated(&self, range: &Range) {
        assert!(
            range.end <= self.len,
            "range {range:?} exceeds allocated memory of length {}",
            self.len
        );
    }

    /// Sets the range as public.
    pub fn set_public(&mut self, range: Range) {
        self.assert_allocated(&range);

        self.public |= &range;
        self.visible |= &range;
        self.uninit -= &range;
        self.private -= &range;
        self.blind -= &range;
    }

    /// Sets the range as private.
    pub fn set_private(&mut self, range: Range) {
        self.assert_allocated(&range);

        self.private |= &range;
        self.visible |= &range;
        self.uninit -= &range;
        self.public -= &range;
        self.blind -= &range;
    }

    /// Sets the range as blind.
    pub fn set_blind(&mut self, range: Range) {
        self.assert_allocated(&range);

        self.blind |= &range;
        self.visible -= &range;
        self.uninit -= &range;
        self.public -= &range;
        self.private -= &range;
    }

    /// Returns an iterator over the public ranges.
    pub fn iter_public(&self) -> impl Iterator<Item = Range> + '_ {
        self.public.iter()
    }

    /// Returns an iterator over the private ranges.
    pub fn iter_private(&self) -> impl Iterator<Item = Range> + '_ {
        self.private.iter()
    }

    /// Returns an iterator over the blind ranges.
    pub fn iter_blind(&self) -> impl Iterator<Item = Range> + '_ {
        self.blind.iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_view() {
        let mut view = VisibilityView::new();
        view.alloc(30);

        assert!(!view.is_set(0..10));
        assert!(!view.is_set_any(0..10));

        view.set_public(0..10);
        view.set_private(10..20);
        view.set_blind(20..30);

        assert!(view.is_public(0..10));
        assert!(view.is_private(10..20));
        assert!(view.is_blind(20..30));
    }

    #[test]
    fn test_mutually_exclusive() {
        let mut view = VisibilityView::new();
        view.alloc(15);

        view.set_public(0..10);
        view.set_private(5..15);

        assert!(view.is_public(0..5));
        assert!(view.is_private(5..15));

        view.set_blind(5..10);

        assert!(view.is_blind(5..10));
        assert!(!view.is_public(0..10));
        assert!(!view.is_private(5..15));
    }

    #[test]
    fn unallocated_range_is_not_set() {
        let mut view = VisibilityView::new();
        view.alloc(10);
        view.set_public(0..10);

        assert!(view.is_set(0..10));
        assert!(view.is_set_any(0..10));

        // Fully out of bounds.
        assert!(!view.is_set(10..20));
        assert!(!view.is_set_any(10..20));

        // Partially out of bounds: the allocated prefix is set, but not all
        // of the range is.
        assert!(!view.is_set(5..15));
        assert!(view.is_set_any(5..15));
    }

    #[test]
    #[should_panic(expected = "exceeds allocated memory")]
    fn setting_visibility_out_of_bounds_panics() {
        let mut view = VisibilityView::new();
        view.alloc(10);

        view.set_public(10..20);
    }
}
