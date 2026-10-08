use mpz_memory_core::{Slice, View as ViewTrait, binary::Binary, view::VisibilityView};
use rangeset::{iter::RangeIterator, ops::Set};
use serde::{Deserialize, Serialize};

type Range = std::ops::Range<usize>;
type RangeSet = rangeset::set::RangeSet<usize>;
type Result<T, E = ViewError> = core::result::Result<T, E>;

#[derive(Debug, Default)]
struct InputView {
    /// Ranges which have been assigned.
    assigned: RangeSet,
    /// Ranges which are fully committed in both parties' views.
    complete: RangeSet,
    /// All input ranges.
    all: RangeSet,
}

#[derive(Debug, Default)]
struct OutputView {
    /// Ranges which have been computed and thus are fully committed in both
    /// parties' views.
    complete: RangeSet,
    /// All output ranges.
    all: RangeSet,
}

/// A view into the decoded ranges.
///
/// A range is considered decoded when its value becomes known to both parties.
#[derive(Debug, Default)]
struct DecodeView {
    /// Ranges which have already been decoded.
    complete: RangeSet,
    /// All ranges which are to be decoded.
    all: RangeSet,
}

#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct FlushView {
    /// Ranges which the Prover is to commit.
    pub(crate) commit: RangeSet,
    /// Ranges which the Prover is to prove.
    pub(crate) prove: RangeSet,
}

impl FlushView {
    /// Returns `true` if the state is empty.
    pub(crate) fn is_empty(&self) -> bool {
        self.commit.is_empty() && self.prove.is_empty()
    }

    pub(crate) fn clear(&mut self) {
        self.commit.clear();
        self.prove.clear();
    }
}

#[derive(Debug, Clone, Copy)]
enum Role {
    Prover,
    Verifier,
}

#[derive(Debug)]
pub(crate) struct View {
    role: Role,
    len: usize,
    input: InputView,
    output: OutputView,
    vis: VisibilityView,
    decode: DecodeView,
    flush: FlushView,
}

impl View {
    pub(crate) fn new_prover() -> Self {
        Self {
            role: Role::Prover,
            len: 0,
            input: InputView::default(),
            output: OutputView::default(),
            vis: VisibilityView::new(),
            decode: DecodeView::default(),
            flush: FlushView::default(),
        }
    }

    pub(crate) fn new_verifier() -> Self {
        Self {
            role: Role::Verifier,
            len: 0,
            input: InputView::default(),
            output: OutputView::default(),
            vis: VisibilityView::new(),
            decode: DecodeView::default(),
            flush: FlushView::default(),
        }
    }

    pub(crate) fn visibility(&self) -> &VisibilityView {
        &self.vis
    }

    pub(crate) fn is_alloc(&self, range: Range) -> bool {
        range.end <= self.len
    }

    fn alloc(&mut self, size: usize) -> Range {
        let range = self.len..self.len + size;
        self.len += size;
        self.vis.alloc(size);
        range
    }

    pub(crate) fn wants_flush(&self) -> bool {
        !self.flush.is_empty()
    }

    pub(crate) fn flush(&self) -> &FlushView {
        &self.flush
    }

    pub(crate) fn alloc_input(&mut self, size: usize) {
        let range = self.alloc(size);

        self.input.all |= &range;
    }

    pub(crate) fn alloc_output(&mut self, size: usize) {
        let range = self.alloc(size);

        self.output.all |= &range;
    }

    fn mark_public(&mut self, range: Range) -> Result<()> {
        if self.vis.is_set_any(range.clone()) {
            return Err(ErrorRepr::VisibilityAlreadySet { range }.into());
        } else if !range.is_disjoint(&self.output.all) {
            return Err(ErrorRepr::VisibilityOutput { range }.into());
        }

        self.vis.set_public(range);

        Ok(())
    }

    fn mark_private(&mut self, range: Range) -> Result<()> {
        if self.vis.is_set_any(range.clone()) {
            return Err(ErrorRepr::VisibilityAlreadySet { range }.into());
        } else if !range.is_disjoint(&self.output.all) {
            return Err(ErrorRepr::VisibilityOutput { range }.into());
        }

        self.vis.set_private(range);

        Ok(())
    }

    fn mark_blind(&mut self, range: Range) -> Result<()> {
        if self.vis.is_set_any(range.clone()) {
            return Err(ErrorRepr::VisibilityAlreadySet { range }.into());
        } else if !range.is_disjoint(&self.output.all) {
            return Err(ErrorRepr::VisibilityOutput { range }.into());
        }

        self.vis.set_blind(range);

        Ok(())
    }

    pub(crate) fn assign(&mut self, range: Range) -> Result<()> {
        if !self.vis.is_visible(range.clone()) {
            return Err(ErrorRepr::VisibilityAssign { range }.into());
        } else if !range.is_disjoint(&self.output.all) {
            return Err(ErrorRepr::OutputAssign { range }.into());
        }

        self.input.assigned |= &range;

        Ok(())
    }

    /// Marks an output range as complete.
    pub(crate) fn set_output(&mut self, range: Range) -> Result<()> {
        // Assert is output.
        if !range.is_subset(&self.output.all) {
            return Err(ErrorRepr::NotOutput { range }.into());
        }

        self.output.complete |= &range;
        // If marked for decoding, prove MACs.
        self.flush.prove |= range.intersection(&self.decode.all);

        Ok(())
    }

    pub(crate) fn is_committed(&self, range: Range) -> bool {
        range.is_subset(&self.input.complete) || range.is_subset(&self.output.complete)
    }

    pub(crate) fn commit(&mut self, range: Range) -> Result<()> {
        // Assert visibility is set.
        if !self.vis.is_set(range.clone()) {
            return Err(ErrorRepr::VisibilityNotSet { range }.into());
        }

        // Assert not output data.
        if !range.is_disjoint(&self.output.all) {
            return Err(ErrorRepr::OutputCommit { range }.into());
        }

        // Assert not committed.
        if !range.is_disjoint(&self.input.complete) {
            return Err(ErrorRepr::AlreadyCommitted { range }.into());
        }

        let blind = range.intersection(self.vis.blind()).into_set();
        let private = range.intersection(self.vis.private()).into_set();
        let public = range.intersection(self.vis.public()).into_set();

        // Assert data is assigned.
        if !public.is_subset(&self.input.assigned) || !private.is_subset(&self.input.assigned) {
            return Err(ErrorRepr::NotAssigned { range }.into());
        }

        // Mark as complete if public.
        self.input.complete |= public;

        match self.role {
            Role::Prover => {
                self.flush.commit |= private;
            }
            Role::Verifier => {
                self.flush.commit |= blind;
            }
        }

        Ok(())
    }

    // Stages a to-be-decoded `range` for proving.
    pub(crate) fn decode(&mut self, range: Range) -> Result<()> {
        // Ignore already decoded data.
        let undecoded = range.difference(&self.decode.complete).into_set();
        if undecoded.is_empty() {
            return Ok(());
        }

        self.decode.all |= &undecoded;

        let input = undecoded.intersection(&self.input.all);
        let output = undecoded.intersection(&self.output.all);

        match self.role {
            Role::Prover => {
                self.flush.prove |= input
                    .intersection(self.vis.private())
                    .intersection(&self.input.complete)
                    .union(output.intersection(&self.output.complete));
            }
            Role::Verifier => {
                self.flush.prove |= input
                    .difference(self.vis.visible())
                    .intersection(&self.input.complete)
                    .union(output.intersection(&self.output.complete));
            }
        };

        Ok(())
    }

    pub(crate) fn complete_flush(&mut self, view: FlushView) {
        // We don't allow outputs to be explicitely committed, only inputs.
        self.input.complete |= &view.commit;
        // Since the verifier learned the plaintext of the proven ranges, those
        // ranges are now decoded.
        self.decode.complete |= &view.prove;

        self.flush.clear();

        // Those to-be-decoded inputs which were committed can be proven now.
        self.flush.prove |= view.commit.intersection(&self.decode.all);
    }
}

impl ViewTrait<Binary> for View {
    type Error = ViewError;

    fn mark_public_raw(&mut self, slice: Slice) -> Result<(), Self::Error> {
        self.mark_public(slice.to_range())
    }

    fn mark_private_raw(&mut self, slice: Slice) -> Result<(), Self::Error> {
        self.mark_private(slice.to_range())
    }

    fn mark_blind_raw(&mut self, slice: Slice) -> Result<(), Self::Error> {
        self.mark_blind(slice.to_range())
    }
}

#[derive(Debug, thiserror::Error)]
#[error(transparent)]
pub(crate) struct ViewError(#[from] ErrorRepr);

#[derive(Debug, thiserror::Error)]
enum ErrorRepr {
    #[error("visibility not set: {range:?}")]
    VisibilityNotSet { range: Range },
    #[error("visibility already set: {range:?}")]
    VisibilityAlreadySet { range: Range },
    #[error("assigning blind data is not allowed: {range:?}")]
    VisibilityAssign { range: Range },
    #[error("setting visibility of output is not allowed: {range:?}")]
    VisibilityOutput { range: Range },
    #[error("must assign visible data: {range:?}")]
    NotAssigned { range: Range },
    #[error("already committed: {range:?}")]
    AlreadyCommitted { range: Range },
    #[error("assigning to output is not allowed: {range:?}")]
    OutputAssign { range: Range },
    #[error("committing output is not allowed: {range:?}")]
    OutputCommit { range: Range },
    #[error("attempted to treat input as output: {range:?}")]
    NotOutput { range: Range },
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::*;

    fn new(role: Role) -> View {
        match role {
            Role::Prover => View::new_prover(),
            Role::Verifier => View::new_verifier(),
        }
    }

    #[rstest]
    #[case::prover(Role::Prover)]
    #[case::verifier(Role::Verifier)]
    fn test_is_alloc(#[case] role: Role) {
        let mut view = new(role);

        view.alloc_input(10);

        assert!(view.is_alloc(0..10));
    }

    #[rstest]
    #[case::prover(Role::Prover)]
    #[case::verifier(Role::Verifier)]
    fn test_assign_blind(#[case] role: Role) {
        let mut view = new(role);

        view.alloc_input(10);
        view.mark_blind(0..10).unwrap();
        let err = view.assign(0..10).unwrap_err().0;

        assert!(matches!(err, ErrorRepr::VisibilityAssign { .. }));
    }

    #[rstest]
    #[case::prover(Role::Prover)]
    #[case::verifier(Role::Verifier)]
    fn test_assign_output(#[case] role: Role) {
        let mut view = new(role);

        view.alloc_output(10);
        // Bypass the visibility guard.
        view.vis.set_public(0..10);

        let err = view.assign(0..10).unwrap_err().0;

        assert!(matches!(err, ErrorRepr::OutputAssign { .. }));
    }

    #[rstest]
    #[case::prover(Role::Prover)]
    #[case::verifier(Role::Verifier)]
    fn test_commit_before_visibility(#[case] role: Role) {
        let mut view = new(role);

        view.alloc_input(10);
        let err = view.commit(0..10).unwrap_err().0;

        assert!(matches!(err, ErrorRepr::VisibilityNotSet { .. }));
    }

    #[rstest]
    #[case::prover(Role::Prover)]
    #[case::verifier(Role::Verifier)]
    fn test_commit_output(#[case] role: Role) {
        let mut view = new(role);

        view.alloc_output(10);
        // Bypass the visibility guard.
        view.vis.set_public(0..10);

        let err = view.commit(0..10).unwrap_err().0;

        assert!(matches!(err, ErrorRepr::OutputCommit { .. }));
    }

    #[rstest]
    #[case::prover(Role::Prover)]
    #[case::verifier(Role::Verifier)]
    fn test_public_commit_no_flush(#[case] role: Role) {
        let mut view = new(role);

        view.alloc_input(10);
        view.mark_public(0..10).unwrap();
        view.assign(0..10).unwrap();
        view.commit(0..10).unwrap();

        assert!(!view.wants_flush());
    }

    #[test]
    fn test_private_commit_wants_flush() {
        let mut view = new(Role::Prover);

        view.alloc_input(10);
        view.mark_private(0..10).unwrap();
        view.assign(0..10).unwrap();
        view.commit(0..10).unwrap();

        assert!(view.wants_flush());
    }

    #[test]
    fn test_blind_commit_wants_flush() {
        let mut view = new(Role::Verifier);

        view.alloc_input(10);
        view.mark_blind(0..10).unwrap();
        view.commit(0..10).unwrap();

        assert!(view.wants_flush());
    }

    #[rstest]
    #[case::prover(Role::Prover)]
    #[case::verifier(Role::Verifier)]
    fn test_output_wants_flush(#[case] role: Role) {
        let mut view = new(role);

        view.alloc_output(10);
        view.decode(0..10).unwrap();
        view.set_output(0..10).unwrap();

        assert!(view.wants_flush());
    }
}
