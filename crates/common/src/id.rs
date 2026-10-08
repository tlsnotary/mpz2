use core::fmt;

/// A logical context identifier.
///
/// Hierarchical: each level is a `u32` index, serialized big-endian. Both
/// parties derive identical IDs by following the same call sequence.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ContextId(Box<[u8]>);

impl ContextId {
    const LEVEL_BYTES: usize = 4;

    /// Creates a context ID at the top level with the given index.
    #[inline]
    pub fn new(index: u32) -> Self {
        Self(index.to_be_bytes().to_vec().into())
    }

    /// Creates a context ID from an arbitrary byte prefix.
    ///
    /// Useful for namespacing contexts under a caller-chosen identifier (e.g.
    /// a sub-protocol name). Forked children are appended to this prefix
    /// using the standard hierarchical layout.
    #[inline]
    pub fn from_prefix(prefix: impl AsRef<[u8]>) -> Self {
        Self(prefix.as_ref().to_vec().into())
    }

    /// Returns the ID as a byte slice.
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Descends into a child namespace at the given index.
    #[inline]
    pub fn child(&self, index: u32) -> Self {
        let mut bytes = Vec::with_capacity(self.0.len() + Self::LEVEL_BYTES);
        bytes.extend_from_slice(&self.0);
        bytes.extend_from_slice(&index.to_be_bytes());
        Self(bytes.into())
    }
}

impl Default for ContextId {
    fn default() -> Self {
        Self::new(0)
    }
}

impl AsRef<[u8]> for ContextId {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl fmt::Display for ContextId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, chunk) in self.0.chunks(Self::LEVEL_BYTES).enumerate() {
            if i > 0 {
                write!(f, "/")?;
            }
            let mut buf = [0u8; 4];
            buf[..chunk.len()].copy_from_slice(chunk);
            write!(f, "{}", u32::from_be_bytes(buf))?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_context_id() {
        let id = ContextId::default();
        assert_eq!(id.as_bytes(), &[0, 0, 0, 0]);

        let child0 = id.child(0);
        let child1 = id.child(1);
        assert_ne!(child0, child1);
        assert_eq!(child0.as_bytes(), &[0, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(child1.as_bytes(), &[0, 0, 0, 0, 0, 0, 0, 1]);

        let grand = child0.child(7);
        assert_eq!(grand.as_bytes(), &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7]);
    }
}
