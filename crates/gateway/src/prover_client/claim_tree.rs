//! Invocation-local withdrawal tree. No persisted/cross-window cache or wire type.
use perp_core::{merkle::merkle_root, Digest};

/// Borrow the already hashed leaves and retain each parent level once. Parent
/// hashes use the native two-leaf root, keeping sorted-pair hashing in perp-core.
/// Unpaired nodes are promoted unchanged, including at intermediate levels.
pub(super) struct ClaimTree<'a> {
    leaves: &'a [Digest],
    parents: Vec<Vec<Digest>>,
}

impl<'a> ClaimTree<'a> {
    pub(super) fn new(leaves: &'a [Digest]) -> Self {
        let mut parents: Vec<Vec<Digest>> = Vec::new();
        loop {
            let level = parents.last().map_or(leaves, Vec::as_slice);
            if level.len() <= 1 {
                break;
            }
            let (pairs, unpaired) = level.as_chunks::<2>();
            let mut next = Vec::with_capacity(level.len().div_ceil(2));
            next.extend(pairs.iter().map(|pair| merkle_root(pair)));
            next.extend_from_slice(unpaired);
            parents.push(next);
        }
        Self { leaves, parents }
    }

    pub(super) fn root(&self) -> Digest {
        self.parents
            .last()
            .map_or(self.leaves, Vec::as_slice)
            .first()
            .copied()
            .unwrap_or([0; 32])
    }

    /// Called only for indices enumerated from these leaves; no external index.
    pub(super) fn proof(&self, mut index: usize) -> Vec<Digest> {
        assert!(
            index < self.leaves.len(),
            "claim index outside local leaves"
        );
        let mut path = Vec::with_capacity(self.parents.len());
        for level in std::iter::once(self.leaves).chain(self.parents.iter().map(Vec::as_slice)) {
            if level.len() == 1 {
                break;
            }
            if let Some(sibling) = level.get(index ^ 1) {
                path.push(*sibling);
            }
            index /= 2;
        }
        path
    }
}
