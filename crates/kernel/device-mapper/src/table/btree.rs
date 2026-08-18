//! The table's sector index: an implicit B-tree of high-sector keys.
//!
//! A table can hold thousands of targets — a volume group with many extents
//! produces one per extent — so the target covering a sector is found by
//! descending a tree of "highest sector in this subtree" keys rather than by
//! walking the list. The leaf layer IS the per-target high-sector array; the
//! internal layers are built on top of it, bottom up.

extern crate alloc;
use alloc::vec::Vec;

/// Keys held in one node. The reference sizes a node to a cache line and a key
/// to a sector number, which is eight keys of eight bytes.
pub const KEYS_PER_NODE: usize = 8;
/// Children hanging off one node: one more than its keys.
pub const CHILDREN_PER_NODE: usize = KEYS_PER_NODE + 1;

/// Ceiling of `n / d`, for the node counts at each layer. # C: O(1)
const fn div_up(n: usize, d: usize) -> usize { n.div_ceil(d) }

/// Number of times `n` must be divided by `base` to reach one — the count of
/// internal layers a leaf layer of `n` nodes needs above it. # C: O(log n)
fn int_log(mut n: usize, base: usize) -> usize {
    let mut result = 0;
    while n > 1 { n = div_up(n, base); result += 1; }
    result
}

/// The built index. Layer `depth - 1` is the leaf layer and aliases the
/// per-target high-sector array; layers below it are internal.
pub struct Index {
    /// Key arrays, outermost layer first, leaf layer last.
    layers: Vec<Vec<u64>>,
    /// Nodes present in each layer, parallel to `layers`.
    counts: Vec<usize>,
    /// Number of targets the leaf layer indexes.
    num_targets: usize,
}

impl Index {
    /// Build the index over `highs`, the last sector each target covers, in
    /// table order. # C: O(N_targets)
    pub fn build(highs: &[u64]) -> Self {
        let num_targets = highs.len();
        let leaf_nodes = div_up(num_targets, KEYS_PER_NODE).max(1);
        let depth = 1 + int_log(leaf_nodes, CHILDREN_PER_NODE);

        // The leaf layer is the high-sector array padded out to a whole
        // number of nodes. The padding value is the largest sector there is,
        // so a descent that reaches a padded key never selects it in
        // preference to a real one.
        let mut leaf = highs.to_vec();
        while leaf.len() % KEYS_PER_NODE != 0 || leaf.is_empty() { leaf.push(u64::MAX); }

        let mut layers: Vec<Vec<u64>> = alloc::vec![Vec::new(); depth];
        let mut counts = alloc::vec![0usize; depth];
        counts[depth - 1] = leaf_nodes;
        layers[depth - 1] = leaf;

        // Internal layers, bottom up: each key is the highest sector reachable
        // through the child it points at, and a child past the end of its
        // layer reads as the largest sector there is.
        for l in (0..depth.saturating_sub(1)).rev() {
            counts[l] = div_up(counts[l + 1], CHILDREN_PER_NODE);
            let mut node_keys = alloc::vec![u64::MAX; counts[l] * KEYS_PER_NODE];
            for n in 0..counts[l] {
                for k in 0..KEYS_PER_NODE {
                    node_keys[n * KEYS_PER_NODE + k] = high(&layers, &counts, l + 1, get_child(n, k));
                }
            }
            layers[l] = node_keys;
        }

        Self { layers, counts, num_targets }
    }

    /// Index of the target covering `sector`, or `None` past the end of the
    /// table. `size` is the table's total length in sectors. # C: O(log N)
    pub fn find(&self, sector: u64, size: u64) -> Option<usize> {
        if sector >= size { return None; }
        let depth = self.counts.len();
        let mut n = 0usize;
        let mut k = 0usize;
        for l in 0..depth {
            n = get_child(n, k);
            let node = &self.layers[l][n * KEYS_PER_NODE..(n + 1) * KEYS_PER_NODE];
            k = KEYS_PER_NODE;
            for (i, key) in node.iter().enumerate() {
                if *key >= sector { k = i; break; }
            }
        }
        let idx = KEYS_PER_NODE * n + k;
        if idx < self.num_targets { Some(idx) } else { None }
    }

    /// Layers in the built tree. # C: O(1)
    pub fn depth(&self) -> usize { self.counts.len() }
}

/// Index of the `k`th child of node `n`. # C: O(1)
const fn get_child(n: usize, k: usize) -> usize { n * CHILDREN_PER_NODE + k }

/// Highest sector reachable through node `n` of layer `l`: follow the last
/// child down to the leaf layer and take that node's last key. A node past the
/// end of its layer covers nothing, so it reads as the largest sector there is
/// and never wins a comparison against a real key.
fn high(layers: &[Vec<u64>], counts: &[usize], mut l: usize, mut n: usize) -> u64 {
    let depth = counts.len();
    while l < depth - 1 { n = get_child(n, CHILDREN_PER_NODE - 1); l += 1; }
    if n >= counts[l] { return u64::MAX; }
    layers[l][n * KEYS_PER_NODE + KEYS_PER_NODE - 1]
}
