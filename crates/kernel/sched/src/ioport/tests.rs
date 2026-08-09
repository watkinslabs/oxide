// Module manifest: `ladder` pins the two errno orderings, `bitmap` the map
// arithmetic and the max-byte window, `apply` the task-state transitions
// (first grant, copy-on-write across fork, drop when nothing is left).

mod apply;
mod bitmap;
mod ladder;
