use crate::NetStack;

static STACK: NetStack = NetStack::new();

/// Resolve the process-wide network stack used by kernel and hosted adapters. # C: O(1)
pub fn global_stack() -> &'static NetStack { &STACK }
