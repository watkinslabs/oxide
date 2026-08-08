// Hosted tests for the hugetlbfs body. The pool cannot hand out real huge
// pages hosted (there is no PMM), so these drive the parts that decide rather
// than the parts that allocate: option enforcement, the mount's ceilings, the
// size grammar's effect on what a mount reports, and the errno each refusal
// produces.

mod options;
