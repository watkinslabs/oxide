// Module manifest:
// - support: task fixtures and shared errno values.
// - policy: predicates, permissions, application, and fork inheritance.
// - deadline: deadline admission, reporting, and fork rules.
// - setattr: scheduler attribute flags, clamps, and fair slices.
// - permissions: capability scopes, target walks, and task LSM ordering.
// - priority_common/setpriority_production: production adapters under hosted tests.

use super::*;

#[path = "tests/support.rs"]
mod support;
use support::*;
#[path = "tests/policy.rs"] mod policy;
#[path = "tests/setattr.rs"] mod setattr_e2e;
#[path = "tests/deadline.rs"] mod deadline;
#[path = "tests/permissions.rs"] mod permissions;
#[path = "../priority_common.rs"] mod priority_common;
#[path = "../141_setpriority.rs"] mod setpriority_production;
