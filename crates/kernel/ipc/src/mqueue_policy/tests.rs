// Hosted tests for the mqueue policy ladders. Every case pins one specific
// errno/ordering decision from the policy module it exercises.
//
// Module manifest:
// - `name`:   `check_name` — the ENOENT/EACCES/ENAMETOOLONG ordering.
// - `open`:   `prepare_open` + `open_fmode`.
// - `attr`:   `validate_attr`, `admit_new_queue`, `charge_msgqueue`, `setattr_flags`.
// - `notify`: `notify_check` + `notify_action`.

mod attr;
mod name;
mod notify;
mod open;
