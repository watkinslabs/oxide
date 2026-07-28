// Hosted tests for the mqueue policy ladders. Every case cites the
// `ipc/mqueue.c` / `fs/namei.c` line it pins.
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
