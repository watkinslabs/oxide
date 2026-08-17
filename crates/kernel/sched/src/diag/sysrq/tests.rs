// Module manifest — one test file per module under test.
//
// | module | covers |
// |---|---|
// | `table` | the key table's letters |
// | `mask`  | the `kernel.sysrq` enable policy |
// | `help`  | the key list's shape |
// | `rx`    | the arm-then-key state machine and its deadline |

mod help;
mod mask;
mod rx;
mod table;
