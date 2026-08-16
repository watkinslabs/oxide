// Every byte format this filesystem reads or writes, as pure functions over
// values. No node state, no locks, no globals reach in here, which is what
// makes each format re-checkable by a hosted test rather than by a boot.
//
// Module manifest:
//   scalar   — decimal flags and counts, and the trimming every write needs
//   request  — the whitespace-separated request lines the write nodes parse
//   response — the answers the read nodes render
//   percent  — the escape a created object's name arrives in

pub mod scalar;
pub mod request;
pub mod response;
pub mod percent;

pub use scalar::{parse_class, parse_flag, parse_u32, render_flag, render_u32, request_text};
pub use request::{parse_access_request, parse_context_request, parse_create_request,
                  parse_validatetrans_request, AvRequest, CreateRequest, TransRequest};
pub use response::{access_response, bool_response, cache_stats_response, hash_stats_response,
                   policyvers_response, AV_LEGACY_ALL_ONES};
pub use percent::percent_decode;
