// Module manifest: queue owns request_queue/gendisk construction and the freeze/quiesce counters;
// request owns request lifetime, completion ownership and execution; bio owns the blk-mq-side BIO
// facade; status owns the blk_status_t <-> errno mapping and the gendisk notification entry points.

mod bio;
mod queue;
mod request;
mod status;
#[cfg(test)]
mod tests;

/// Register Linux blk-mq KPI symbols.
/// # C: O(1)
pub(super) fn export_symbols() {
    queue::export_symbols();
    request::export_symbols();
    bio::export_symbols();
    status::export_symbols();
}
