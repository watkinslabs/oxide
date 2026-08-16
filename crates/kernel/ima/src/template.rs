// Module manifest — measurement record templates.
//
//   desc    named templates, field identities, format expansion
//   event   the data a record is serialised from
//   fields  per-field serialisation and the digest-field encodings
//   entry   the built record: template digest, binary and ASCII renderings

pub mod desc;
pub mod entry;
pub mod event;
pub mod fields;

pub use desc::{lookup_desc, parse_fmt, FieldId, TemplateDesc, BUILTIN, TEMPLATE_IMA_FMT, TEMPLATE_IMA_NAME};
pub use entry::TemplateEntry;
pub use event::{Event, InodeMeta};
pub use fields::{digest_field, init_field, write_field_data, DataFmt, DigestType, FieldData};

#[cfg(test)]
mod tests;
