//! NT file-create disposition decisions shared by the kernel adapter tests.

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(crate) enum CreateDisposition {
    Supersede,
    Open,
    Create,
    OpenIf,
    Overwrite,
    OverwriteIf,
}

const FILE_DELETE_ON_CLOSE: u32 = 0x0000_1000;
const DELETE_ACCESS: u32 = 0x0001_0000;

impl CreateDisposition {
    pub(crate) const fn decode(value: u32) -> Option<Self> {
        match value {
            0 => Some(Self::Supersede), 1 => Some(Self::Open), 2 => Some(Self::Create),
            3 => Some(Self::OpenIf), 4 => Some(Self::Overwrite), 5 => Some(Self::OverwriteIf),
            _ => None,
        }
    }
    pub(crate) const fn allows_missing(self) -> bool {
        matches!(self, Self::Supersede | Self::Create | Self::OpenIf | Self::OverwriteIf)
    }
    pub(crate) const fn rejects_existing(self) -> bool { matches!(self, Self::Create) }
    pub(crate) const fn truncates_existing(self) -> bool {
        matches!(self, Self::Supersede | Self::Overwrite | Self::OverwriteIf)
    }
}

pub(crate) const fn delete_on_close_access_valid(options: u32, desired: u32) -> bool {
    options & FILE_DELETE_ON_CLOSE == 0 || desired & DELETE_ACCESS != 0
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn accepts_the_six_nt_create_dispositions() {
        for value in 0..=5 { assert!(CreateDisposition::decode(value).is_some()); }
        assert!(CreateDisposition::decode(6).is_none());
    }
    #[test]
    fn disposition_matrix_preserves_create_and_overwrite_semantics() {
        assert!(CreateDisposition::decode(2).unwrap().rejects_existing());
        assert!(!CreateDisposition::decode(1).unwrap().allows_missing());
        assert!(CreateDisposition::decode(3).unwrap().allows_missing());
        assert!(CreateDisposition::decode(4).unwrap().truncates_existing());
        assert!(CreateDisposition::decode(5).unwrap().truncates_existing());
        assert!(!CreateDisposition::decode(3).unwrap().truncates_existing());
    }

    #[test]
    fn delete_on_close_requires_delete_access() {
        assert!(delete_on_close_access_valid(0, 0));
        assert!(!delete_on_close_access_valid(FILE_DELETE_ON_CLOSE, 0));
        assert!(delete_on_close_access_valid(FILE_DELETE_ON_CLOSE, DELETE_ACCESS));
    }
}
