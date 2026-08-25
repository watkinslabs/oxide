use super::*;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

fn mk_file() -> Arc<File> {
    let i: InodeRef = MemFile::new(1);
    let d = Dentry::new_root(Arc::clone(&i));
    File::new(i, d, OpenFlags::O_RDWR)
}

struct RwCapType;
impl FileSystemType for RwCapType {
    fn name(&self) -> &str { "rwcap" }
    fn mount(&self, _src: Option<&str>, _opts: &str) -> KResult<Arc<SuperBlock>> {
        unreachable!("file_fd tests construct superblocks directly")
    }
}

fn rwcap_sb(dev: u64) -> Arc<SuperBlock> {
    SuperBlock::new(Arc::new(RwCapType),
        Arc::new(SimpleSuperOps { magic: 0xCA9, block_size: 4096, options: String::new() }),
        0xCA9, dev, 4096, "rwcap".into(), Arc::new(()))
}


#[path = "file_fd/tests/file.rs"]
mod file;
#[path = "file_fd/tests/fdtable.rs"]
mod fdtable;
#[path = "file_fd/tests/metadata.rs"]
mod metadata;
#[path = "file_fd/tests/limits.rs"]
mod limits;
