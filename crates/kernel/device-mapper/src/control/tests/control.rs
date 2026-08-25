    use super::*;

    const CAPACITY: usize = 1024;
    static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn request() -> Vec<u8> {
        let mut bytes = alloc::vec![0; CAPACITY];
        put_u32(&mut bytes, DATA_SIZE, CAPACITY as u32).expect("size");
        put_u32(&mut bytes, DATA_START, DATA as u32).expect("start");
        bytes
    }

    fn named(name: &str) -> Vec<u8> {
        let mut bytes = request();
        write_fixed(&mut bytes, NAME, uapi::DM_NAME_LEN, name).expect("name");
        bytes
    }

    #[test]
    fn control_create_list_rename_and_remove_publish_one_real_mapper_node() {
        let _guard = TEST_LOCK.lock().expect("test lock");
        registry::reset_for_test();
        let original = "dm-control-fixture";
        let renamed = "dm-control-renamed";

        let mut create = named(original);
        dispatch(uapi::DM_DEV_CREATE, &mut create).expect("create");
        let dev = registry::by_name(original).expect("published mapper");
        assert_eq!(dev.minor, 0);
        assert!(block::registry::by_name("dm-0").is_some(), "block registry owns mapper disk");

        let mut listed = request();
        dispatch(uapi::DM_LIST_DEVICES, &mut listed).expect("list");
        assert!(listed[DATA..].windows(original.len()).any(|window| window == original.as_bytes()));

        let mut rename = named(original);
        rename[DATA..DATA + renamed.len()].copy_from_slice(renamed.as_bytes());
        rename[DATA + renamed.len()] = 0;
        dispatch(uapi::DM_DEV_RENAME, &mut rename).expect("rename");
        assert!(registry::by_name(original).is_none());
        assert_eq!(registry::by_name(renamed).expect("renamed mapper").minor, 0);

        let mut remove = named(renamed);
        dispatch(uapi::DM_DEV_REMOVE, &mut remove).expect("remove");
        assert!(registry::by_name(renamed).is_none());
        assert!(block::registry::by_name("dm-0").is_none());
    }

    #[test]
    fn version_stamps_reply_and_rejects_a_foreign_ioctl_type() {
        let mut bytes = request();
        dispatch(uapi::DM_VERSION, &mut bytes).expect("version");
        assert_eq!(read_u32(&bytes, VERSION).expect("major"), uapi::DM_VERSION_MAJOR);
        assert_eq!(dispatch(0, &mut bytes), Err(Errno::Enotty));
    }

    #[test]
    fn loaded_zero_table_resumes_and_services_the_published_block_node() {
        let _guard = TEST_LOCK.lock().expect("test lock");
        registry::reset_for_test();
        let name = "dm-zero-fixture";
        let mut create = named(name);
        dispatch(uapi::DM_DEV_CREATE, &mut create).expect("create");

        let mut load = named(name);
        let spec = 312usize;
        put_u32(&mut load, DATA_START, spec as u32).expect("table start");
        put_u32(&mut load, TARGET_COUNT, 1).expect("target count");
        put_u64(&mut load, spec + TARGET_SECTOR, 0).expect("sector");
        put_u64(&mut load, spec + TARGET_LENGTH, 8).expect("length");
        put_u32(&mut load, spec + TARGET_NEXT, 48).expect("next");
        write_fixed(&mut load, spec + TARGET_TYPE, uapi::DM_MAX_TYPE_NAME, "zero").expect("type");
        load[spec + TARGET_SPEC] = 0;
        dispatch(uapi::DM_TABLE_LOAD, &mut load).expect("load zero table");

        let mut resume = named(name);
        dispatch(uapi::DM_DEV_SUSPEND, &mut resume).expect("resume");
        assert_eq!(read_u32(&resume, EVENT_NR).expect("event number"), 1);
        let mut wait = named(name);
        put_u32(&mut wait, EVENT_NR, 0).expect("wait event number");
        dispatch(uapi::DM_DEV_WAIT, &mut wait).expect("wait for table event");
        assert_eq!(read_u32(&wait, EVENT_NR).expect("wait result"), 1);
        let disk = block::registry::by_name("dm-0").expect("published disk");
        let mut read = block::BlockRequest::new_read(0, 1, 512);
        disk.dev.submit_sync(&mut read).expect("zero read");
        assert_eq!(read.buffer, alloc::vec![0; 512]);

        let mut remove = named(name);
        dispatch(uapi::DM_DEV_REMOVE, &mut remove).expect("remove");
    }

