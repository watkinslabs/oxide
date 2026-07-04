use super::*;
    #[test] fn layout() {
        assert_eq!(REC, 384);
        assert_eq!(core::mem::offset_of!(utmp, ut_pid), 4);
        assert_eq!(core::mem::offset_of!(utmp, ut_line), 8);
        assert_eq!(core::mem::offset_of!(utmp, ut_id), 40);
        assert_eq!(core::mem::offset_of!(utmp, ut_user), 44);
        assert_eq!(core::mem::offset_of!(utmp, ut_host), 76);
        assert_eq!(core::mem::offset_of!(utmp, ut_exit), 332);
        assert_eq!(core::mem::offset_of!(utmp, ut_session), 336);
        assert_eq!(core::mem::offset_of!(utmp, ut_tv), 340);
        assert_eq!(core::mem::offset_of!(utmp, ut_addr_v6), 348);
        assert_eq!(core::mem::offset_of!(utmp, __glibc_reserved), 364);
    }
