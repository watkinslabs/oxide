use super::*;
use core::sync::atomic::{AtomicUsize, Ordering};

static HITS: AtomicUsize = AtomicUsize::new(0);
static THREAD_HITS: AtomicUsize = AtomicUsize::new(0);
const TEST_DEV_ID: usize = 0x1000;

unsafe extern "C" fn test_handler(_irq: i32, dev_id: *mut c_void) -> i32 {
    assert_eq!(dev_id as usize, TEST_DEV_ID);
    HITS.fetch_add(1, Ordering::Relaxed);
    1
}

unsafe extern "C" fn not_mine_handler(_irq: i32, _dev_id: *mut c_void) -> i32 {
    IRQ_NONE
}

unsafe extern "C" fn shared_handler(_irq: i32, _dev_id: *mut c_void) -> i32 {
    IRQ_HANDLED
}

unsafe extern "C" fn wake_handler(_irq: i32, dev_id: *mut c_void) -> i32 {
    assert_eq!(dev_id as usize, TEST_DEV_ID);
    HITS.fetch_add(1, Ordering::Relaxed);
    IRQ_WAKE_THREAD
}

unsafe extern "C" fn thread_handler(_irq: i32, dev_id: *mut c_void) -> i32 {
    assert_eq!(dev_id as usize, TEST_DEV_ID);
    THREAD_HITS.fetch_add(1, Ordering::Relaxed);
    1
}

#[test]
fn request_dispatch_disable_and_free_irq() {
    let _modules = crate::test_serial::claim();
    let irq = hal_x86_64::VEC_MSI_POOL_FIRST as u32;
    HITS.store(0, Ordering::Relaxed);
    assert_eq!(request_irq(irq, Some(test_handler), 0, core::ptr::null(), TEST_DEV_ID as *mut c_void), LINUX_OK);
    assert!(arch_irq::invoke_x86_line_handler(irq as u8));
    assert_eq!(HITS.load(Ordering::Relaxed), 1);
    disable_irq(irq);
    assert!(arch_irq::invoke_x86_line_handler(irq as u8));
    assert_eq!(HITS.load(Ordering::Relaxed), 1);
    enable_irq(irq);
    assert!(arch_irq::invoke_x86_line_handler(irq as u8));
    assert_eq!(HITS.load(Ordering::Relaxed), 2);
    free_irq(irq, TEST_DEV_ID as *mut c_void);
    assert!(!arch_irq::invoke_x86_line_handler(irq as u8));
}

#[test]
fn rejects_duplicate_unshared_and_accepts_threaded_irq() {
    let _modules = crate::test_serial::claim();
    let irq = hal_x86_64::VEC_MSI_POOL_FIRST as u32 + 1;
    HITS.store(0, Ordering::Relaxed);
    THREAD_HITS.store(0, Ordering::Relaxed);
    assert_eq!(request_irq(irq, Some(test_handler), 0, core::ptr::null(), TEST_DEV_ID as *mut c_void), LINUX_OK);
    assert_eq!(request_irq(irq, Some(test_handler), 0, core::ptr::null(), (TEST_DEV_ID + 1) as *mut c_void), -LINUX_EBUSY);
    free_irq(irq, TEST_DEV_ID as *mut c_void);
    assert_eq!(
        request_threaded_irq(irq, Some(wake_handler), Some(thread_handler), 0, core::ptr::null(), TEST_DEV_ID as *mut c_void),
        LINUX_OK
    );
    assert!(arch_irq::invoke_x86_line_handler(irq as u8));
    synchronize_irq(irq);
    assert_eq!(HITS.load(Ordering::Relaxed), 1);
    assert_eq!(THREAD_HITS.load(Ordering::Relaxed), 1);
    free_irq(irq, TEST_DEV_ID as *mut c_void);
}

#[test]
fn threaded_irq_with_default_primary_wakes_thread() {
    let _modules = crate::test_serial::claim();
    let irq = hal_x86_64::VEC_MSI_POOL_FIRST as u32 + 2;
    THREAD_HITS.store(0, Ordering::Relaxed);
    assert_eq!(
        request_threaded_irq(irq, None, Some(thread_handler), IRQF_ONESHOT, core::ptr::null(), TEST_DEV_ID as *mut c_void),
        LINUX_OK
    );
    assert!(arch_irq::invoke_x86_line_handler(irq as u8));
    synchronize_irq(irq);
    assert_eq!(THREAD_HITS.load(Ordering::Relaxed), 1);
    free_irq(irq, TEST_DEV_ID as *mut c_void);
}

#[test]
fn shared_line_aggregates_handler_claims() {
    let _modules = crate::test_serial::claim();
    let irq = hal_x86_64::VEC_MSI_POOL_FIRST as u32 + 3;
    let other = TEST_DEV_ID + 1;
    assert_eq!(
        request_irq(irq, Some(not_mine_handler), IRQF_SHARED, core::ptr::null(), TEST_DEV_ID as *mut c_void),
        LINUX_OK
    );
    assert_eq!(
        request_irq(irq, Some(shared_handler), IRQF_SHARED, core::ptr::null(), other as *mut c_void),
        LINUX_OK
    );
    assert_eq!(linux_irq_dispatch(irq).ret, arch_irq::IrqRet::Handled);
    free_irq(irq, TEST_DEV_ID as *mut c_void);
    free_irq(irq, other as *mut c_void);
}

#[test]
fn unclaimed_line_reports_not_mine() {
    let _modules = crate::test_serial::claim();
    let irq = hal_x86_64::VEC_MSI_POOL_FIRST as u32 + 4;
    assert_eq!(
        request_irq(irq, Some(not_mine_handler), 0, core::ptr::null(), TEST_DEV_ID as *mut c_void),
        LINUX_OK
    );
    assert_eq!(linux_irq_dispatch(irq).ret, arch_irq::IrqRet::NotMine);
    free_irq(irq, TEST_DEV_ID as *mut c_void);
}

#[test]
fn removing_one_shared_action_preserves_the_line_thread_count() {
    let _modules = crate::test_serial::claim();
    let irq = hal_x86_64::VEC_MSI_POOL_FIRST as u32 + 5;
    let other = TEST_DEV_ID + 1;
    assert_eq!(
        request_irq(irq, Some(not_mine_handler), IRQF_SHARED, core::ptr::null(), TEST_DEV_ID as *mut c_void),
        LINUX_OK
    );
    assert_eq!(
        request_irq(irq, Some(not_mine_handler), IRQF_SHARED, core::ptr::null(), other as *mut c_void),
        LINUX_OK
    );
    {
        let mut records = IRQ_RECORDS.lock();
        let mut counts = [7u32, 11u32].into_iter();
        for rec in records.iter_mut().flatten().filter(|rec| rec.irq == irq) {
            rec.thread_handled = counts.next().expect("two shared records");
        }
    }
    free_irq(irq, TEST_DEV_ID as *mut c_void);
    let total = IRQ_RECORDS.lock().iter().flatten()
        .filter(|rec| rec.irq == irq)
        .fold(0u32, |sum, rec| sum.wrapping_add(rec.thread_handled));
    assert_eq!(total, 18);
    free_irq(irq, other as *mut c_void);
}

#[test]
fn export_symbols_registers_irq_surface() {
    let _modules = crate::test_serial::claim();
    export_symbols();
    for name in [
        "request_irq", "request_threaded_irq", "free_irq", "enable_irq",
        "disable_irq", "disable_irq_nosync", "synchronize_irq", "in_irq",
    ] {
        assert!(crate::symtab::is_exported(name));
    }
}
