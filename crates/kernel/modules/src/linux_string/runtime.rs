static STACK_GUARD: usize = 0x4f58_4944_455f_5350;

pub(crate) fn export_symbols() {
    use crate::symtab::export;
    export("__ref_stack_chk_guard", &STACK_GUARD as *const usize as usize, false);
    for (name, addr) in [
        ("__stack_chk_fail", __stack_chk_fail as *const () as usize),
        ("__fortify_panic", __fortify_panic as *const () as usize),
        ("__fentry__", __fentry__ as *const () as usize),
    ] { export(name, addr, false); }
}

pub(crate) extern "C" fn __stack_chk_fail() -> ! {
    loop { core::hint::spin_loop(); }
}

pub(crate) extern "C" fn __fortify_panic(_name: *const u8) -> ! {
    loop { core::hint::spin_loop(); }
}

pub(crate) extern "C" fn __fentry__() {}
