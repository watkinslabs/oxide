// auxv walking (docs/59§6 G3). The kernel appends the auxiliary vector
// after envp on the initial stack: env words, a 0 terminator, then
// (a_type, a_val) pairs ending at AT_NULL. Word-granular walk — testable
// without a real stack. AT_RANDOM (25) → 16 random bytes used to seed the
// stack-protector canary; AT_PHDR/AT_ENTRY/etc. feed the rtld at G12.

pub const AT_NULL: usize = 0;
pub const AT_RANDOM: usize = 25;

// Find an auxv entry's value. `envp` points at the first env word.
pub(crate) unsafe fn find_auxval(envp: *const usize, at_type: usize) -> Option<usize> {
    // SAFETY: envp is the kernel-provided env array; it is NUL-word
    // terminated and immediately followed by the auxv, so every step
    // stays inside the initial-stack block until AT_NULL ends it.
    unsafe {
        let mut p = envp;
        while *p != 0 { p = p.add(1); } // skip env strings
        p = p.add(1); // past the env terminator → auxv
        loop {
            let t = *p;
            if t == AT_NULL { return None; }
            let v = *p.add(1);
            if t == at_type { return Some(v); }
            p = p.add(2);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{find_auxval, AT_RANDOM};
    #[test]
    fn walks_env_then_auxv() {
        // [env0, env1, 0, AT_RANDOM, 0xCAFE, 6(unknown), 7, AT_NULL, 0]
        let words: [usize; 9] = [0x1000, 0x2000, 0, AT_RANDOM, 0xCAFE, 6, 7, 0, 0];
        let envp = words.as_ptr();
        // SAFETY: `words` is a live, properly terminated env+auxv layout.
        assert_eq!(unsafe { find_auxval(envp, AT_RANDOM) }, Some(0xCAFE));
        // SAFETY: same live, terminated env+auxv layout as above.
        assert_eq!(unsafe { find_auxval(envp, 99) }, None);
    }
}
