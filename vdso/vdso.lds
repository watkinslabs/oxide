/* Linker script for the per-arch oxide vDSO.
 *
 * The kernel maps the vDSO ELF at user VA `base`, and a single-page
 * kernel-published `vvar` page at `base - 0x1000`. The PROVIDE
 * directive teaches the linker that `_vdso_data` lives at byte
 * offset -0x1000 from the start of the image — RIP-relative loads
 * against `_vdso_data + N` then resolve correctly at runtime
 * regardless of where the kernel placed the vDSO.
 *
 * Layout mirrors the Linux x86_64 vdso.lds.S, minus the eh_frame
 * machinery (we link with --no-eh-frame-hdr).
 */

SECTIONS
{
    PROVIDE(_vdso_data = . - 0x1000);
    . = SIZEOF_HEADERS;

    .hash           : { *(.hash) }                  :text
    .gnu.hash       : { *(.gnu.hash) }
    .dynsym         : { *(.dynsym) }
    .dynstr         : { *(.dynstr) }
    .gnu.version    : { *(.gnu.version) }
    .gnu.version_d  : { *(.gnu.version_d) }
    .gnu.version_r  : { *(.gnu.version_r) }
    .dynamic        : { *(.dynamic) }               :text :dynamic
    .rodata         : { *(.rodata*) }               :text
    .note           : { *(.note.*) }                :text :note
    .text           : { *(.text*) }                 :text =0x90909090

    /DISCARD/       : {
        *(.eh_frame)
        *(.eh_frame_hdr)
        *(.note.gnu.build-id)
        *(.note.gnu.property)
    }
}

PHDRS
{
    text        PT_LOAD     FLAGS(5) FILEHDR PHDRS;  /* R E */
    dynamic     PT_DYNAMIC  FLAGS(4);                /* R */
    note        PT_NOTE     FLAGS(4);                /* R */
}

VERSION
{
    LINUX_2.6 {
    global:
        clock_gettime;
        __vdso_clock_gettime;
        gettimeofday;
        __vdso_gettimeofday;
        getcpu;
        __vdso_getcpu;
        time;
        __vdso_time;
        clock_getres;
        __vdso_clock_getres;
        __kernel_clock_gettime;
        __kernel_gettimeofday;
        __kernel_getcpu;
        __kernel_clock_getres;
        __kernel_rt_sigreturn;
    local: *;
    };
}
