// Synthetic policy images for the reader's tests.
//
// The writer is deliberately independent of the reader: it lays out the wire
// format from the specification of each record, so a round trip exercises the
// format itself and not one shared helper's idea of it. Every field a test
// wants to corrupt is an option here, so the negative tests state WHAT is wrong
// rather than which byte they patched.

use alloc::vec::Vec;

use crate::uapi::version::{POLICYDB_CONFIG_MLS, POLICYDB_MAGIC, POLICYDB_SIGNATURE};

/// Version the synthetic image is written at unless a test says otherwise.
pub const SYNTH_VERSION: u32 = 34;
/// Symbol tables a current-version image carries.
pub const SYNTH_SYM_NUM: u32 = 8;
/// Object-context categories a current-version image carries.
pub const SYNTH_OCON_NUM: u32 = 9;

/// Class values the synthetic policy assigns.
pub const CLASS_PROCESS_VAL: u32 = 1;
/// Value of the `file` class.
pub const CLASS_FILE_VAL: u32 = 2;
/// Value of the `domain` attribute.
pub const TYPE_DOMAIN_VAL: u32 = 1;
/// Value of the `user_t` type.
pub const TYPE_USER_VAL: u32 = 2;
/// Value of the `file_t` type.
pub const TYPE_FILE_VAL: u32 = 3;
/// Value of the `user_r` role.
pub const ROLE_USER_VAL: u32 = 2;
/// Value of the `user_u` user.
pub const USER_VAL: u32 = 1;
/// Sensitivity value of `s0`.
pub const SENS_S0: u32 = 1;

/// Little-endian byte sink mirroring the reader's cursor.
#[derive(Default)]
pub struct W { pub b: Vec<u8> }

impl W {
    pub fn u32(&mut self, v: u32) { self.b.extend_from_slice(&v.to_le_bytes()); }
    pub fn u64(&mut self, v: u64) { self.b.extend_from_slice(&v.to_le_bytes()); }
    pub fn raw(&mut self, s: &str) { self.b.extend_from_slice(s.as_bytes()); }
    /// Length-prefixed string, for the records that prefix it directly.
    pub fn lstr(&mut self, s: &str) { self.u32(s.len() as u32); self.raw(s); }

    pub fn ebitmap(&mut self, bits: &[u32]) {
        self.u32(64);
        if bits.is_empty() { self.u32(0); self.u32(0); return; }
        let max = *bits.iter().max().unwrap_or(&0);
        let highbit = (max / 384 + 1) * 384;
        let mut chunks: Vec<(u32, u64)> = Vec::new();
        for &b in bits {
            let start = b & !63u32;
            match chunks.iter_mut().find(|c| c.0 == start) {
                Some(c) => c.1 |= 1u64 << (b - start),
                None => chunks.push((start, 1u64 << (b - start))),
            }
        }
        chunks.sort_by_key(|c| c.0);
        self.u32(highbit);
        self.u32(chunks.len() as u32);
        for (s, m) in chunks { self.u32(s); self.u64(m); }
    }

    pub fn level(&mut self, sens: u32, cats: &[u32]) { self.u32(sens); self.ebitmap(cats); }

    pub fn range(&mut self, low: u32, high: u32) {
        self.u32(2);
        self.u32(low);
        self.u32(high);
        self.ebitmap(&[]);
        self.ebitmap(&[]);
    }

    pub fn context(&mut self, user: u32, role: u32, ty: u32) {
        self.u32(user); self.u32(role); self.u32(ty);
        self.range(SENS_S0, SENS_S0);
    }

    /// One post-hash access-vector record.
    pub fn av(&mut self, src: u32, tgt: u32, class: u32, specified: u16, datum: u32) {
        self.b.extend_from_slice(&(src as u16).to_le_bytes());
        self.b.extend_from_slice(&(tgt as u16).to_le_bytes());
        self.b.extend_from_slice(&(class as u16).to_le_bytes());
        self.b.extend_from_slice(&specified.to_le_bytes());
        self.u32(datum);
    }
}

/// What a test wants the image to say, where it differs from a valid one.
pub struct Opts {
    pub magic: u32,
    pub signature: &'static [u8],
    pub version: u32,
    pub config: u32,
    pub sym_num: u32,
    pub ocon_num: u32,
    /// Common the `file` class inherits from; a name no common declares is a
    /// dangling reference the reader must refuse.
    pub file_common: &'static str,
    /// Value of the first boolean record.
    pub bool_value: u32,
    /// Type-attribute maps written, normally one per type.
    pub type_attr_count: u32,
    /// Bytes appended after the last section.
    pub trailing: usize,
}

impl Default for Opts {
    fn default() -> Self {
        Self {
            magic: POLICYDB_MAGIC,
            signature: POLICYDB_SIGNATURE,
            version: SYNTH_VERSION,
            config: POLICYDB_CONFIG_MLS,
            sym_num: SYNTH_SYM_NUM,
            ocon_num: SYNTH_OCON_NUM,
            file_common: "file",
            bool_value: 1,
            type_attr_count: 3,
            trailing: 0,
        }
    }
}

/// A valid current-version image. # C: O(1)
pub fn synth() -> Vec<u8> { build(&Opts::default()) }

/// An image differing from the valid one exactly as `o` says. # C: O(1)
pub fn build(o: &Opts) -> Vec<u8> {
    let mut w = W::default();
    header(&mut w, o);
    symbols(&mut w, o);
    rules(&mut w);
    transitions(&mut w);
    contexts(&mut w);
    for i in 0..o.type_attr_count {
        if i == TYPE_USER_VAL - 1 { w.ebitmap(&[TYPE_DOMAIN_VAL - 1]); } else { w.ebitmap(&[]); }
    }
    for _ in 0..o.trailing { w.b.push(0); }
    w.b
}

fn header(w: &mut W, o: &Opts) {
    w.u32(o.magic);
    w.u32(o.signature.len() as u32);
    w.b.extend_from_slice(o.signature);
    w.u32(o.version);
    w.u32(o.config);
    w.u32(o.sym_num);
    w.u32(o.ocon_num);
    w.ebitmap(&[0, 2]);
    w.ebitmap(&[TYPE_USER_VAL]);
}

fn symbols(w: &mut W, o: &Opts) {
    // commons: one common, two permissions
    w.u32(1); w.u32(1);
    w.u32(4); w.u32(1); w.u32(2); w.u32(2); w.raw("file");
    w.u32(4); w.u32(1); w.raw("read");
    w.u32(5); w.u32(2); w.raw("write");

    // classes: emitted out of value order, to pin value-indexed placement
    w.u32(2); w.u32(2);
    // The `file` class declares one permission and inherits two, so its
    // record's count pair differs and pins their order.
    class(w, "file", o.file_common, CLASS_FILE_VAL, 3, &[("open", 1)]);
    class(w, "process", "", CLASS_PROCESS_VAL, 3,
          &[("transition", 1), ("dyntransition", 2), ("fork", 3)]);

    // roles: the object role plus one user role
    w.u32(2); w.u32(2);
    role(w, "object_r", 1, &[0], &[]);
    role(w, "user_r", ROLE_USER_VAL, &[ROLE_USER_VAL - 1],
         &[TYPE_USER_VAL - 1, TYPE_FILE_VAL - 1]);

    // types: one attribute and two concrete types
    w.u32(3); w.u32(3);
    ty(w, "domain", TYPE_DOMAIN_VAL, true);
    ty(w, "user_t", TYPE_USER_VAL, false);
    ty(w, "file_t", TYPE_FILE_VAL, false);

    // users
    w.u32(1); w.u32(1);
    w.u32(6); w.u32(USER_VAL); w.u32(0); w.raw("user_u");
    w.ebitmap(&[ROLE_USER_VAL - 1]);
    w.range(SENS_S0, SENS_S0);
    w.level(SENS_S0, &[]);

    // booleans: value and state precede the name length
    w.u32(2); w.u32(2);
    w.u32(o.bool_value); w.u32(1); w.u32(4); w.raw("b_on");
    w.u32(2); w.u32(0); w.u32(5); w.raw("b_off");

    // sensitivities
    w.u32(1); w.u32(1);
    w.u32(2); w.u32(0); w.raw("s0");
    w.level(SENS_S0, &[]);

    // categories
    w.u32(1); w.u32(1);
    w.u32(2); w.u32(1); w.u32(0); w.raw("c0");
}

fn class(w: &mut W, name: &str, common: &str, value: u32, nprim: u32, perms: &[(&str, u32)]) {
    w.u32(name.len() as u32);
    w.u32(common.len() as u32);
    w.u32(value);
    w.u32(nprim);
    w.u32(perms.len() as u32);
    w.u32(0);
    w.raw(name);
    if !common.is_empty() { w.raw(common); }
    for (pname, pvalue) in perms { w.u32(pname.len() as u32); w.u32(*pvalue); w.raw(pname); }
    w.u32(0);
    w.u32(0); w.u32(0); w.u32(0);
    w.u32(0);
}

fn role(w: &mut W, name: &str, value: u32, dominates: &[u32], types: &[u32]) {
    w.u32(name.len() as u32); w.u32(value); w.u32(0); w.raw(name);
    w.ebitmap(dominates);
    w.ebitmap(types);
}

fn ty(w: &mut W, name: &str, value: u32, attribute: bool) {
    let prop = if attribute { 0x3 } else { 0x1 };
    w.u32(name.len() as u32); w.u32(value); w.u32(prop); w.u32(0); w.raw(name);
}

fn rules(w: &mut W) {
    w.u32(3);
    w.av(TYPE_USER_VAL, TYPE_FILE_VAL, CLASS_FILE_VAL, 0x0001, 0x1);
    w.av(TYPE_DOMAIN_VAL, TYPE_DOMAIN_VAL, CLASS_PROCESS_VAL, 0x0001, 0x4);
    w.av(TYPE_USER_VAL, TYPE_FILE_VAL, CLASS_PROCESS_VAL, 0x0010, TYPE_USER_VAL);

    // one conditional block: `if b_on` grants write on file
    w.u32(1);
    w.u32(0); w.u32(1);
    w.u32(1); w.u32(1);
    w.u32(1);
    w.av(TYPE_USER_VAL, TYPE_FILE_VAL, CLASS_FILE_VAL, 0x0001, 0x2);
    w.u32(0);
}

fn transitions(w: &mut W) {
    w.u32(1);
    w.u32(ROLE_USER_VAL); w.u32(TYPE_FILE_VAL); w.u32(ROLE_USER_VAL); w.u32(CLASS_PROCESS_VAL);
    w.u32(1);
    w.u32(ROLE_USER_VAL); w.u32(ROLE_USER_VAL);
    // filename transitions, compressed form
    w.u32(1);
    w.lstr("log");
    w.u32(TYPE_FILE_VAL); w.u32(CLASS_FILE_VAL); w.u32(1);
    w.ebitmap(&[TYPE_USER_VAL - 1]);
    w.u32(TYPE_FILE_VAL);
}

fn contexts(w: &mut W) {
    // initial SIDs
    w.u32(1); w.u32(1); w.context(USER_VAL, 1, TYPE_USER_VAL);
    // deprecated per-filesystem contexts, which the reader must consume
    w.u32(1); w.lstr("olddev"); w.context(USER_VAL, 1, TYPE_FILE_VAL);
    w.context(USER_VAL, 1, TYPE_FILE_VAL);
    // ports
    w.u32(1); w.u32(6); w.u32(80); w.u32(80); w.context(USER_VAL, 1, TYPE_FILE_VAL);
    // interfaces
    w.u32(1); w.lstr("eth0"); w.context(USER_VAL, 1, TYPE_FILE_VAL);
    w.context(USER_VAL, 1, TYPE_FILE_VAL);
    // IPv4 nodes
    w.u32(1); w.u32(0x0100_007f); w.u32(0x00ff_ffff);
    w.context(USER_VAL, 1, TYPE_FILE_VAL);
    // fs_use
    w.u32(1); w.u32(1); w.lstr("ext4"); w.context(USER_VAL, 1, TYPE_FILE_VAL);
    // IPv6 nodes
    w.u32(1); for _ in 0..8 { w.u32(0); } w.context(USER_VAL, 1, TYPE_FILE_VAL);
    // InfiniBand partition keys
    w.u32(1); w.u64(1); w.u32(1); w.u32(4); w.context(USER_VAL, 1, TYPE_FILE_VAL);
    // InfiniBand end ports
    w.u32(1); w.lstr("mlx0"); w.u32(1); w.context(USER_VAL, 1, TYPE_FILE_VAL);

    // genfs: the shorter prefix is written first, so a load that keeps the
    // written order would answer `/` for a path under `/sys/kernel`
    w.u32(1);
    w.lstr("proc");
    w.u32(2);
    w.lstr("/"); w.u32(0); w.context(USER_VAL, 1, TYPE_FILE_VAL);
    w.lstr("/sys/kernel"); w.u32(CLASS_FILE_VAL); w.context(USER_VAL, 1, TYPE_USER_VAL);

    // range transitions
    w.u32(1);
    w.u32(TYPE_USER_VAL); w.u32(TYPE_FILE_VAL); w.u32(CLASS_PROCESS_VAL);
    w.range(SENS_S0, SENS_S0);
}
