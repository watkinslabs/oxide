// The stream cipher the temporal-key and wired-equivalent ciphers run on.
//
// It exists here rather than in the shared cryptography crate on purpose: it
// is not a primitive anything new should reach for, and both of its callers
// are in this file's directory. Keeping it beside them means nothing else
// grows a dependency on it.

/// Size of the permutation state.
const STATE_LEN: usize = 256;
/// Bytes discarded before the keystream is used. The two ciphers here
/// discard none: their key schedules are defined over the raw stream, and
/// dropping bytes would produce a link that talks to nothing.
const DISCARD: usize = 0;

/// One keyed stream generator.
pub struct Rc4 {
    s: [u8; STATE_LEN],
    i: u8,
    j: u8,
}

impl Rc4 {
    /// Key the generator. # C: O(256)
    pub fn new(key: &[u8]) -> Self {
        let mut s = [0u8; STATE_LEN];
        for (idx, slot) in s.iter_mut().enumerate() { *slot = idx as u8; }
        if !key.is_empty() {
            let mut j: u8 = 0;
            for i in 0..STATE_LEN {
                j = j.wrapping_add(s[i]).wrapping_add(key[i % key.len()]);
                s.swap(i, j as usize);
            }
        }
        let mut me = Self { s, i: 0, j: 0 };
        for _ in 0..DISCARD { me.byte(); }
        me
    }

    /// Next keystream byte. # C: O(1)
    fn byte(&mut self) -> u8 {
        self.i = self.i.wrapping_add(1);
        self.j = self.j.wrapping_add(self.s[self.i as usize]);
        self.s.swap(self.i as usize, self.j as usize);
        let k = self.s[self.i as usize].wrapping_add(self.s[self.j as usize]);
        self.s[k as usize]
    }

    /// Combine the keystream with a buffer in place. The cipher is its own
    /// inverse, so this is both the encrypt and the decrypt direction.
    /// # C: O(len)
    pub fn apply(&mut self, data: &mut [u8]) {
        for b in data.iter_mut() { *b ^= self.byte(); }
    }
}

/// Combine a buffer with a fresh keystream under `key`. # C: O(256 + len)
pub fn apply(key: &[u8], data: &mut [u8]) { Rc4::new(key).apply(data); }
