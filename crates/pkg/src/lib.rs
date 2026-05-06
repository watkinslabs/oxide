// pkg — RPM package manager surface. Wraps rpm (header) + inflate
// (gz unwrap) + cpio (entry walker) into a single API the kernel-
// side `rpm` command + system installer can drive.
//
// Surface:
//   read(blob) -> Result<Package>
//   Package::name(), version(), release(), arch(), summary()
//   Package::extract() -> Vec<File> ((path, mode, contents))
//
// All-in-memory: callers pass a fully-loaded RPM blob, get back
// fully-decoded files. v1 supports gzip-only payloads (the
// `Cargo.toml` PAYLOADCOMPRESSOR=gzip default in rpm-build).

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

#[cfg(any(test, feature = "hosted"))]
extern crate std;

extern crate alloc;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Error {
    Rpm(rpm::Error),
    Cpio(cpio::Error),
    Inflate(inflate::Error),
    UnsupportedCompressor,
    MalformedFileTags,
}

impl From<rpm::Error>     for Error { fn from(e: rpm::Error)     -> Self { Error::Rpm(e) } }
impl From<cpio::Error>    for Error { fn from(e: cpio::Error)    -> Self { Error::Cpio(e) } }
impl From<inflate::Error> for Error { fn from(e: inflate::Error) -> Self { Error::Inflate(e) } }

#[derive(Clone, Debug)]
pub struct Package<'a> {
    pkg:     rpm::Package<'a>,
    payload: &'a [u8],
}

#[derive(Clone, Debug)]
pub struct File {
    pub path:     String,
    pub mode:     u32,
    pub uid:      u32,
    pub gid:      u32,
    pub contents: Vec<u8>,
}

pub fn read(blob: &[u8]) -> Result<Package<'_>, Error> {
    let pkg = rpm::parse(blob)?;
    let payload = &blob[pkg.payload_off..];
    Ok(Package { pkg, payload })
}

impl<'a> Package<'a> {
    pub fn name(&self)    -> Option<&str> { self.pkg.tag_str(rpm::RPMTAG_NAME) }
    pub fn version(&self) -> Option<&str> { self.pkg.tag_str(rpm::RPMTAG_VERSION) }
    pub fn release(&self) -> Option<&str> { self.pkg.tag_str(rpm::RPMTAG_RELEASE) }
    pub fn arch(&self)    -> Option<&str> { self.pkg.tag_str(rpm::RPMTAG_ARCH) }
    pub fn summary(&self) -> Option<&str> { self.pkg.tag_str(rpm::RPMTAG_SUMMARY) }

    /// Returns "name-version-release.arch".
    pub fn nvra(&self) -> String {
        let n = self.name().unwrap_or("?");
        let v = self.version().unwrap_or("?");
        let r = self.release().unwrap_or("?");
        let a = self.arch().unwrap_or("?");
        let mut s = String::new();
        s.push_str(n); s.push('-');
        s.push_str(v); s.push('-');
        s.push_str(r); s.push('.');
        s.push_str(a);
        s
    }

    /// Extract every regular-file payload entry. Combines DIRNAMES,
    /// DIRINDEXES, BASENAMES into absolute paths. v1 ignores
    /// directory + symlink entries (mode-bit filtered).
    pub fn extract(&self) -> Result<Vec<File>, Error> {
        let compressor = self.pkg.tag_str(rpm::RPMTAG_PAYLOADCOMPRESSOR).unwrap_or("gzip");
        if compressor != "gzip" { return Err(Error::UnsupportedCompressor); }

        let raw = inflate::gunzip(self.payload)?;
        let entries = cpio::parse(&raw)?;

        let mut out = Vec::with_capacity(entries.len());
        for e in entries {
            // Mode bits: top 4 = file type. S_IFREG = 0o100000.
            let kind = e.mode & 0o170000;
            if kind != 0o100000 { continue; }
            // RPM-style cpio names use leading "./" — normalize.
            let raw = e.name.strip_prefix("./").unwrap_or(e.name);
            let path = if raw.starts_with('/') {
                raw.to_string()
            } else {
                let mut s = String::from('/');
                s.push_str(raw);
                s
            };
            out.push(File {
                path,
                mode: e.mode & 0o7777,
                uid:  e.uid,
                gid:  e.gid,
                contents: e.data.to_vec(),
            });
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::{Command, Stdio};
    use std::io::Write;

    fn pipe_gzip(input: &[u8]) -> Vec<u8> {
        let mut c = Command::new("gzip").arg("-cn").stdin(Stdio::piped()).stdout(Stdio::piped())
            .spawn().expect("gzip cmd");
        c.stdin.as_mut().unwrap().write_all(input).unwrap();
        c.wait_with_output().unwrap().stdout
    }

    fn pad4(v: &mut Vec<u8>) { while v.len() % 4 != 0 { v.push(0); } }

    fn cpio_entry(out: &mut Vec<u8>, name: &str, mode: u32, data: &[u8]) {
        let _8x = |n: u32| std::format!("{:08x}", n);
        out.extend_from_slice(b"070701");
        out.extend_from_slice(_8x(0).as_bytes());
        out.extend_from_slice(_8x(mode).as_bytes());
        out.extend_from_slice(_8x(0).as_bytes());
        out.extend_from_slice(_8x(0).as_bytes());
        out.extend_from_slice(_8x(1).as_bytes());
        out.extend_from_slice(_8x(0).as_bytes());
        out.extend_from_slice(_8x(data.len() as u32).as_bytes());
        out.extend_from_slice(_8x(0).as_bytes());
        out.extend_from_slice(_8x(0).as_bytes());
        out.extend_from_slice(_8x(0).as_bytes());
        out.extend_from_slice(_8x(0).as_bytes());
        out.extend_from_slice(_8x((name.len() + 1) as u32).as_bytes());
        out.extend_from_slice(_8x(0).as_bytes());
        out.extend_from_slice(name.as_bytes()); out.push(0);
        pad4(out);
        out.extend_from_slice(data); pad4(out);
    }

    fn build_rpm(payload_format: &str, payload: Vec<u8>) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&[0xed,0xab,0xee,0xdb]);
        out.resize(96, 0);

        // Sig hdr (empty).
        out.extend_from_slice(&[0x8e,0xad,0xe8,0x01, 0,0,0,0]);
        out.extend_from_slice(&[0,0,0,0]); out.extend_from_slice(&[0,0,0,0]);
        while out.len() % 8 != 0 { out.push(0); }

        // Pkg hdr: NAME, VERSION, RELEASE, ARCH, PAYLOADCOMPRESSOR
        out.extend_from_slice(&[0x8e,0xad,0xe8,0x01, 0,0,0,0]);
        let count_off = out.len();
        out.extend_from_slice(&[0,0,0,0]);
        let store_off = out.len();
        out.extend_from_slice(&[0,0,0,0]);

        let mut store: Vec<u8> = Vec::new();
        let mut tags: Vec<(u32, u32, u32, u32)> = Vec::new();
        let add = |tag: u32, s: &str, store: &mut Vec<u8>, tags: &mut Vec<(u32,u32,u32,u32)>| {
            let off = store.len() as u32;
            store.extend_from_slice(s.as_bytes()); store.push(0);
            tags.push((tag, rpm::TagType::String as u32, off, 1));
        };
        add(rpm::RPMTAG_NAME,    "demo",  &mut store, &mut tags);
        add(rpm::RPMTAG_VERSION, "1.0",   &mut store, &mut tags);
        add(rpm::RPMTAG_RELEASE, "1",     &mut store, &mut tags);
        add(rpm::RPMTAG_ARCH,    "x86_64", &mut store, &mut tags);
        add(rpm::RPMTAG_PAYLOADCOMPRESSOR, payload_format, &mut store, &mut tags);

        for (t, k, o, n) in &tags {
            out.extend_from_slice(&t.to_be_bytes());
            out.extend_from_slice(&k.to_be_bytes());
            out.extend_from_slice(&o.to_be_bytes());
            out.extend_from_slice(&n.to_be_bytes());
        }
        out.extend_from_slice(&store);
        out[count_off..count_off+4].copy_from_slice(&(tags.len() as u32).to_be_bytes());
        out[store_off..store_off+4].copy_from_slice(&(store.len() as u32).to_be_bytes());

        out.extend_from_slice(&payload);
        out
    }

    #[test]
    fn metadata_roundtrip() {
        let blob = build_rpm("gzip", Vec::new());
        let p = read(&blob).unwrap();
        assert_eq!(p.name(),    Some("demo"));
        assert_eq!(p.version(), Some("1.0"));
        assert_eq!(p.arch(),    Some("x86_64"));
        assert_eq!(p.nvra(),    "demo-1.0-1.x86_64");
    }

    #[test]
    fn extracts_gzipped_cpio() {
        let mut cpio_stream = Vec::new();
        cpio_entry(&mut cpio_stream, "./usr/bin/demo", 0o100755, b"#!/bin/sh\necho hi\n");
        cpio_entry(&mut cpio_stream, "./etc/demo.conf", 0o100644, b"key=value\n");
        cpio_entry(&mut cpio_stream, "TRAILER!!!", 0, b"");

        let gz = pipe_gzip(&cpio_stream);
        let blob = build_rpm("gzip", gz);

        let p = read(&blob).unwrap();
        let files = p.extract().unwrap();
        assert_eq!(files.len(), 2);
        assert_eq!(files[0].path, "/usr/bin/demo");
        assert_eq!(files[0].mode, 0o755);
        assert_eq!(files[1].path, "/etc/demo.conf");
        assert_eq!(files[1].contents, b"key=value\n");
    }

    #[test]
    fn rejects_unsupported_compressor() {
        let blob = build_rpm("zstd", Vec::new());
        let p = read(&blob).unwrap();
        assert_eq!(p.extract().unwrap_err(), Error::UnsupportedCompressor);
    }
}
