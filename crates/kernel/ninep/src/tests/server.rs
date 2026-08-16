// A scripted in-memory 9P server used as the far end of the client tests.
//
// It is an INDEPENDENT encoder: it writes replies with the same primitives the
// client decodes, so a round-trip test checks the two halves against a real
// message rather than checking the decoder against its own encoder. It also
// records every request it saw, which is what makes fid-leak and tag-reuse
// assertions possible at all.

extern crate alloc;
use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use std::sync::Mutex;

use crate::client::req::Request;
use crate::codec::{encode_dirent, split_header, Dec, DirEntry, Enc, Qid, StatDotl, StatFs};
use crate::err::NpResult;
use crate::transport::{ReplySink, Transport};
use crate::uapi::{limits, op, qid as qidbits, stats, version};

/// One object in the served tree.
#[derive(Clone, Debug)]
pub struct Node {
    pub name: String,
    pub is_dir: bool,
    pub mode: u32,
    pub data: Vec<u8>,
    pub children: Vec<usize>,
    pub parent: Option<usize>,
    pub symlink: Option<String>,
}

/// Everything the scripted server remembers.
pub struct ServerState {
    pub nodes: Vec<Node>,
    pub fids: BTreeMap<u32, usize>,
    /// Every `(opcode, tag)` the server received, in order.
    pub seen: Vec<(u8, u16)>,
    /// Tags that were live when a request arrived — a duplicate here is a tag
    /// handed out twice while the first reply was still owed.
    pub concurrent_tags: Vec<u16>,
    pub live_tags: Vec<u16>,
    /// Fid numbers the client asked to clunk, in order. A repeat is a double
    /// clunk; a fid created and never listed here is a leak.
    pub clunked: Vec<u32>,
    pub created_fids: Vec<u32>,
    /// Frame size the server will admit to.
    pub msize: u32,
    /// Version string the server answers with, overridable to test downgrades.
    pub version_answer: String,
    /// When set, the next request receives this errno as an `Rlerror` instead
    /// of being executed.
    pub fail_next: Option<u32>,
    /// Cap on the payload of one `Rread`, to force the client's split loop.
    pub read_chunk: usize,
    /// Cap on the payload the server accepts in one `Twrite`.
    pub write_chunk: usize,
}

impl ServerState {
    fn node_qid(&self, idx: usize) -> Qid {
        let n = &self.nodes[idx];
        let ty = if n.is_dir { qidbits::QTDIR }
            else if n.symlink.is_some() { qidbits::QTSYMLINK }
            else { qidbits::QTFILE };
        Qid { ty, version: 1, path: idx as u64 }
    }
}

/// The scripted server plus its transport face.
pub struct ScriptedServer {
    pub state: Mutex<ServerState>,
    sink: Mutex<Option<Weak<dyn ReplySink>>>,
    max_msize: u32,
}

impl ScriptedServer {
    /// Build a server whose tree is a root directory. # C: O(1)
    pub fn new() -> Arc<Self> {
        let root = Node {
            name: "/".to_string(), is_dir: true, mode: 0o40755,
            data: Vec::new(), children: Vec::new(), parent: None, symlink: None,
        };
        Arc::new(Self {
            state: Mutex::new(ServerState {
                nodes: alloc::vec![root],
                fids: BTreeMap::new(),
                seen: Vec::new(),
                concurrent_tags: Vec::new(),
                live_tags: Vec::new(),
                clunked: Vec::new(),
                created_fids: Vec::new(),
                msize: limits::DEFAULT_MSIZE,
                version_answer: version::V9P2000L.to_string(),
                fail_next: None,
                read_chunk: usize::MAX,
                write_chunk: usize::MAX,
            }),
            sink: Mutex::new(None),
            max_msize: limits::MAX_SOCK_MSIZE,
        })
    }

    /// Add a regular file under `parent`, returning its node index. # C: O(1)
    pub fn add_file(&self, parent: usize, name: &str, data: &[u8]) -> usize {
        let mut s = self.state.lock().unwrap();
        let idx = s.nodes.len();
        s.nodes.push(Node {
            name: name.to_string(), is_dir: false, mode: 0o100644,
            data: data.to_vec(), children: Vec::new(), parent: Some(parent), symlink: None,
        });
        s.nodes[parent].children.push(idx);
        idx
    }

    /// Add a directory under `parent`. # C: O(1)
    pub fn add_dir(&self, parent: usize, name: &str) -> usize {
        let mut s = self.state.lock().unwrap();
        let idx = s.nodes.len();
        s.nodes.push(Node {
            name: name.to_string(), is_dir: true, mode: 0o40755,
            data: Vec::new(), children: Vec::new(), parent: Some(parent), symlink: None,
        });
        s.nodes[parent].children.push(idx);
        idx
    }

    /// Fids the client created and has not clunked. # C: O(N)
    pub fn leaked_fids(&self) -> Vec<u32> {
        let s = self.state.lock().unwrap();
        s.created_fids.iter().copied().filter(|f| !s.clunked.contains(f)).collect()
    }

    /// Tags that were reused while a reply was still owed. # C: O(N)
    pub fn tag_collisions(&self) -> Vec<u16> { self.state.lock().unwrap().concurrent_tags.clone() }

    /// Opcodes received, in order. # C: O(N)
    pub fn opcodes(&self) -> Vec<u8> {
        self.state.lock().unwrap().seen.iter().map(|(t, _)| *t).collect()
    }

    fn reply(&self, ty: u8, tag: u16, body: impl FnOnce(&mut Enc) -> NpResult<()>) -> Vec<u8> {
        let mut e = Enc::request(ty, tag, self.max_msize);
        body(&mut e).expect("scripted server reply encode");
        e.finish().expect("scripted server reply finish")
    }

    fn rlerror(&self, tag: u16, code: u32) -> Vec<u8> {
        self.reply(op::RLERROR, tag, |e| e.u32(code))
    }

    fn handle(&self, frame: &[u8]) -> Vec<u8> {
        let (hdr, body) = split_header(frame).expect("scripted server framing");
        {
            let mut s = self.state.lock().unwrap();
            if s.live_tags.contains(&hdr.tag) { s.concurrent_tags.push(hdr.tag); }
            s.live_tags.push(hdr.tag);
            s.seen.push((hdr.ty, hdr.tag));
            if let Some(code) = s.fail_next.take() {
                s.live_tags.retain(|t| *t != hdr.tag);
                return self.rlerror(hdr.tag, code);
            }
        }
        let out = self.dispatch(hdr.ty, hdr.tag, body);
        self.state.lock().unwrap().live_tags.retain(|t| *t != hdr.tag);
        out
    }

    fn dispatch(&self, ty: u8, tag: u16, body: &[u8]) -> Vec<u8> {
        let mut d = Dec::new(body);
        match ty {
            op::TVERSION => {
                let want = d.u32().unwrap();
                let _ver = d.string().unwrap();
                let mut s = self.state.lock().unwrap();
                s.msize = s.msize.min(want);
                let (m, v) = (s.msize, s.version_answer.clone());
                drop(s);
                self.reply(op::reply_of(op::TVERSION), tag, |e| { e.u32(m)?; e.string(&v) })
            }
            op::TATTACH => {
                let fid = d.u32().unwrap();
                let _afid = d.u32().unwrap();
                let mut s = self.state.lock().unwrap();
                s.fids.insert(fid, 0);
                s.created_fids.push(fid);
                let q = s.node_qid(0);
                drop(s);
                self.reply(op::reply_of(op::TATTACH), tag, |e| e.qid(&q))
            }
            op::TWALK => self.walk(tag, &mut d),
            op::TCLUNK => {
                let fid = d.u32().unwrap();
                let mut s = self.state.lock().unwrap();
                s.fids.remove(&fid);
                s.clunked.push(fid);
                drop(s);
                self.reply(op::reply_of(op::TCLUNK), tag, |_| Ok(()))
            }
            op::TLOPEN => {
                let fid = d.u32().unwrap();
                let _flags = d.u32().unwrap();
                let s = self.state.lock().unwrap();
                let Some(&idx) = s.fids.get(&fid) else { drop(s); return self.rlerror(tag, 9) };
                let q = s.node_qid(idx);
                drop(s);
                self.reply(op::reply_of(op::TLOPEN), tag, |e| { e.qid(&q)?; e.u32(0) })
            }
            op::TREAD => self.read(tag, &mut d),
            op::TWRITE => self.write(tag, &mut d),
            op::TREADDIR => self.readdir(tag, &mut d),
            op::TGETATTR => self.getattr(tag, &mut d),
            op::TSTATFS => {
                let _fid = d.u32().unwrap();
                let sfs = StatFs {
                    ty: crate::V9FS_MAGIC as u32, bsize: 4096, blocks: 1000, bfree: 500,
                    bavail: 500, files: 100, ffree: 50, fsid: 7, namelen: 255,
                };
                self.reply(op::reply_of(op::TSTATFS), tag, |e| sfs.encode(e))
            }
            op::TFLUSH => {
                let _oldtag = d.u16().unwrap();
                self.reply(op::reply_of(op::TFLUSH), tag, |_| Ok(()))
            }
            op::TFSYNC | op::TSETATTR | op::TUNLINKAT | op::TRENAMEAT | op::TLINK =>
                self.reply(op::reply_of(ty), tag, |_| Ok(())),
            op::TMKDIR => {
                let dfid = d.u32().unwrap();
                let name = d.string().unwrap().to_string();
                let s = self.state.lock().unwrap();
                let Some(&parent) = s.fids.get(&dfid) else { drop(s); return self.rlerror(tag, 9) };
                drop(s);
                let idx = self.add_dir(parent, &name);
                let q = self.state.lock().unwrap().node_qid(idx);
                self.reply(op::reply_of(op::TMKDIR), tag, |e| e.qid(&q))
            }
            op::TLCREATE => {
                let fid = d.u32().unwrap();
                let name = d.string().unwrap().to_string();
                let s = self.state.lock().unwrap();
                let Some(&parent) = s.fids.get(&fid) else { drop(s); return self.rlerror(tag, 9) };
                drop(s);
                let idx = self.add_file(parent, &name, &[]);
                let mut s = self.state.lock().unwrap();
                s.fids.insert(fid, idx);
                let q = s.node_qid(idx);
                drop(s);
                self.reply(op::reply_of(op::TLCREATE), tag, |e| { e.qid(&q)?; e.u32(0) })
            }
            _ => self.rlerror(tag, 38),
        }
    }

    fn walk(&self, tag: u16, d: &mut Dec<'_>) -> Vec<u8> {
        let fid = d.u32().unwrap();
        let newfid = d.u32().unwrap();
        let n = d.u16().unwrap() as usize;
        let mut names = Vec::new();
        for _ in 0..n { names.push(d.string().unwrap().to_string()); }
        let mut s = self.state.lock().unwrap();
        let Some(&start) = s.fids.get(&fid) else { return self.rlerror(tag, 9) };
        let mut at = start;
        let mut qids = Vec::new();
        for nm in &names {
            let next = if nm == ".." { s.nodes[at].parent.unwrap_or(at) }
                else {
                    match s.nodes[at].children.iter().copied().find(|c| &s.nodes[*c].name == nm) {
                        Some(c) => c,
                        None => break,
                    }
                };
            at = next;
            qids.push(s.node_qid(at));
        }
        if qids.len() == names.len() {
            if newfid != fid { s.created_fids.push(newfid); }
            s.fids.insert(newfid, at);
        }
        drop(s);
        self.reply(op::reply_of(op::TWALK), tag, |e| {
            e.u16(qids.len() as u16)?;
            for q in &qids { e.qid(q)?; }
            Ok(())
        })
    }

    fn read(&self, tag: u16, d: &mut Dec<'_>) -> Vec<u8> {
        let fid = d.u32().unwrap();
        let off = d.u64().unwrap() as usize;
        let count = d.u32().unwrap() as usize;
        let s = self.state.lock().unwrap();
        let Some(&idx) = s.fids.get(&fid) else { drop(s); return self.rlerror(tag, 9) };
        let data = &s.nodes[idx].data;
        let start = off.min(data.len());
        let want = count.min(s.read_chunk);
        let end = (start + want).min(data.len());
        let slice = data[start..end].to_vec();
        drop(s);
        self.reply(op::reply_of(op::TREAD), tag, |e| e.data(&slice))
    }

    fn write(&self, tag: u16, d: &mut Dec<'_>) -> Vec<u8> {
        let fid = d.u32().unwrap();
        let off = d.u64().unwrap() as usize;
        let data = d.data().unwrap().to_vec();
        let mut s = self.state.lock().unwrap();
        let Some(&idx) = s.fids.get(&fid) else { drop(s); return self.rlerror(tag, 9) };
        let take = data.len().min(s.write_chunk);
        let node = &mut s.nodes[idx];
        if node.data.len() < off + take { node.data.resize(off + take, 0); }
        node.data[off..off + take].copy_from_slice(&data[..take]);
        drop(s);
        self.reply(op::reply_of(op::TWRITE), tag, |e| e.u32(take as u32))
    }

    fn readdir(&self, tag: u16, d: &mut Dec<'_>) -> Vec<u8> {
        let fid = d.u32().unwrap();
        let cookie = d.u64().unwrap();
        let count = d.u32().unwrap() as usize;
        let s = self.state.lock().unwrap();
        let Some(&idx) = s.fids.get(&fid) else { drop(s); return self.rlerror(tag, 9) };
        let kids: Vec<usize> = s.nodes[idx].children.clone();
        let mut payload = Enc::request(0, 0, self.max_msize);
        let mut emitted = Vec::new();
        // The cookie is the 1-based index of the next entry, which is a valid
        // opaque choice: the client must not assume any particular meaning.
        for (i, c) in kids.iter().enumerate().skip(cookie as usize) {
            let name = s.nodes[*c].name.clone();
            let ent = DirEntry {
                qid: s.node_qid(*c), offset: (i + 1) as u64,
                dtype: if s.nodes[*c].is_dir { 4 } else { 8 },
                name: name.as_bytes(),
            };
            let mut probe = Enc::request(0, 0, self.max_msize);
            encode_dirent(&mut probe, &ent).unwrap();
            let sz = probe.len() - limits::HDRSZ;
            if emitted.len() + sz > count { break; }
            encode_dirent(&mut payload, &ent).unwrap();
            emitted.resize(emitted.len() + sz, 0);
        }
        drop(s);
        let bytes = payload.finish().unwrap()[limits::HDRSZ..].to_vec();
        self.reply(op::reply_of(op::TREADDIR), tag, |e| e.data(&bytes))
    }

    fn getattr(&self, tag: u16, d: &mut Dec<'_>) -> Vec<u8> {
        let fid = d.u32().unwrap();
        let mask = d.u64().unwrap();
        let s = self.state.lock().unwrap();
        let Some(&idx) = s.fids.get(&fid) else { drop(s); return self.rlerror(tag, 9) };
        let n = &s.nodes[idx];
        let st = StatDotl {
            valid: mask & stats::BASIC,
            qid: s.node_qid(idx),
            mode: n.mode,
            uid: 0, gid: 0, nlink: 1, rdev: 0,
            size: n.data.len() as u64, blksize: 4096,
            blocks: (n.data.len() as u64).div_ceil(512),
            ..Default::default()
        };
        drop(s);
        self.reply(op::reply_of(op::TGETATTR), tag, |e| st.encode(e))
    }
}

impl Transport for ScriptedServer {
    fn attach_sink(&self, sink: Weak<dyn ReplySink>) { *self.sink.lock().unwrap() = Some(sink); }

    /// Answers synchronously, which is what lets the whole client be driven
    /// without a scheduler. # C: O(frame)
    fn submit(&self, req: &Arc<Request>) -> NpResult<()> {
        let frame = self.handle(&req.tc);
        let sink = self.sink.lock().unwrap().clone();
        if let Some(s) = sink.and_then(|w| w.upgrade()) { s.deliver(&frame); }
        Ok(())
    }

    fn max_msize(&self) -> u32 { self.max_msize }
    fn is_connected(&self) -> bool { true }
}

