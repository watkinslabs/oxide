use alloc::sync::Arc;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use block::{BlockError, KResult};

use super::Zram;

/// The primary compressor has priority zero; secondary slots start at one.
const PRIMARY_PRIORITY: usize = 0;
const FIRST_SECONDARY_PRIORITY: usize = PRIMARY_PRIORITY + 1;

/// The complete set of compressor implementations linked into this driver.
/// Linux zcomp has one backend table; selection, lookup, and sysfs rendering
/// must all consume this same registry so no advertised name can lack I/O.
const BACKENDS: &[Compression] = &[Compression::Lzo, Compression::Lzorle, Compression::Lz4, Compression::Lz4hc, Compression::Deflate, Compression::Zstd, Compression::Eight42];

#[derive(Copy, Clone, Eq, PartialEq)]
pub(crate) enum Compression {
    Lzo,
    Lzorle,
    Lz4,
    Lz4hc,
    Deflate,
    Zstd,
    Eight42,
}

impl Compression {
    /// Linux's configured default zcomp backend. # C: O(1)
    pub(crate) const fn default_algorithm() -> Self { Self::Lz4 }

    /// # C: O(1)
    pub(crate) const fn name(self) -> &'static str {
        match self { Self::Lzo => "lzo", Self::Lzorle => "lzo-rle", Self::Lz4 => "lz4", Self::Lz4hc => "lz4hc", Self::Deflate => "deflate", Self::Zstd => "zstd", Self::Eight42 => "842" }
    }

    /// # C: O(length of text)
    pub(crate) fn from_name(text: &str) -> Option<Self> {
        BACKENDS.iter().copied().find(|algorithm| algorithm.name() == text)
    }

    /// Render exactly the compressors compiled into this driver, with the
    /// selected backend bracketed like Linux `zcomp_available_show`.
    /// # C: O(1)
    fn available_text(self) -> String {
        let mut text = String::new();
        for algorithm in BACKENDS {
            if *algorithm == self { text.push('['); }
            text.push_str(algorithm.name());
            if *algorithm == self { text.push(']'); }
            text.push(' ');
        }
        text
    }
}

/// One independently configurable primary or secondary compressor.
#[derive(Clone)]
pub(crate) struct CompressionConfig {
    pub(crate) algorithm: Compression,
    /// Linux zcomp's generic signed `level` parameter. Deflate interprets it
    /// as zlib level; LZ4 interprets it as its acceleration argument.
    pub(crate) level: i32,
    pub(crate) deflate_window_bits: i32,
    /// Generic zcomp dictionary bytes. Linux stores them independently of the
    /// selected backend; LZ4 consumes them while deflate retains them for a
    /// later backend change. A pathname would be mutable split state.
    pub(crate) dictionary: Vec<u8>,
    /// Created exactly once while `disksize` initializes the device. Every I/O
    /// path uses this priority-owned zcomp equivalent rather than rebuilding
    /// backend state from independent configuration fields.
    owner: Option<Arc<Compressor>>,
}

enum StreamOwner {
    Lzo(crate::lzo::Streams),
    Zstd(crate::zstd::Streams),
    Stateless,
}

struct Compressor { algorithm: Compression, level: i32, deflate_window_bits: i32, dictionary: Vec<u8>, streams: StreamOwner }

impl Compressor {
    fn new(config: &CompressionConfig) -> KResult<Self> {
        let streams = match config.algorithm {
            Compression::Lzo | Compression::Lzorle => StreamOwner::Lzo(crate::lzo::Streams::new()),
            Compression::Zstd => StreamOwner::Zstd(crate::zstd::Streams::new(config.level, &config.dictionary)?),
            Compression::Lz4 | Compression::Lz4hc | Compression::Deflate | Compression::Eight42 => StreamOwner::Stateless,
        };
        Ok(Self { algorithm: config.algorithm, level: config.level, deflate_window_bits: config.deflate_window_bits, dictionary: config.dictionary.clone(), streams })
    }

    fn compress(&self, bytes: &[u8]) -> KResult<Vec<u8>> {
        match (&self.streams, self.algorithm) {
            (StreamOwner::Lzo(streams), Compression::Lzo) => streams.compress(bytes),
            (StreamOwner::Lzo(streams), Compression::Lzorle) => crate::lzorle::compress(bytes, streams),
            (StreamOwner::Zstd(streams), Compression::Zstd) => streams.compress(bytes),
            (StreamOwner::Stateless, Compression::Lz4) => Ok(crate::lz4::compress(bytes, &self.dictionary, self.level)),
            (StreamOwner::Stateless, Compression::Lz4hc) => Ok(crate::lz4hc::compress(bytes, &self.dictionary, self.level)),
            (StreamOwner::Stateless, Compression::Deflate) => crate::deflate::compress(bytes, self.level, self.deflate_window_bits),
            (StreamOwner::Stateless, Compression::Eight42) => crate::eight42::compress(bytes),
            _ => Err(BlockError::Eio),
        }
    }

    fn decompress(&self, bytes: &[u8], page: &mut [u8]) -> KResult<()> {
        match (&self.streams, self.algorithm) {
            (StreamOwner::Lzo(_), Compression::Lzo) => crate::lzo::decompress(bytes, page),
            (StreamOwner::Lzo(_), Compression::Lzorle) => crate::lzorle::decompress(bytes, page),
            (StreamOwner::Zstd(streams), Compression::Zstd) => streams.decompress(bytes, page),
            (StreamOwner::Stateless, Compression::Lz4 | Compression::Lz4hc) => {
                let written = if self.dictionary.is_empty() { lz4_flex::block::decompress_into(bytes, page) }
                    else { lz4_flex::block::decompress_into_with_dict(bytes, page, &self.dictionary) }.map_err(|_| BlockError::Eio)?;
                if written == page.len() { Ok(()) } else { Err(BlockError::Eio) }
            }
            (StreamOwner::Stateless, Compression::Deflate) => {
                let config = zlib_rs::InflateConfig { window_bits: crate::deflate::window_bits(self.level, self.deflate_window_bits)? };
                let (decoded, result) = zlib_rs::decompress_slice(page, bytes, config);
                if result == zlib_rs::ReturnCode::Ok && decoded.len() == page.len() { Ok(()) } else { Err(BlockError::Eio) }
            }
            (StreamOwner::Stateless, Compression::Eight42) => crate::eight42::decompress(bytes, page),
            _ => Err(BlockError::Eio),
        }
    }
}

impl CompressionConfig {
    pub(crate) const fn new(algorithm: Compression, level: i32) -> Self {
        Self { algorithm, level, deflate_window_bits: crate::deflate::PARAM_NOT_SET, dictionary: Vec::new(), owner: None }
    }

    pub(crate) const fn default_for(algorithm: Compression) -> Self {
        Self::new(algorithm, crate::deflate::PARAM_NOT_SET)
    }

    fn set_level(&mut self, level: i32) { self.level = level; }

    fn set_deflate_window_bits(&mut self, bits: i32) -> KResult<()> {
        if self.algorithm != Compression::Deflate { return Err(BlockError::Einval); }
        self.deflate_window_bits = bits;
        Ok(())
    }

    pub(crate) fn validate_initialization(&self) -> KResult<()> {
        match self.algorithm {
            Compression::Deflate => crate::deflate::validate_initialization(self.level, self.deflate_window_bits),
            Compression::Zstd => crate::zstd::validate_initialization(self.level),
            _ => Ok(()),
        }
    }

    pub(crate) fn initialize(&mut self) -> KResult<()> {
        self.validate_initialization()?;
        self.owner = Some(Arc::new(Compressor::new(self)?));
        Ok(())
    }

    fn invalidate_owner(&mut self) { self.owner = None; }

    pub(crate) fn compress(&self, bytes: &[u8]) -> KResult<Vec<u8>> {
        self.owner.as_ref().ok_or(BlockError::Eio)?.compress(bytes)
    }

    pub(crate) fn decompress(&self, bytes: &[u8], page: &mut [u8]) -> KResult<()> {
        self.owner.as_ref().ok_or(BlockError::Eio)?.decompress(bytes, page)
    }

    #[cfg(test)]
    pub(crate) fn initialized_owner(&self) -> bool { self.owner.is_some() }

    fn set_dictionary(&mut self, dictionary: Option<Vec<u8>>) { self.dictionary = dictionary.unwrap_or_default(); }
}

#[derive(Copy, Clone)]
struct AlgorithmParams<'a> {
    algorithm: Option<&'a str>,
    priority: Option<usize>,
    level: Option<i32>,
    dictionary_requested: bool,
    deflate_window_bits: Option<i32>,
}

/// Parse Linux's generic `algorithm_params` argument grammar.  Unknown named
/// parameters are accepted by Linux's parser and are left to a selected
/// backend, while a bare or empty field is invalid before backend selection.
/// The caller rejects any known setting that no compiled backend can honor.
fn parse_algorithm_params(text: &str) -> KResult<AlgorithmParams<'_>> {
    let mut params = AlgorithmParams { algorithm: None, priority: None, level: None, dictionary_requested: false, deflate_window_bits: None };
    for item in text.split_ascii_whitespace() {
        let Some((name, value)) = item.split_once('=') else { return Err(BlockError::Einval); };
        if name.is_empty() || value.is_empty() { return Err(BlockError::Einval); }
        match name {
            "algo" => params.algorithm = Some(value),
            "priority" => params.priority = Some(value.parse::<usize>().map_err(|_| BlockError::Einval)?),
            "level" => params.level = Some(value.parse::<i32>().map_err(|_| BlockError::Einval)?),
            // Linux zram copies `dict=` into the generic parameter object.
            // Individual backends decide whether to consume it; its deflate
            // backend intentionally leaves the dictionary unused.
            "dict" => params.dictionary_requested = true,
            "deflate.winbits" => params.deflate_window_bits = Some(value.parse::<i32>().map_err(|_| BlockError::Einval)?),
            // Linux's `next_arg` loop intentionally leaves future/backend
            // fields untouched at this generic layer.
            _ => {}
        }
    }
    Ok(params)
}

/// Resolve Linux's `algo`/`priority` selector to one configured compressor.
/// # C: O(number of compressor priorities)
fn selected_config<'a>(state: &'a mut super::State, params: &AlgorithmParams<'_>) -> KResult<&'a mut CompressionConfig> {
    let algorithm = match params.algorithm {
        Some(name) => Some(Compression::from_name(name).ok_or(BlockError::Einval)?),
        None => None,
    };
    let priority = match (algorithm, params.priority) {
        (Some(algorithm), Some(priority)) => {
            let config = if priority == PRIMARY_PRIORITY { Some(&mut state.primary_algorithm) }
                else { priority.checked_sub(FIRST_SECONDARY_PRIORITY).and_then(|index| state.recompression_algorithms.get_mut(index)).and_then(Option::as_mut) };
            let config = config.ok_or(BlockError::Einval)?;
            if config.algorithm != algorithm { return Err(BlockError::Einval); }
            priority
        }
        (Some(algorithm), None) => {
            if state.primary_algorithm.algorithm == algorithm { PRIMARY_PRIORITY }
            else { state.recompression_algorithms.iter().position(|config| config.as_ref().is_some_and(|config| config.algorithm == algorithm)).map(|index| index + FIRST_SECONDARY_PRIORITY).ok_or(BlockError::Einval)? }
        }
        (None, Some(priority)) => priority,
        (None, None) => PRIMARY_PRIORITY,
    };
    if priority == PRIMARY_PRIORITY { Ok(&mut state.primary_algorithm) }
    else { priority.checked_sub(FIRST_SECONDARY_PRIORITY).and_then(|index| state.recompression_algorithms.get_mut(index)).and_then(Option::as_mut).ok_or(BlockError::Einval) }
}

impl Zram {
    /// Select the primary Linux compressor before initialization.
    /// # C: O(1)
    pub fn set_algorithm_text(&self, text: &str) -> KResult<()> {
        let algorithm = Compression::from_name(text.trim()).ok_or(BlockError::Einval)?;
        let mut state = self.state.lock();
        if state.size != 0 { return Err(BlockError::Ebusy); }
        // Linux keeps `params[ZRAM_PRIMARY_COMP]` when only its backend is
        // changed; parameters are owned by priority, not compressor name.
        state.primary_algorithm.invalidate_owner();
        state.primary_algorithm.algorithm = algorithm;
        Ok(())
    }

    /// Configure one Linux secondary compressor before initialization.
    /// Input is `algo=<name> priority=<one-based slot>`.
    /// # C: O(1)
    pub fn set_recomp_algorithm_text(&self, text: &str) -> KResult<()> {
        let mut algorithm = None;
        let mut priority = None;
        for item in text.split_ascii_whitespace() {
            let Some((name, value)) = item.split_once('=') else { return Err(BlockError::Einval); };
            if name.is_empty() || value.is_empty() { return Err(BlockError::Einval); }
            match name {
                "algo" => { algorithm = Compression::from_name(value); if algorithm.is_none() { return Err(BlockError::Einval); } }
                "priority" => priority = Some(value.parse::<usize>().map_err(|_| BlockError::Einval)?),
                _ => {}
            }
        }
        let (Some(algorithm), Some(priority)) = (algorithm, priority) else { return Err(BlockError::Einval); };
        let index = priority.checked_sub(FIRST_SECONDARY_PRIORITY).ok_or(BlockError::Einval)?;
        let mut state = self.state.lock();
        if index >= state.recompression_algorithms.len() { return Err(BlockError::Einval); }
        if state.size != 0 { return Err(BlockError::Ebusy); }
        // `recomp_algorithm` changes only `comp_algs[priority]`; preserve
        // parameters already configured for this priority.
        if let Some(config) = state.recompression_algorithms[index].as_mut() { config.invalidate_owner(); config.algorithm = algorithm; }
        else { state.recompression_algorithms[index] = Some(CompressionConfig::default_for(algorithm)); }
        Ok(())
    }

    /// Render only configured secondary priorities, never fabricate an empty
    /// priority selection.  Each line lists exactly the compiled backends.
    /// # C: O(number of configured priorities)
    pub fn recompression_algorithms(&self) -> String {
        let state = self.state.lock();
        let mut text = String::new();
        for (index, selected) in state.recompression_algorithms.iter().enumerate() {
            let Some(selected) = selected else { continue; };
            text.push('#');
            text.push_str(&(index + FIRST_SECONDARY_PRIORITY).to_string());
            text.push_str(": ");
            text.push_str(&selected.algorithm.available_text());
            text.push('\n');
        }
        text
    }

    /// Set per-compressor parameters before initialization.  A direct caller
    /// cannot turn a pathname into a dictionary byte stream, so `dict=` is
    /// rejected here; sysfs uses the byte-owning companion API below.
    /// # C: O(number of compressor priorities)
    pub fn set_algorithm_params_text(&self, text: &str) -> KResult<()> {
        self.set_algorithm_params_inner(text, None)
    }

    /// Apply `algorithm_params` after the sysfs owner has opened and copied
    /// Linux's `dict=<path>` file.  The driver owns only immutable bytes, never
    /// a path that could resolve differently when I/O later occurs.
    /// # C: O(dictionary bytes + compressor priorities)
    pub fn set_algorithm_params_with_dictionary_text(&self, text: &str, dictionary: Vec<u8>) -> KResult<()> {
        self.set_algorithm_params_inner(text, Some(dictionary))
    }

    /// Reset the selected compressor's parameters before the sysfs owner opens
    /// a requested dictionary, matching Linux `comp_params_store` ordering.
    /// # C: O(number of compressor priorities)
    pub fn reset_algorithm_params_text(&self, text: &str) -> KResult<()> {
        let params = parse_algorithm_params(text)?;
        let mut state = self.state.lock();
        if state.size != 0 { return Err(BlockError::Ebusy); }
        let config = selected_config(&mut state, &params)?;
        let algorithm = config.algorithm;
        *config = CompressionConfig::default_for(algorithm);
        Ok(())
    }

    fn set_algorithm_params_inner(&self, text: &str, dictionary: Option<Vec<u8>>) -> KResult<()> {
        let params = parse_algorithm_params(text)?;
        let mut state = self.state.lock();
        if state.size != 0 { return Err(BlockError::Ebusy); }
        if params.dictionary_requested != dictionary.is_some() { return Err(BlockError::Einval); }
        let config = selected_config(&mut state, &params)?;
        config.invalidate_owner();
        config.set_level(params.level.unwrap_or(crate::deflate::PARAM_NOT_SET));
        config.set_dictionary(dictionary);
        if config.algorithm == Compression::Deflate {
            config.set_deflate_window_bits(params.deflate_window_bits.unwrap_or(crate::deflate::PARAM_NOT_SET))?;
        } else {
            if params.deflate_window_bits.is_some() { return Err(BlockError::Einval); }
        }
        Ok(())
    }

    /// Render Linux `comp_algorithm` with the selected primary bracketed.
    /// # C: O(1)
    pub fn algorithms(&self) -> String { self.state.lock().primary_algorithm.algorithm.available_text() }
}
