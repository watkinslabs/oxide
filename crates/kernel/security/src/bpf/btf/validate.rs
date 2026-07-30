// Cross-record BTF reference, name, cycle, and concrete-layout validation.

use alloc::vec::Vec;
use syscall::errno::Errno;

use super::format::*;

fn reserve<T>(v: &mut Vec<T>, count: usize) -> Result<(), Errno> {
    v.try_reserve_exact(count).map_err(|_| Errno::Enomem)
}

fn name_bytes(strings: &[u8], off: u32) -> Option<&[u8]> {
    let off = off as usize;
    if off >= strings.len() || off > MAX_NAME_OFFSET { return None; }
    let end = strings[off..].iter().position(|b| *b == EMPTY_STRING)?;
    Some(&strings[off..off + end])
}

fn valid_name(strings: &[u8], off: u32, empty_ok: bool) -> bool {
    name_bytes(strings, off).is_some_and(|name| empty_ok || !name.is_empty())
}

fn valid_ident(strings: &[u8], off: u32, empty_ok: bool) -> bool {
    let Some(name) = name_bytes(strings, off) else { return false; };
    if name.is_empty() { return empty_ok; }
    if name.len() >= MAX_NAME_LEN
        || !name[0].is_ascii_alphabetic() && !matches!(name[0], b'_' | b'.') {
        return false;
    }
    name[1..].iter().all(|b| b.is_ascii_alphanumeric() || matches!(*b, b'_' | b'.'))
}

fn valid_section(strings: &[u8], off: u32) -> bool {
    name_bytes(strings, off).is_some_and(|name| !name.is_empty() && name.len() < MAX_NAME_LEN
        && name.iter().all(|b| b.is_ascii_graphic() || *b == b' '))
}

fn valid_ref(types: &[BtfType], id: u32, void_ok: bool) -> bool {
    id == TYPE_ID_VOID && void_ok || id != TYPE_ID_VOID && id as usize <= types.len()
}

fn type_at(types: &[BtfType], id: u32) -> Option<&BtfType> {
    id.checked_sub(1).and_then(|i| types.get(i as usize))
}

fn resolve_kind(types: &[BtfType], mut id: u32) -> Option<Kind> {
    for _ in 0..=types.len() {
        let t = type_at(types, id)?;
        if matches!(t.kind, Kind::Typedef | Kind::Volatile | Kind::Const
            | Kind::Restrict | Kind::TypeTag) {
            id = t.size_or_type;
        } else { return Some(t.kind); }
    }
    None
}

fn validate_decl_tag(t: &BtfType, component: i32, types: &[BtfType]) -> Result<(), Errno> {
    let target = type_at(types, t.size_or_type).ok_or(Errno::Einval)?;
    if component == DECL_TAG_TYPE_COMPONENT {
        return if matches!(target.kind, Kind::Struct | Kind::Union | Kind::Func
            | Kind::Var | Kind::Typedef) { Ok(()) } else { Err(Errno::Einval) };
    }
    if component < 0 { return Err(Errno::Einval); }
    let count = match &target.data {
        TypeData::Members(v) => v.len(),
        TypeData::Params(v) => v.len(),
        _ if target.kind == Kind::Func => {
            match &type_at(types, target.size_or_type).ok_or(Errno::Einval)?.data {
                TypeData::Params(v) => v.len(),
                _ => return Err(Errno::Einval),
            }
        }
        _ => return Err(Errno::Einval),
    };
    if component as usize >= count { Err(Errno::Einval) } else { Ok(()) }
}

fn validate_record(t: &BtfType, types: &[BtfType], strings: &[u8]) -> Result<(), Errno> {
    let anonymous = matches!(t.kind, Kind::Int | Kind::Ptr | Kind::Array | Kind::Volatile | Kind::Const
        | Kind::Restrict | Kind::FuncProto | Kind::Struct | Kind::Union | Kind::Enum
        | Kind::Float | Kind::Enum64);
    if !valid_name(strings, t.name_off, anonymous) { return Err(Errno::Einval); }
    if matches!(t.kind, Kind::Ptr | Kind::Array | Kind::Volatile | Kind::Const
        | Kind::Restrict | Kind::FuncProto) && t.name_off != EMPTY_NAME_OFFSET {
        return Err(Errno::Einval);
    }
    if t.kind == Kind::Datasec && !valid_section(strings, t.name_off) {
        return Err(Errno::Einval);
    }
    if !matches!(t.kind, Kind::Int | Kind::Float | Kind::DeclTag | Kind::TypeTag | Kind::Datasec)
        && !valid_ident(strings, t.name_off, anonymous) {
        return Err(Errno::Einval);
    }
    let type_ref = match t.kind {
        Kind::Ptr | Kind::FuncProto => Some((t.size_or_type, true)),
        Kind::Typedef | Kind::Volatile | Kind::Const | Kind::Restrict | Kind::Func
        | Kind::Var | Kind::DeclTag | Kind::TypeTag => Some((t.size_or_type, false)),
        _ => None,
    };
    if type_ref.is_some_and(|(id, void_ok)| !valid_ref(types, id, void_ok)) {
        return Err(Errno::Einval);
    }
    match &t.data {
        TypeData::Array { elem_type, index_type, .. } => {
            if !valid_ref(types, *elem_type, false) || !valid_ref(types, *index_type, false)
                || resolve_kind(types, *index_type) != Some(Kind::Int) {
                return Err(Errno::Einval);
            }
        }
        TypeData::Members(v) => for m in v {
            if !valid_ident(strings, m.name_off, true) || !valid_ref(types, m.type_id, false)
                || t.kind == Kind::Union && m.bit_offset != 0 {
                return Err(Errno::Einval);
            }
        },
        TypeData::Enum(v) => for e in v {
            if !valid_ident(strings, e.name_off, false) { return Err(Errno::Einval); }
        },
        TypeData::Enum64(v) => for e in v {
            if !valid_ident(strings, e.name_off, false) { return Err(Errno::Einval); }
        },
        TypeData::Params(v) => for (at, p) in v.iter().enumerate() {
            let variadic = p.name_off == EMPTY_NAME_OFFSET && p.type_id == TYPE_ID_VOID;
            if variadic && at + 1 != v.len()
                || !variadic && (!valid_ident(strings, p.name_off, true)
                    || !valid_ref(types, p.type_id, false)) {
                return Err(Errno::Einval);
            }
        },
        TypeData::Datasec(v) => for s in v {
            if type_at(types, s.type_id).is_none_or(|var| var.kind != Kind::Var) {
                return Err(Errno::Einval);
            }
        },
        TypeData::DeclTag { component_idx } => validate_decl_tag(t, *component_idx, types)?,
        _ => {}
    }
    if t.kind == Kind::Func && resolve_kind(types, t.size_or_type) != Some(Kind::FuncProto) {
        return Err(Errno::Einval);
    }
    Ok(())
}

fn layout_edges(t: &BtfType, out: &mut Vec<u32>) -> Result<(), Errno> {
    match &t.data {
        TypeData::Array { elem_type, index_type, .. } => {
            reserve(out, 2)?; out.push(*elem_type); out.push(*index_type);
        }
        TypeData::Members(v) => {
            reserve(out, v.len())?;
            for m in v { out.push(m.type_id); }
        }
        TypeData::Var { .. } => { reserve(out, 1)?; out.push(t.size_or_type); }
        _ if matches!(t.kind, Kind::Typedef | Kind::Volatile | Kind::Const
            | Kind::Restrict | Kind::TypeTag) => {
            reserve(out, 1)?; out.push(t.size_or_type);
        }
        _ => {}
    }
    Ok(())
}

fn visit(id: usize, depth: usize, types: &[BtfType], marks: &mut [u8]) -> Result<(), Errno> {
    if depth == MAX_RESOLVE_DEPTH { return Err(Errno::E2big); }
    if marks[id] == VISIT_OPEN { return Err(Errno::Eexist); }
    if marks[id] == VISIT_DONE { return Ok(()); }
    marks[id] = VISIT_OPEN;
    let mut edges = Vec::new();
    layout_edges(&types[id], &mut edges)?;
    for edge in edges {
        visit(edge.checked_sub(1).ok_or(Errno::Einval)? as usize, depth + 1, types, marks)?;
    }
    marks[id] = VISIT_DONE;
    Ok(())
}

fn resolved_size(types: &[BtfType], id: u32, depth: usize) -> Result<Option<u32>, Errno> {
    if depth == MAX_RESOLVE_DEPTH { return Err(Errno::E2big); }
    let Some(t) = type_at(types, id) else { return Ok(None); };
    Ok(match &t.data {
        TypeData::Array { elem_type, nelems, .. } => {
            let Some(size) = resolved_size(types, *elem_type, depth + 1)? else { return Ok(None); };
            Some(size.checked_mul(*nelems).ok_or(Errno::Einval)?)
        }
        TypeData::Var { .. } => resolved_size(types, t.size_or_type, depth + 1)?,
        _ if matches!(t.kind, Kind::Typedef | Kind::Volatile | Kind::Const
            | Kind::Restrict | Kind::TypeTag) => resolved_size(types, t.size_or_type, depth + 1)?,
        _ if t.kind == Kind::Ptr => Some(core::mem::size_of::<usize>() as u32),
        _ if matches!(t.kind, Kind::Int | Kind::Struct | Kind::Union | Kind::Enum
            | Kind::Float | Kind::Enum64) => Some(t.size_or_type),
        _ => None,
    })
}

fn validate_sizes(types: &[BtfType]) -> Result<(), Errno> {
    for t in types {
        match &t.data {
            TypeData::Array { elem_type, index_type, nelems } => {
                let Some(elem) = resolved_size(types, *elem_type, 0)? else {
                    return Err(Errno::Einval);
                };
                if resolved_size(types, *index_type, 0)?.is_none()
                    || elem.checked_mul(*nelems).is_none() {
                    return Err(Errno::Einval);
                }
            }
            TypeData::Members(members) => {
                let limit = t.size_or_type.checked_mul(BITS_PER_BYTE).ok_or(Errno::Einval)?;
                let mut last = 0;
                for m in members {
                    if m.bit_offset < last { return Err(Errno::Einval); }
                    last = m.bit_offset;
                    let Some(bytes) = resolved_size(types, m.type_id, 0)? else {
                        return Err(Errno::Einval);
                    };
                    let base = bytes.checked_mul(BITS_PER_BYTE).ok_or(Errno::Einval)?;
                    let bits = if m.bitfield_bits == 0 {
                        if m.bit_offset % BITS_PER_BYTE != 0 { return Err(Errno::Einval); }
                        base
                    } else {
                        if !matches!(resolve_kind(types, m.type_id),
                            Some(Kind::Int | Kind::Enum | Kind::Enum64))
                            || m.bitfield_bits as u32 > base {
                            return Err(Errno::Einval);
                        }
                        m.bitfield_bits as u32
                    };
                    if m.bit_offset.checked_add(bits).is_none_or(|end| end > limit) {
                        return Err(Errno::Einval);
                    }
                }
            }
            TypeData::Datasec(entries) => {
                let mut end = 0;
                for s in entries {
                    let var = type_at(types, s.type_id).ok_or(Errno::Einval)?;
                    let Some(size) = resolved_size(types, var.size_or_type, 0)? else {
                        return Err(Errno::Einval);
                    };
                    if s.size == 0 || s.size < size || s.offset < end
                        || s.offset >= t.size_or_type {
                        return Err(Errno::Einval);
                    }
                    end = s.offset.checked_add(s.size).ok_or(Errno::Einval)?;
                    if end > t.size_or_type { return Err(Errno::Einval); }
                }
            }
            _ => {}
        }
    }
    Ok(())
}

/// Validate decoded references, names, cycles, and concrete layouts. # C: O(types²)
pub(super) fn validate_all(types: &[BtfType], strings: &[u8]) -> Result<(), Errno> {
    for t in types { validate_record(t, types, strings)?; }
    let mut marks = Vec::new();
    reserve(&mut marks, types.len())?;
    marks.resize(types.len(), 0);
    for id in 0..types.len() { visit(id, 0, types, &mut marks)?; }
    validate_sizes(types)
}
