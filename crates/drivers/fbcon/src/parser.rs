#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum CsiState {
    Ground,
    Esc,
    Csi,
    CsiParam,
    CsiInter,
    Osc,
    OscString,
    Ss2,
    Ss3,
    DcsEntry,
    DcsParam,
    DcsPassthrough,
    DcsString,
}

impl Default for CsiState {
    fn default() -> Self { CsiState::Ground }
}

#[derive(Copy, Clone, Debug, Default)]
pub struct ParserState {
    pub state: CsiState,
    pub params: [u32; 16],
    pub param_count: u8,
    pub intermediate: [u8; 4],
    pub inter_count: u8,
    pub utf8_pending: [u8; 4],
    pub utf8_len: u8,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Action {
    None,
    PutChar(u32),
    Bell,
    Backspace,
    Tab,
    Linefeed,
    CarriageReturn,
    SaveCursor,
    RestoreCursor,
    Index,
    ReverseIndex,
    FullReset,
    CursorUp(u32),
    CursorDown(u32),
    CursorForward(u32),
    CursorBackward(u32),
    CursorNextLine(u32),
    CursorPrevLine(u32),
    CursorColumn(u32),
    CursorRow(u32),
    CursorPosition(u32, u32),
    EraseDisplay(u32),
    EraseLine(u32),
    InsertLine(u32),
    DeleteLine(u32),
    InsertBlanks(u32),
    DeleteChar(u32),
    ScrollUp(u32),
    ScrollDown(u32),
    SetScrollRegion(u32, u32),
    SetGraphicRendition([u32; 16], u8),
    DeviceStatusReport(u32),
    SetMode(u32, bool),
}

pub fn step(state: &mut ParserState, byte: u8) -> Action {
    match state.state {
        CsiState::Ground => match byte {
            0x07 => Action::Bell,
            0x08 => Action::Backspace,
            0x09 => Action::Tab,
            0x0a => Action::Linefeed,
            0x0d => Action::CarriageReturn,
            0x1b => {
                state.state = CsiState::Esc;
                Action::None
            }
            b if (0x20..0x7f).contains(&b) => Action::PutChar(b as u32),
            b if (0xc2..0xf5).contains(&b) => {
                state.utf8_pending[0] = b;
                state.utf8_len = 1;
                Action::None
            }
            b if (b & 0xc0) == 0x80 && state.utf8_len > 0 => {
                state.utf8_pending[state.utf8_len as usize] = b;
                state.utf8_len += 1;
                if utf8_full(state) {
                    let cp = utf8_decode(&state.utf8_pending[..state.utf8_len as usize]);
                    state.utf8_len = 0;
                    Action::PutChar(cp)
                } else {
                    Action::None
                }
            }
            _ => Action::None,
        },
        CsiState::Esc => match byte {
            b'[' => {
                state.state = CsiState::CsiParam;
                state.param_count = 0;
                state.params = [0; 16];
                state.intermediate = [0; 4];
                state.inter_count = 0;
                Action::None
            }
            b']' => {
                state.state = CsiState::Osc;
                Action::None
            }
            b'P' => {
                state.state = CsiState::DcsEntry;
                Action::None
            }
            b'7' => {
                state.state = CsiState::Ground;
                Action::SaveCursor
            }
            b'8' => {
                state.state = CsiState::Ground;
                Action::RestoreCursor
            }
            b'D' => {
                state.state = CsiState::Ground;
                Action::Index
            }
            b'M' => {
                state.state = CsiState::Ground;
                Action::ReverseIndex
            }
            b'c' => {
                state.state = CsiState::Ground;
                Action::FullReset
            }
            _ => {
                state.state = CsiState::Ground;
                Action::None
            }
        },
        CsiState::CsiParam => match byte {
            b'0'..=b'9' => {
                let i = state.param_count as usize;
                if i < 16 {
                    state.params[i] = state.params[i].saturating_mul(10) + (byte - b'0') as u32;
                }
                Action::None
            }
            b';' => {
                if state.param_count < 15 {
                    state.param_count += 1;
                }
                Action::None
            }
            0x3c..=0x3f => {
                let i = state.inter_count as usize;
                if i < 4 {
                    state.intermediate[i] = byte;
                    state.inter_count += 1;
                }
                Action::None
            }
            0x20..=0x2f => {
                let i = state.inter_count as usize;
                if i < 4 {
                    state.intermediate[i] = byte;
                    state.inter_count += 1;
                }
                state.state = CsiState::CsiInter;
                Action::None
            }
            0x40..=0x7e => {
                let action = csi_final(state, byte);
                state.state = CsiState::Ground;
                action
            }
            _ => {
                state.state = CsiState::Ground;
                Action::None
            }
        },
        CsiState::CsiInter => match byte {
            0x40..=0x7e => {
                let action = csi_final(state, byte);
                state.state = CsiState::Ground;
                action
            }
            _ => {
                state.state = CsiState::Ground;
                Action::None
            }
        },
        CsiState::Osc => {
            state.state = CsiState::OscString;
            Action::None
        }
        CsiState::OscString => match byte {
            0x07 => {
                state.state = CsiState::Ground;
                Action::None
            }
            0x1b => Action::None,
            b'\\' => {
                state.state = CsiState::Ground;
                Action::None
            }
            _ => Action::None,
        },
        _ => {
            state.state = CsiState::Ground;
            Action::None
        }
    }
}

fn csi_final(state: &mut ParserState, byte: u8) -> Action {
    let n = state.param_count as usize + 1;
    let p1 = state.params[0];
    let p2 = if n > 1 { state.params[1] } else { 0 };
    match byte {
        b'A' => Action::CursorUp(p1.max(1)),
        b'B' => Action::CursorDown(p1.max(1)),
        b'C' => Action::CursorForward(p1.max(1)),
        b'D' => Action::CursorBackward(p1.max(1)),
        b'E' => Action::CursorNextLine(p1.max(1)),
        b'F' => Action::CursorPrevLine(p1.max(1)),
        b'G' => Action::CursorColumn(p1.max(1)),
        b'H' | b'f' => Action::CursorPosition(p1.max(1), p2.max(1)),
        b'J' => Action::EraseDisplay(p1),
        b'K' => Action::EraseLine(p1),
        b'L' => Action::InsertLine(p1.max(1)),
        b'M' => Action::DeleteLine(p1.max(1)),
        b'P' => Action::DeleteChar(p1.max(1)),
        b'@' => Action::InsertBlanks(p1.max(1)),
        b'S' => Action::ScrollUp(p1.max(1)),
        b'T' => Action::ScrollDown(p1.max(1)),
        b'd' => Action::CursorRow(p1.max(1)),
        b'r' => Action::SetScrollRegion(p1.max(1), p2.max(1)),
        b'm' => Action::SetGraphicRendition(state.params, n as u8),
        b'n' => Action::DeviceStatusReport(p1),
        b'h' | b'l' => {
            let set = byte == b'h';
            if state.intermediate[..state.inter_count as usize].first() == Some(&b'?') {
                Action::SetMode(p1, set)
            } else {
                Action::None
            }
        }
        _ => Action::None,
    }
}

fn utf8_full(state: &ParserState) -> bool {
    let lead = state.utf8_pending[0];
    let need = if (lead & 0xe0) == 0xc0 {
        2
    } else if (lead & 0xf0) == 0xe0 {
        3
    } else if (lead & 0xf8) == 0xf0 {
        4
    } else {
        1
    };
    state.utf8_len as usize >= need
}

fn utf8_decode(bytes: &[u8]) -> u32 {
    match bytes.len() {
        2 => ((bytes[0] & 0x1f) as u32) << 6 | (bytes[1] & 0x3f) as u32,
        3 => {
            ((bytes[0] & 0x0f) as u32) << 12
                | ((bytes[1] & 0x3f) as u32) << 6
                | (bytes[2] & 0x3f) as u32
        }
        4 => {
            ((bytes[0] & 0x07) as u32) << 18
                | ((bytes[1] & 0x3f) as u32) << 12
                | ((bytes[2] & 0x3f) as u32) << 6
                | (bytes[3] & 0x3f) as u32
        }
        _ => bytes[0] as u32,
    }
}
