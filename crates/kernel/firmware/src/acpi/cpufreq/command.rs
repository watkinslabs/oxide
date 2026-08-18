//! Cross-CPU ACPI P-state transition commands.

const KIND_SHIFT: u64 = 56;
const WIDTH_SHIFT: u64 = 48;
const PORT_SHIFT: u64 = 32;
const FIELD_MASK: u64 = 0xff;

/// Hardware action encoded in a cross-CPU transition request.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum CommandKind { SystemIo = 1, IntelMsr = 2, AmdMsr = 3 }

/// One self-contained P-state programming request. Its encoding carries every
/// value the remote handler needs, so an IPI never dereferences policy state
/// or takes a provider lock in interrupt context.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Command { pub kind: CommandKind, pub port: u16, pub width_bits: u8, pub control: u32 }

impl Command {
    /// Pack the command into the call-function queue's opaque argument.
    /// # C: O(1)
    pub const fn encode(self) -> u64 {
        ((self.kind as u8 as u64) << KIND_SHIFT) | ((self.width_bits as u64) << WIDTH_SHIFT)
            | ((self.port as u64) << PORT_SHIFT) | self.control as u64
    }

    /// Decode a command, refusing all unassigned bits and malformed I/O widths.
    /// # C: O(1)
    pub const fn decode(raw: u64) -> Option<Command> {
        let kind = match ((raw >> KIND_SHIFT) & FIELD_MASK) as u8 {
            1 => CommandKind::SystemIo, 2 => CommandKind::IntelMsr, 3 => CommandKind::AmdMsr,
            _ => return None,
        };
        let width_bits = ((raw >> WIDTH_SHIFT) & FIELD_MASK) as u8;
        let port = ((raw >> PORT_SHIFT) & 0xffff) as u16;
        let control = raw as u32;
        match kind {
            CommandKind::SystemIo if !matches!(width_bits, 8 | 16 | 32) => None,
            CommandKind::SystemIo => Some(Command { kind, port, width_bits, control }),
            _ if port != 0 || width_bits != 0 => None,
            _ => Some(Command { kind, port, width_bits, control }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn io_command_round_trips_without_looking_up_any_policy_state() {
        let command = Command { kind: CommandKind::SystemIo, port: 0x1234, width_bits: 16,
                                control: 0xfeed_beef };
        assert_eq!(Command::decode(command.encode()), Some(command));
    }

    #[test]
    fn msr_commands_admit_only_their_self_contained_control_value() {
        let command = Command { kind: CommandKind::IntelMsr, port: 0, width_bits: 0, control: 0x31 };
        assert_eq!(Command::decode(command.encode()), Some(command));
        assert_eq!(Command::decode(command.encode() | (1 << PORT_SHIFT)), None);
    }

    #[test]
    fn an_unassigned_or_noncanonical_encoding_is_rejected() {
        assert_eq!(Command::decode(0), None);
        assert_eq!(Command::decode((1 << KIND_SHIFT) | (64 << WIDTH_SHIFT)), None);
        assert_eq!(Command::decode((2 << KIND_SHIFT) | (1 << 52)), None);
    }
}
