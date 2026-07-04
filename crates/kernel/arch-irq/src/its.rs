// GICv3 ITS bring-up and command programming.
//
// This is a manifest. ITS register state/probe, command queue setup, command
// builders/posting, and BASER table setup are split by hardware responsibility.

mod baser;
mod cmdq;
mod commands;
mod probe;
mod regs;

pub use baser::{
    baser_setup, typer_devbits, typer_id_bits, typer_itt_entry_size, typer_phys_lpi,
    typer_virt_lpi, BaserSlot, BaserType, GITS_BASER_COUNT,
};
pub use cmdq::{cmdq_pa, cmdq_setup, CmdqStatus};
pub use commands::{
    cmd_int, cmd_inv, cmd_mapc, cmd_mapd, cmd_mapti, cmd_post, cmd_sync, ctlr_enable, CmdStatus,
    ITS_CMD_INT, ITS_CMD_INV, ITS_CMD_MAPC, ITS_CMD_MAPD, ITS_CMD_MAPTI, ITS_CMD_SYNC,
};
pub use probe::{enable, translater_pa, ItsStatus};
pub use regs::GITS_TRANSLATER;

#[cfg(test)]
mod tests;
