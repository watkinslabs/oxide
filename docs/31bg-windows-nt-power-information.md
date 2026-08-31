# Windows NT Power Information

Status: FROZEN

Date: 2026-08-31

## Contract

Wine exposes `NtPowerInformation` with five arguments. Oxide exposes the
64-bit export as selector 111 and implements the `SystemExecutionState`
query (level 16), returning `ES_USER_PRESENT` after validating the input and
output buffers.

Other power-information levels remain unsupported. The adapter does not
change Linux power policy, suspend, hibernation, or machine-terminal state.
