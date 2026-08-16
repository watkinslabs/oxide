// Fixed bounds of the framework.

/// Most modules that may run at once.
///
/// The bound exists so every hook list is a fixed array: a hook is taken on
/// the hot path of the VFS and the socket layer, and a list that could grow
/// would put an allocation there. Raising it costs one pointer per hook per
/// module and nothing else.
pub const MAX_LSM_COUNT: usize = 12;

/// Longest module name the boot line may select.
pub const MAX_LSM_NAME: usize = 32;
