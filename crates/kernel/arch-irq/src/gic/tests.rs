#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gic_status_distinct() {
        let a = GicStatus::AlreadyOn;
        let b = GicStatus::Enabled { typer: 0, gicd_iidr: 0, gicr_typer_lo: 0 };
        assert_ne!(a, b);
    }
}
