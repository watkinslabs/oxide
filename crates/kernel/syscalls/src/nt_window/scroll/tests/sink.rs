use super::*;

#[test]
fn position_terminal_outcomes_map_without_collapsing_pending() {
    assert_eq!(map_position_outcome(PositionOutcome::Complete(true)), Outcome::Complete(1));
    assert_eq!(map_position_outcome(PositionOutcome::Complete(false)), Outcome::Failed);
    assert_eq!(map_position_outcome(PositionOutcome::Failed), Outcome::Failed);
    assert_eq!(map_position_outcome(PositionOutcome::Pending), Outcome::Pending);
}
