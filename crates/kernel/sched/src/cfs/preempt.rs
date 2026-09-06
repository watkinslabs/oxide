use super::*;

#[derive(Clone, Copy)]
struct Entity {
    vruntime: u64,
    deadline: u64,
    weight: u64,
    id: u64,
    group: bool,
    queued: bool,
}

#[cfg(test)]
#[path = "tests/preempt.rs"]
mod tests;

impl Entity {
    fn key(self, floor: u64, total: u64, sum: i128) -> PickKey {
        entity_key(sum, total, floor, self.vruntime, self.deadline, self.id, self.group)
    }
}

impl CfsRunqueue {
    fn entity(&self, task: &Task, path: &[u64]) -> Entity {
        if let Some(id) = path.first() {
            let group = &self.children[id];
            Entity { vruntime: group.vruntime, deadline: group.deadline,
                weight: group.shares.max(1) as u64, id: *id, group: true,
                queued: group.rq.nr_running != 0 }
        } else {
            Entity { vruntime: task.sched.se.vruntime.load(Ordering::Acquire),
                deadline: task.sched.se.deadline.load(Ordering::Acquire),
                weight: task_weight(task), id: task.tid as u64, group: false,
                queued: crate::class_queue::owns(task, self.queue_id) }
        }
    }

    fn task_path(&self, task: &Task) -> &[u64] {
        if task.sched.group_id() == ROOT_GROUP_ID { return &[]; }
        &self.paths.get(&task.sched.group_id())
            .expect("fair wake task lacks its installed group path")[1..]
    }

    /// Compare sibling entities in their shared clock after wake enqueue.
    /// # C: O(depth + entities in the common queue)
    pub(crate) fn wakeup_preempts(&self, current: &Task, wakee: &Task) -> bool {
        let mut current_path = self.task_path(current);
        let mut wake_path = self.task_path(wakee);
        let mut rq = self;
        while !current_path.is_empty() && !wake_path.is_empty()
            && current_path[0] == wake_path[0]
        {
            rq = &rq.children[&current_path[0]].rq;
            current_path = &current_path[1..];
            wake_path = &wake_path[1..];
        }
        let running_entity = rq.entity(current, current_path);
        let wake = rq.entity(wakee, wake_path);
        let (floor, mut total, mut sum) = rq.stats();
        // Running tasks are detached from the class tree. Their ancestor
        // can already be represented by other queued members; count it once.
        if !running_entity.queued {
            total = total.saturating_add(running_entity.weight);
            sum = sum.saturating_add(signed_delta(floor, running_entity.vruntime) * running_entity.weight as i128);
        }
        let current_key = running_entity.key(floor, total, sum);
        let wake_key = wake.key(floor, total, sum);
        if !wake_key.eligible { return false; }
        let Some((best, _)) = rq.best_queued(floor, total, sum) else { return false; };
        best.id == wake_key.id && best.group == wake_key.group
            && better(wake_key, current_key)
    }
}
