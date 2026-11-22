//! A network's upkeep: the router's firmware against upstream ([`eval`], looked up from
//! this machine and cached, [`upstream`]), its packages, its config backups, and the rules
//! that turn those into Maintenance rows ([`recommend`]). All of it pure but the lookup.

pub mod eval;
pub mod recommend;
pub mod upstream;

use sentry_core::maint::tasks::Task;

/// `maintenance.cadence` as recurring tasks (`cadence-<workflow>`), for the workflows this
/// network has. `tasks.toml` can replace one with the same id.
pub fn cadence_tasks(cfg: &crate::config::Network, workflows: &[String]) -> Vec<Task> {
    cfg.maintenance
        .cadence
        .iter()
        .filter(|c| workflows.contains(&c.workflow))
        .map(|c| Task {
            id: format!("cadence-{}", c.workflow),
            title: format!("Run {}", c.workflow),
            why: "On a cadence (maintenance.cadence in network_config.yaml).".into(),
            level: sentry_core::maint::Level::Routine,
            every: Some(c.every),
            act: format!("run {}", c.workflow),
            item: None,
            steps: String::new(),
            added: None,
            off: false,
            source: sentry_core::maint::tasks::Source::Config,
            review: None,
            after: None,
            again: None,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Cadence, Network};
    use sentry_core::config::Dur;
    use sentry_core::maint::tasks::Do;

    #[test]
    fn a_cadence_is_a_task_only_for_a_workflow_there_is() {
        let mut cfg = Network::default();
        cfg.maintenance.cadence = vec![
            Cadence {
                workflow: "config-backup".into(),
                every: Dur::secs(30 * 86_400),
            },
            Cadence {
                workflow: "package-update".into(),
                every: Dur::secs(60 * 86_400),
            },
        ];
        let t = cadence_tasks(&cfg, &["config-backup".to_string()]);
        assert_eq!(t.len(), 1);
        assert_eq!(t[0].id, "cadence-config-backup");
        assert_eq!(t[0].action(), Do::Run("config-backup".into()));
        assert_eq!(t[0].every, Some(Dur::secs(30 * 86_400)));
        assert!(cadence_tasks(&cfg, &[]).is_empty());
    }
}
