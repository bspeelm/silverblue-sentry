//! Applying something with Claude, as one session: Claude investigates and writes one plan
//! (`plan`), the user approves it once, sentry carries it out (`sudo` for what needs root),
//! Claude verifies the result (`verdict`), and the task is done. `session` is the state
//! machine both programs drive; the window is `tui::applyview`.

pub mod plan;
pub mod session;
pub mod sudo;
pub mod verdict;
