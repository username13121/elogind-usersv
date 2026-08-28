use elogind_usersv_protocol::ErrorCode;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum UserManagerState {
    Absent,
    Starting {
        generation: u64,
        attempt: u32,
        manager_pid: Option<u32>,
    },
    Ready {
        generation: u64,
        manager_pid: u32,
        restart_attempts: u32,
    },
    Backoff {
        generation: u64,
        next_attempt: u32,
    },
    Stopping {
        generation: u64,
        restart_after_stop: bool,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UserMachine {
    pub uid: u32,
    pub eligible_sessions: usize,
    pub state: UserManagerState,
    pending_pam: Vec<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Action {
    SpawnHelper,
    StartManager { generation: u64, attempt: u32 },
    ShutdownHelper { generation: u64 },
    ScheduleBackoff { generation: u64, attempt: u32 },
    ReplyReady(Vec<u64>),
    ReplyError { requests: Vec<u64>, code: ErrorCode },
}

impl UserMachine {
    pub fn new(uid: u32) -> Self {
        Self {
            uid,
            eligible_sessions: 0,
            state: UserManagerState::Absent,
            pending_pam: Vec::new(),
        }
    }

    pub fn set_eligible_sessions(&mut self, count: usize) -> Vec<Action> {
        let previous = self.eligible_sessions;
        self.eligible_sessions = count;
        if previous == 0 && count > 0 {
            return match &mut self.state {
                UserManagerState::Absent => vec![Action::SpawnHelper],
                UserManagerState::Stopping {
                    restart_after_stop, ..
                } => {
                    *restart_after_stop = true;
                    Vec::new()
                }
                _ => Vec::new(),
            };
        }
        if previous > 0 && count == 0 {
            let mut actions = Vec::new();
            let pending = std::mem::take(&mut self.pending_pam);
            if !pending.is_empty() {
                actions.push(Action::ReplyError {
                    requests: pending,
                    code: ErrorCode::SessionIneligible,
                });
            }
            match self.state {
                UserManagerState::Absent => {}
                UserManagerState::Stopping { .. } => {}
                ref state => {
                    let generation = state.generation().expect("active state has generation");
                    self.state = UserManagerState::Stopping {
                        generation,
                        restart_after_stop: false,
                    };
                    actions.push(Action::ShutdownHelper { generation });
                }
            }
            return actions;
        }
        Vec::new()
    }

    pub fn add_pam_request(&mut self, request: u64) -> Vec<Action> {
        if matches!(self.state, UserManagerState::Ready { .. }) {
            vec![Action::ReplyReady(vec![request])]
        } else {
            self.pending_pam.push(request);
            Vec::new()
        }
    }

    pub fn cancel_pam_request(&mut self, request: u64) {
        self.pending_pam.retain(|pending| *pending != request);
    }

    pub fn helper_spawned(&mut self, generation: u64) {
        assert!(matches!(self.state, UserManagerState::Absent));
        self.state = UserManagerState::Starting {
            generation,
            attempt: 1,
            manager_pid: None,
        };
    }

    pub fn lease_accepted(&self) -> Vec<Action> {
        match self.state {
            UserManagerState::Starting {
                generation,
                attempt,
                manager_pid: None,
            } => vec![Action::StartManager {
                generation,
                attempt,
            }],
            _ => Vec::new(),
        }
    }

    pub fn manager_spawned(&mut self, generation: u64, pid: u32) {
        if let UserManagerState::Starting {
            generation: current,
            manager_pid,
            ..
        } = &mut self.state
            && *current == generation
        {
            *manager_pid = Some(pid);
        }
    }

    pub fn ready_succeeded(&mut self, generation: u64) -> Vec<Action> {
        let UserManagerState::Starting {
            generation: current,
            attempt,
            manager_pid: Some(manager_pid),
        } = self.state
        else {
            return Vec::new();
        };
        if current != generation {
            return Vec::new();
        }
        self.state = UserManagerState::Ready {
            generation,
            manager_pid,
            restart_attempts: attempt.saturating_sub(1),
        };
        let pending = std::mem::take(&mut self.pending_pam);
        if pending.is_empty() {
            Vec::new()
        } else {
            vec![Action::ReplyReady(pending)]
        }
    }

    pub fn startup_failed(&mut self, generation: u64) -> Vec<Action> {
        let UserManagerState::Starting {
            generation: current,
            attempt,
            ..
        } = self.state
        else {
            return Vec::new();
        };
        if current != generation {
            return Vec::new();
        }
        if self.eligible_sessions == 0 {
            self.state = UserManagerState::Stopping {
                generation,
                restart_after_stop: false,
            };
            return vec![Action::ShutdownHelper { generation }];
        }
        let next_attempt = attempt.saturating_add(1);
        self.state = UserManagerState::Backoff {
            generation,
            next_attempt,
        };
        vec![Action::ScheduleBackoff {
            generation,
            attempt: next_attempt,
        }]
    }

    pub fn manager_exited(&mut self, generation: u64) -> Vec<Action> {
        match self.state {
            UserManagerState::Ready {
                generation: current,
                restart_attempts,
                ..
            } if current == generation && self.eligible_sessions > 0 => {
                let next_attempt = restart_attempts.saturating_add(2).max(1);
                self.state = UserManagerState::Backoff {
                    generation,
                    next_attempt,
                };
                vec![Action::ScheduleBackoff {
                    generation,
                    attempt: next_attempt,
                }]
            }
            UserManagerState::Ready {
                generation: current,
                ..
            } if current == generation => {
                self.state = UserManagerState::Stopping {
                    generation,
                    restart_after_stop: false,
                };
                vec![Action::ShutdownHelper { generation }]
            }
            UserManagerState::Starting {
                generation: current,
                ref mut manager_pid,
                ..
            } if current == generation => {
                *manager_pid = None;
                Vec::new()
            }
            _ => Vec::new(),
        }
    }

    pub fn backoff_elapsed(&mut self, generation: u64, attempt: u32) -> Vec<Action> {
        if self.state
            != (UserManagerState::Backoff {
                generation,
                next_attempt: attempt,
            })
            || self.eligible_sessions == 0
        {
            return Vec::new();
        }
        self.state = UserManagerState::Starting {
            generation,
            attempt,
            manager_pid: None,
        };
        vec![Action::StartManager {
            generation,
            attempt,
        }]
    }

    pub fn helper_exited(&mut self, generation: u64) -> Vec<Action> {
        if self.state.generation() != Some(generation) {
            return Vec::new();
        }
        let restart = self.eligible_sessions > 0
            || matches!(
                self.state,
                UserManagerState::Stopping {
                    restart_after_stop: true,
                    ..
                }
            );
        self.state = UserManagerState::Absent;
        if restart {
            vec![Action::SpawnHelper]
        } else {
            let pending = std::mem::take(&mut self.pending_pam);
            if pending.is_empty() {
                Vec::new()
            } else {
                vec![Action::ReplyError {
                    requests: pending,
                    code: ErrorCode::StartupFailed,
                }]
            }
        }
    }

    pub fn begin_shutdown(&mut self) -> Vec<Action> {
        let Some(generation) = self.state.generation() else {
            return Vec::new();
        };
        self.eligible_sessions = 0;
        self.state = UserManagerState::Stopping {
            generation,
            restart_after_stop: false,
        };
        let pending = std::mem::take(&mut self.pending_pam);
        let mut actions = vec![Action::ShutdownHelper { generation }];
        if !pending.is_empty() {
            actions.push(Action::ReplyError {
                requests: pending,
                code: ErrorCode::Internal,
            });
        }
        actions
    }
}

impl UserManagerState {
    pub fn generation(&self) -> Option<u64> {
        match self {
            Self::Absent => None,
            Self::Starting { generation, .. }
            | Self::Ready { generation, .. }
            | Self::Backoff { generation, .. }
            | Self::Stopping { generation, .. } => Some(*generation),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normal_lifecycle_and_concurrent_pam_requests() {
        let mut machine = UserMachine::new(1000);
        assert_eq!(machine.set_eligible_sessions(1), vec![Action::SpawnHelper]);
        machine.helper_spawned(10);
        assert!(machine.add_pam_request(1).is_empty());
        assert!(machine.add_pam_request(2).is_empty());
        assert_eq!(
            machine.lease_accepted(),
            vec![Action::StartManager {
                generation: 10,
                attempt: 1
            }]
        );
        machine.manager_spawned(10, 1234);
        assert_eq!(
            machine.ready_succeeded(10),
            vec![Action::ReplyReady(vec![1, 2])]
        );
        assert_eq!(
            machine.add_pam_request(3),
            vec![Action::ReplyReady(vec![3])]
        );
        assert!(machine.set_eligible_sessions(2).is_empty());
        assert!(machine.set_eligible_sessions(1).is_empty());
        assert_eq!(
            machine.set_eligible_sessions(0),
            vec![Action::ShutdownHelper { generation: 10 }]
        );
        assert!(matches!(machine.state, UserManagerState::Stopping { .. }));
        assert!(machine.helper_exited(10).is_empty());
        assert_eq!(machine.state, UserManagerState::Absent);
    }

    #[test]
    fn startup_failure_reuses_helper_and_lease() {
        let mut machine = UserMachine::new(1000);
        machine.set_eligible_sessions(1);
        machine.helper_spawned(4);
        machine.add_pam_request(1);
        assert_eq!(
            machine.startup_failed(4),
            vec![Action::ScheduleBackoff {
                generation: 4,
                attempt: 2
            }]
        );
        assert_eq!(
            machine.backoff_elapsed(4, 2),
            vec![Action::StartManager {
                generation: 4,
                attempt: 2
            }]
        );
    }

    #[test]
    fn manager_crash_after_ready_restarts_with_same_generation() {
        let mut machine = UserMachine::new(1000);
        machine.set_eligible_sessions(1);
        machine.helper_spawned(8);
        machine.manager_spawned(8, 100);
        machine.ready_succeeded(8);
        assert_eq!(
            machine.manager_exited(8),
            vec![Action::ScheduleBackoff {
                generation: 8,
                attempt: 2
            }]
        );
        assert!(matches!(
            machine.state,
            UserManagerState::Backoff { generation: 8, .. }
        ));
    }

    #[test]
    fn login_during_stopping_waits_for_complete_exit() {
        let mut machine = UserMachine::new(1000);
        machine.set_eligible_sessions(1);
        machine.helper_spawned(2);
        machine.manager_spawned(2, 200);
        machine.ready_succeeded(2);
        machine.set_eligible_sessions(0);
        machine.add_pam_request(9);
        assert!(machine.set_eligible_sessions(1).is_empty());
        assert_eq!(machine.helper_exited(2), vec![Action::SpawnHelper]);
        assert_eq!(machine.pending_pam, vec![9]);
    }

    #[test]
    fn cancelled_pam_request_is_not_replied_later() {
        let mut machine = UserMachine::new(1000);
        machine.add_pam_request(42);
        machine.cancel_pam_request(42);
        machine.set_eligible_sessions(1);
        machine.helper_spawned(1);
        machine.manager_spawned(1, 100);
        assert!(machine.ready_succeeded(1).is_empty());
    }

    #[test]
    fn stale_helper_events_are_ignored() {
        let mut machine = UserMachine::new(1000);
        machine.set_eligible_sessions(1);
        machine.helper_spawned(5);
        assert!(machine.ready_succeeded(4).is_empty());
        assert!(machine.helper_exited(4).is_empty());
        assert_eq!(machine.state.generation(), Some(5));
    }
}
