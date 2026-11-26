// SPDX-License-Identifier: MPL-2.0

//! The effective seccomp policy of one thread.
//!
//! Installation copies and validates a cBPF program before publishing an
//! immutable filter chain. Syscall entry evaluates a stable snapshot, and
//! fork/clone share that chain while retaining independent per-thread heads.
//!
//! Adapted from upstream Asterinas PR #4249. The user-notification listener
//! (`SECCOMP_RET_USER_NOTIF`, `SECCOMP_FILTER_FLAG_NEW_LISTENER`) is not
//! implemented: installing a filter that can return `USER_NOTIF` fails with
//! `EINVAL`, and querying it with `SECCOMP_GET_ACTION_AVAIL` fails with
//! `EOPNOTSUPP`.

use super::{
    abi::{
        MODE_FILTER, MODE_STRICT, RET_ACTION_FULL, RET_ALLOW, RET_DATA, RET_ERRNO, RET_KILL_THREAD,
        RET_LOG, RET_TRACE, RET_TRAP, RET_USER_NOTIF, SeccompData,
    },
    cbpf::VerifiedProgram,
};
use crate::prelude::*;

// Linux's seccomp_attach_filter() charges four extra instructions per old filter:
// <https://github.com/torvalds/linux/blob/v6.18/kernel/seccomp.c>.
const MAX_INSNS_PER_PATH: usize = 32768;
const PREVIOUS_FILTER_PENALTY: usize = 4;
const MAX_ERRNO: u32 = 4095;

/// The effective seccomp policy of one thread.
#[derive(Clone, Default)]
pub(crate) struct SeccompState {
    policy: Policy,
}

/// A policy attached to a thread, distinct from a temporary evaluation snapshot.
pub(crate) struct ThreadSeccompState {
    state: SeccompState,
}

impl ThreadSeccompState {
    pub(crate) fn new(state: SeccompState) -> Self {
        Self { state }
    }

    pub(crate) fn snapshot(&self) -> SeccompState {
        self.state.clone()
    }

    pub(crate) fn status(&self) -> (u32, usize) {
        (self.state.mode(), self.state.filter_count())
    }
}

#[derive(Clone, Default)]
enum Policy {
    #[default]
    Disabled,
    Strict,
    Filter(Arc<FilterNode>),
}

struct FilterNode {
    program: VerifiedProgram,
    previous: Option<Arc<FilterNode>>,
    path_insns: usize,
    logging: bool,
}

/// A syscall disposition and the optional action selected for logging.
pub(crate) struct SeccompEvaluation {
    decision: SeccompDecision,
    logged_action: Option<u32>,
}

impl SeccompEvaluation {
    pub(crate) fn decision(&self) -> &SeccompDecision {
        &self.decision
    }

    /// Emits the selected seccomp log record, if any.
    pub(crate) fn log(&self, ctx: &Context, data: &SeccompData) {
        if let Some(action) = self.logged_action {
            warn!(
                "seccomp: pid={} tid={} syscall={} arch={:#x} ip={:#x} action={:#x}",
                ctx.process.pid(),
                ctx.posix_thread.tid(),
                data.syscall_number(),
                data.arch(),
                data.instruction_pointer(),
                action,
            );
        }
    }
}

/// A syscall disposition after merging every installed filter.
pub(crate) enum SeccompDecision {
    Allow,
    Errno(u32),
    Trap(u32),
    #[expect(dead_code)]
    Trace(u32),
    KillThread,
    KillProcess,
    StrictViolation,
}

impl SeccompState {
    pub(crate) fn mode(&self) -> u32 {
        match self.policy {
            Policy::Disabled => 0,
            Policy::Strict => MODE_STRICT,
            Policy::Filter(_) => MODE_FILTER,
        }
    }

    fn filter_count(&self) -> usize {
        let mut count = 0;
        let mut node = self.head();
        while let Some(filter) = node {
            count += 1;
            node = filter.previous.as_ref();
        }
        count
    }

    pub(crate) fn is_strict(&self) -> bool {
        matches!(self.policy, Policy::Strict)
    }

    pub(super) fn to_strict(&self) -> Result<Self> {
        if !matches!(self.policy, Policy::Disabled | Policy::Strict) {
            return Err(errno!(EINVAL, "cannot change seccomp filter mode to strict"));        }
        Ok(Self {
            policy: Policy::Strict,
        })
    }

    fn head(&self) -> Option<&Arc<FilterNode>> {
        match &self.policy {
            Policy::Filter(head) => Some(head),
            _ => None,
        }
    }

    /// Checks whether this policy can receive a TSYNC update from `source`.
    ///
    /// A disabled target can receive the update. A filtered target must share
    /// a chain suffix with `source` starting at the target's current head.
    /// Strict policies are ineligible.
    pub(super) fn can_sync_from(&self, source: &Self) -> bool {
        if self.is_strict() || source.is_strict() {
            return false;
        }
        let Some(head) = self.head() else {
            return true;
        };
        let mut node = source.head();
        while let Some(filter) = node {
            if Arc::ptr_eq(head, filter) {
                return true;
            }
            node = filter.previous.as_ref();
        }
        false
    }

    pub(super) fn append(&self, program: VerifiedProgram, logging: bool) -> Result<Self> {
        if self.is_strict() {
            return Err(errno!(EINVAL, "cannot change strict seccomp mode to filter"));        }
        let path_insns = program.len()
            + self
                .head()
                .map_or(0, |head| head.path_insns + PREVIOUS_FILTER_PENALTY);
        if path_insns > MAX_INSNS_PER_PATH {
            return Err(errno!(ENOMEM, "seccomp filter chain is too long"));        }

        let head = Arc::new(FilterNode {
            program,
            previous: self.head().cloned(),
            path_insns,
            logging,
        });

        Ok(Self {
            policy: Policy::Filter(head),
        })
    }

    pub(crate) fn evaluate(&self, data: &SeccompData) -> SeccompEvaluation {
        if self.is_strict() {
            return if crate::syscall::strict_seccomp_allows(data.syscall_number()) {
                SeccompEvaluation {
                    decision: SeccompDecision::Allow,
                    logged_action: None,
                }
            } else {
                SeccompEvaluation {
                    decision: SeccompDecision::StrictViolation,
                    logged_action: Some(RET_KILL_THREAD),
                }
            };
        }
        let mut winner = (RET_ALLOW, None);
        let mut node = self.head().map(Arc::as_ref);
        while let Some(filter) = node {
            let current = filter.program.run(data);
            // Linux compares signed actions so KILL_PROCESS precedes KILL_THREAD.
            // Strict inequality retains the newest filter's data on a tie.
            if ((current & RET_ACTION_FULL) as i32) < ((winner.0 & RET_ACTION_FULL) as i32) {
                winner = (current, Some(filter));
            }
            node = filter.previous.as_deref();
        }

        let (result, winning_filter) = winner;
        let action = result & RET_ACTION_FULL;
        let requested_log = winning_filter
            .is_some_and(|filter| filter.logging)
            .then_some(action);
        let (decision, logged_action) = match action {
            RET_ALLOW => (SeccompDecision::Allow, None),
            RET_LOG => (SeccompDecision::Allow, Some(action)),
            RET_ERRNO => (
                SeccompDecision::Errno((result & RET_DATA).min(MAX_ERRNO)),
                requested_log,
            ),
            RET_TRAP => (SeccompDecision::Trap(result & RET_DATA), requested_log),
            RET_TRACE => (SeccompDecision::Trace(result & RET_DATA), requested_log),
            RET_USER_NOTIF => {
                // No notification listener is implemented; a filter that
                // dynamically computes USER_NOTIF cannot be supervised, so
                // treat it like an unknown action and kill the process.
                (SeccompDecision::KillProcess, Some(action))
            }
            RET_KILL_THREAD => (SeccompDecision::KillThread, Some(action)),
            // Unknown actions kill the process and retain the original action in the log.
            _ => (SeccompDecision::KillProcess, Some(action)),
        };
        SeccompEvaluation {
            decision,
            logged_action,
        }
    }
}

impl Drop for FilterNode {
    fn drop(&mut self) {
        // A valid chain can contain thousands of one-instruction programs.
        // Release its unique tail iteratively instead of recursing on the kernel stack.
        let mut previous = self.previous.take();
        while let Some(node) = previous {
            match Arc::into_inner(node) {
                Some(mut node) => previous = node.previous.take(),
                None => break,
            }
        }
    }
}
