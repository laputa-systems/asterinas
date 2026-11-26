# Handoff: bctl-related branches in this checkout

Owner: another agent working in `/Users/josh/repos/bctl`. These branches are
deliberately **not** integrated into `main` here. Do not retire their worktrees
or delete their branches without that owner's decision.

Captured from integration checkout `main` at
`2826f4446637c48254cac5665a9ca0095b7ce43a` (2026-11-26).

## Branch inventory

| Branch | HEAD | Worktree | Own commits beyond `fleet/scoped-clean` | Lane |
| --- | --- | --- | --- | --- |
| `fleet/scoped-clean` | `e310190ae` | none | 211 (shared fork baseline) | fork mainline: lint, CI, build scoping |
| `feat/bctl-as1-seccomp` | `f9fc68452` | `.work/wt/as1-seccomp` | 5 | seccomp(2) with classic-BPF filtering |
| `feat/bctl-as2-pidns` | `ad28234e1` | `.work/wt/as2-pidns` | 5 | PID namespaces (port of upstream PR #3025) |
| `feat/bctl-as2-userns` | `cb4890d4a` | `.work/wt/as2-userns` | 7 | user namespaces for Chromium zygote sandbox |
| `feat/bctl-as3-ipc` | `726f2155c` | `.work/wt/as3-ipc` | 6 | Chromium IPC tail, robust lists, seals-gated mappings |

All four lane worktrees are clean (`git status --porcelain` empty).

## Shape of the fork lineage

All five branches share merge base `12374d1337d21f2d0dbe39c5cab340b41c58e553`
("Add x86-64 ptrace floating-point regset", 2026-11-10) with `main`. Each lane
branch is `fleet/scoped-clean` plus only its own 5–7 commits, so the large
divergence below is shared fork baseline, not lane work:

- Each lane branch: 199–201 commits ahead of `main`, 273 behind `main`.
- Each lane branch: ~838–848 files changed, ~100k insertions vs the merge base
  (includes the fork's own `errno!` migration, mycrates registries, openat2,
  frame reclamation, netlink fixes, lint/CI changes).

`main` has since implemented PID and user namespaces independently
(`kernel/core/src/process/namespace/pid_ns.rs`, `user_ns.rs`). `main` has **no**
seccomp syscall implementation and no System V IPC implementation. Any port to
`main` must therefore be selective: reapply the 5–7 lane commits (or their
net diff against `fleet/scoped-clean`), not a whole-lineage merge.

## Lane-specific commits

`feat/bctl-as1-seccomp`:
- `a08c86622` feat(seccomp): implement seccomp(2) with classic-BPF filtering
- `76b7a5330` fix(seccomp): allocate filter nodes with `Arc::new`
- `693980aa8` fix(seccomp): adapt error returns and imports to the fork's APIs
- `00335eb55` fix(seccomp): close `Err` wrappers on error returns
- `f9fc68452` fix(seccomp): import `LinuxAbi` for `set_syscall_ret` in trap path

`feat/bctl-as2-pidns`:
- `532081159` feat(pidns): port PID namespaces from upstream PR #3025
- `7349a9760` fix(pidns): address first-round build errors and test/docs gaps
- `17551206e` fix(pidns): always deliver SIGKILL/SIGSTOP to namespace inits
- `f18d890da` fix(test): rename sched syscall wrappers for glibc 2.42 compat
- `ad28234e1` fix(test): repair network test includes for initramfs build

`feat/bctl-as2-userns`:
- `fb10eb8e8` feat(userns): implement user namespaces for Chromium zygote sandbox
- `d92889a5d` fix(userns): correct translation helpers and ancestor-check signature
- `5ba60ca89` style(userns): format changed lines per rustfmt
- `3ac15e1fd` style(userns): merge re-export into existing use block
- `036150b67` fix(test): make user_ns regression test compile under `-Werror`
- `d7cdfe94b` fix(test): rename local sched wrappers clashing with glibc 2.42
- `cb4890d4a` fix(test): use common `test.h` path in network regression tests

`feat/bctl-as3-ipc`:
- `d9324a4fb` fix(ipc): complete Chromium IPC tail (cmp-requeue, robust, dontwait, nested epoll)
- `48dcfb315` fix(ipc): drop redundant `CurrentUserSpace` import
- `a3b7383fd` debug: temporary robust-list tracing for BCTL-87 diagnosis
- `c6a967fb0` feat(ipc): implement `get_robust_list` for musl robust-mutex probing
- `63ec3cf28` fix(ipc): seals-gated read mappings and SIGBUS on truncated access
- `726f2155c` Revert "debug: temporary robust-list tracing for BCTL-87 diagnosis"

## Live bridge leases — release before any retirement

| Worktree | Lease owner file | Session ID |
| --- | --- | --- |
| `as1-seccomp` | `.work/worker-bridge/.active-worktree-f7f647…/owner.json` | `usrw_693ca722-1a65-44c4-b446-4d0ac11002d0` |
| `as2-pidns` | `.work/worker-bridge/.active-worktree-b6aaf0…/owner.json` | `usrw_4b124866-252b-4d93-a4bf-421242c02080` |
| `as2-userns` | `.work/worker-bridge/.active-worktree-273903…/owner.json` | `usrw_a48d3e04-437f-47c3-b884-0cf9d3437ee5` |
| `as3-ipc` | `.work/worker-bridge/.active-worktree-99f9e7…/owner.json` | `usrw_1e4936d5-2605-46c0-929b-a71b297dfad1` |

`worktree-retire <path> --into main --dry-run` refuses all four:
`<sha> is not integrated into 2826f444…`. That refusal is correct — the content
is not integrated here. Do not waive it or force-delete a branch/worktree.

## Related branch, not clearly bctl-owned

`upstream-pidns` (`f11d2167a`, 14 commits ahead / 1634 behind `main`) is an early
PID-namespace prototype ending in commits `tmp`/`tmp1`. `main` already carries a
PID namespace implementation, so this appears superseded; confirm with the
bctl owner before deleting it.

## Suggested next steps for the owner

1. Confirm which lanes are accepted in the bctl campaign.
2. Port each accepted lane's 5–7 commits (or `git diff fleet/scoped-clean..<branch>`)
   onto the target branch; expect conflicts where `main` already changed the
   same files, especially PID/user namespaces.
3. Run the fork's `make lint` / build / ktest gates on the result.
4. Release the bridge leases above, then retire only accepted, integrated
   worktrees with `worktree-retire <path> --into <integration-head>`.

## Evidence commands

```sh
git branch -vv
git worktree list --porcelain
git merge-base main feat/bctl-as1-seccomp
git rev-list --count main..feat/bctl-as1-seccomp   # 199
git rev-list --count feat/bctl-as1-seccomp..main    # 273
git log --oneline fleet/scoped-clean..feat/bctl-as1-seccomp
git diff --stat "$(git merge-base main feat/bctl-as1-seccomp)" feat/bctl-as1-seccomp
cat .work/worker-bridge/.active-worktree-*/owner.json
```
