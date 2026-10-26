# Copilot review instructions

## RTC output readiness

`Rtc::poll_output()` caches output readiness and the next timeout. Missing invalidation can
silently delay events, packets, or timers. When reviewing changes that affect live RTC state,
trace changed public mutation paths through their callees and check this invariant:

- Mutations that can affect events, transmitted packets, or the next timeout must invalidate
  the corresponding readiness cache before the next output poll.
- `DirectApi`, `SdpApi`, `Channel`, and `Bwe` use `RtcMut`. Its mutable dereference arms both
  signals; methods returning mutable references must also pass through that boundary.
- Direct `Rtc` methods and `Writer` use explicit wakes. Arm before a fallible mutation, or
  keep a method-local `Wake` alive across it, so errors and early returns after partial
  mutation still invalidate readiness. See `src/poll.rs` for the guard implementation.
- Treat every suppressed readiness flag as an invariant of the entire guarded operation.
  Revalidate it whenever that operation or any callee changes, even if the diff does not touch
  the suppression itself. Apply this to all current and future narrowed paths and guard types.
- `no_events()` asserts that no application event or outgoing packet becomes ready for polling.
  `no_timeout()` asserts that the cached next deadline remains valid: no timer is scheduled,
  moved, or cancelled, and no state used to derive the deadline changes. Check both direct
  mutations and indirect effects such as advancing time, changing queues, or enabling output.
- Trace all branches, helpers, early returns, and error paths before accepting suppression.
  A rejected or failed operation may already have changed state. For operations that process
  several items, the suppressed flag must remain valid for every item. Narrowing one operation
  must never clear readiness requested by another operation or discard already pending output.
- Every suppression needs regression coverage: begin with drained readiness, check both flags,
  and verify the output or deadline that must remain observable. Cover adjacent cases that must
  still wake, partial failures where relevant, and preservation of other operations' pending wakes.
  When changed behavior invalidates a suppression, retain the required wake and update the test;
  do not preserve outdated narrowing merely to satisfy existing assertions.
- Read-only access should preserve cached readiness. Builder changes that only accumulate
  pending configuration may defer invalidation until that configuration reaches live state.
- Preserve public borrowing behavior: a persistent guard with `Drop` in a public API handle
  can extend its mutable RTC borrow beyond its last use. Prefer mutation-scoped guards or
  handles that arm on mutable access without a destructor.

For a finding, identify a concrete mutation and the stale output or deadline it can cause,
or show a previously valid caller that stops compiling. Use the Writer borrow and failed
DTLS receive regressions in `tests/writer-borrow.rs` and `tests/dtls-error-readiness.rs` as
examples. Do not flag a missing explicit wake when `RtcMut` already provides invalidation.
