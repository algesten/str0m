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
- `no_events()` and `no_timeout()` require evidence that the entire operation, including
  callees and error paths, cannot affect the suppressed signal. Narrowing one operation
  must not clear readiness armed by another operation.
- Read-only access should preserve cached readiness. Builder changes that only accumulate
  pending configuration may defer invalidation until that configuration reaches live state.
- Preserve public borrowing behavior: a persistent guard with `Drop` in a public API handle
  can extend its mutable RTC borrow beyond its last use. Prefer mutation-scoped guards or
  handles that arm on mutable access without a destructor.

For a finding, identify a concrete mutation and the stale output or deadline it can cause,
or show a previously valid caller that stops compiling. Use the Writer borrow and failed
DTLS receive regressions in `tests/writer-borrow.rs` and `tests/dtls-error-readiness.rs` as
examples. Do not flag a missing explicit wake when `RtcMut` already provides invalidation.
