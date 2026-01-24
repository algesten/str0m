# Resume: GitHub Issue #839 - Transaction-based Type-State API

## Overview

Working on str0m (a sans-I/O WebRTC implementation) to implement a transaction-based type-state API that enforces poll-to-timeout at compile time.

**Issue**: https://github.com/algesten/str0m/issues/839

## What Was Done

1. Initial implementation was created but **completely misunderstood the task**
2. User restructured the entire API and left `todo!()` markers for implementation
3. Fixed various code style issues (fully qualified paths, transaction patterns)

## Current State

The user has created the new API structure. Your job is to implement the `todo!()` markers.

### Key Files

- **`src/tx.rs`** - New transaction API with `RtcTx<'a, State>` type
- **`src/ice/mod.rs`** - Ice sub-API wrapper (renamed from `src/ice_.rs`)
- **`src/ice_.rs`** - Original ICE implementation (internal)
- **`src/io/mod.rs`** - Network I/O types (`Receive` struct modified)
- **`src/lib.rs`** - Main library with `Rtc::begin()` returning `RtcTx<'a, Mutate>`

## Transaction Pattern

```rust
// ONE transaction per loop iteration
loop {
    // Wait for input or timeout
    let input = wait_for_input_or_timeout(timeout);

    let tx = rtc.begin(Instant::now());

    let poll_tx = if let Some(data) = input {
        tx.receive(data)?
    } else {
        tx.finish()?
    };

    // Poll to completion
    loop {
        match poll_tx.poll()? {
            Output::Timeout(t) => { timeout = t; break; }
            Output::Transmit(tx, t) => { send(t); poll_tx = tx; }
            Output::Event(tx, e) => { handle(e); poll_tx = tx; }
        }
    }
}
```

## TODO Markers to Implement

### In `src/tx.rs`

1. **`ice()`** (line ~91) - Return `Ice<'a>` taking ownership of transaction
2. **`sdp_api()`** (line ~115) - Return `SdpApi<'a>`
3. **`direct_api()`** (line ~122) - Return `DirectApi<'a>`
4. **`bwe()`** (line ~148) - Return `Bwe<'a>`
5. **`channel()`** (line ~167) - Return `Result<Channel<'a>, Self>`
6. **`writer()`** (line ~199) - Return `Result<Writer<'a>, Self>`

### In `src/ice/mod.rs`

The `Ice<'a>` struct exists wrapping `RtcTx<'a, Mutate>`:

```rust
pub struct Ice<'a> {
    tx: RtcTx<'a, Mutate>,
}
```

Need to implement:

1. **`new()`** - Constructor (crate-visible)
2. **`add_local_candidate()`** - Delegate to `rtc.ice.add_local_candidate()`
3. **`add_remote_candidate()`** - Delegate to `rtc.ice.add_remote_candidate()`
4. **`finish()`** - Transition to `RtcTx<'a, Poll>` (already exists, verify implementation)

### Similar patterns needed for:
- `Bwe<'a>` in `src/bwe/mod.rs`
- `Channel<'a>` in `src/channel/mod.rs`
- `Writer<'a>` in `src/media/writer.rs`
- `SdpApi<'a>` in `src/change/sdp.rs`
- `DirectApi<'a>` in `src/change/direct.rs`

## Implementation Pattern

For each sub-API wrapper:

```rust
pub struct SubApi<'a> {
    tx: RtcTx<'a, Mutate>,
}

impl<'a> SubApi<'a> {
    pub(crate) fn new(tx: RtcTx<'a, Mutate>) -> Self {
        Self { tx }
    }

    // Domain-specific methods that access inner Rtc
    pub fn some_method(&mut self) {
        let inner = self.tx.inner.as_mut().expect("inner");
        // Call inner.rtc.some_method()
    }

    pub fn finish(mut self) -> Result<RtcTx<'a, Poll>, RtcError> {
        let mut inner = self.tx.take_inner();
        inner.ret.take().unwrap()?;
        Ok(RtcTx {
            inner: Some(inner),
            _state: PhantomData,
        })
    }
}
```

## Code Style Rules

1. **NO fully qualified paths** - Always use `use` statements
   - Bad: `std::time::Duration::from_micros(1)`
   - Good: `use std::time::Duration;` then `Duration::from_micros(1)`

2. **NO crate-qualified imports either**
   - Bad: `crate::ice::Ice`
   - Good: `use crate::ice::Ice;` then just `Ice`

3. **One transaction per loop** - Don't start with standalone `begin().finish().poll()` then do mutation

## Key Structures

### `RtcTxInner<'a>`
```rust
struct RtcTxInner<'a> {
    rtc: &'a mut Rtc,
    ret: Option<Result<(), RtcError>>,
}
```

### `RtcTx<'a, State>`
```rust
pub struct RtcTx<'a, State> {
    inner: Option<RtcTxInner<'a>>,
    _state: PhantomData<State>,
}
```

- `take_inner()` takes the Option to prevent Drop panic during transitions
- Drop panics if `inner` is still `Some` (transaction not completed)

## Tests

- `tests/handshake-direct.rs` - Uses the new transaction API
- Tests in `src/tx.rs` verify panic on incomplete drop

## Helpful Commands

```bash
cargo build          # Check compilation
cargo test           # Run all tests
cargo test handshake # Run handshake tests specifically
```

## Next Steps

1. Read `src/ice/mod.rs` to see the current Ice structure
2. Implement `Ice::new()` constructor
3. Implement `add_local_candidate()` and `add_remote_candidate()` by accessing `self.tx.inner.as_mut().unwrap().rtc`
4. Implement `tx.ice()` in `src/tx.rs` to return `Ice::new(self)`
5. Check if `Ice::finish()` is already implemented correctly
6. Repeat pattern for other sub-APIs (Bwe, Channel, Writer, SdpApi, DirectApi)
7. Ensure all tests pass
