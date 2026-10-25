//! This can be empty since feature flags are additive, and the _internal_test_exports
//! is enabled for str0m in the main compilation unit.
// Avoid rewriting existing code: nested conditions are often more readable than long if-chains.
#![allow(clippy::collapsible_if)]
