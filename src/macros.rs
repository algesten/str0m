/// Shorthand for unwrap_or_else to provide context for panics.
///
/// The macro should be used similar to `assert!` with an intermediary `maybe_value` or `result_value`.
///
/// ```ignore
/// let maybe_value = my_values.iter().find(|x| == 42);
/// let value = assume!(maybe_value, "The value should be defined because: {:?}", something);
/// ```
macro_rules! assume {
    ($exp:expr, $($arg:tt)*) => {{
        $exp.unwrap_or_else(|| panic!("{}", std::fmt::format(core::format_args!($($arg)*))))
    }}
}
