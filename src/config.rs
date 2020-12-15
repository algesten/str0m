#![allow(dead_code)]

use std::str::FromStr;

pub fn get_config(var: &str) -> String {
    let val = std::env::var(var).ok();
    debug!("Read env var {}: {:?}", var, val);
    val.unwrap_or_else(|| panic!("Missing env var: {}", var))
}

pub fn get_config_as<T: FromStr>(var: &str) -> T
where
    <T as FromStr>::Err: std::fmt::Debug,
{
    let val = get_config(var);
    val.parse()
        .unwrap_or_else(|_| panic!("Can't parse env var ({}) value: {}", var, val))
}

pub fn get_config_or(var: &str, or: &str) -> String {
    let val = std::env::var(var).ok();
    debug!("Read env var {}: {:?} (default: {})", var, val, or);
    val.unwrap_or_else(|| or.into())
}

pub fn get_config_as_or<T: FromStr>(var: &str, or: T) -> T
where
    <T as FromStr>::Err: std::fmt::Debug,
    T: std::fmt::Display,
{
    let val = std::env::var(var).ok();
    debug!("Read env var {}: {:?} (default: {})", var, val, or);
    val.and_then(|c| c.parse().ok()).unwrap_or(or)
}
