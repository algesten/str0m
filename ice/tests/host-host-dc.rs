use std::time::Duration;

use str0m_ice::{IceAgentEvent, IceAgentStats, IceConnectionState};
use tracing::info_span;

mod common;
use common::{host, init_log, progress, TestAgent};
