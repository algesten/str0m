use std::fmt;

/// Media direction.
///
/// And also extmap direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// Send only direction.
    SendOnly,
    /// Receive only direction.
    RecvOnly,
    /// Bi-directional.
    SendRecv,
    /// Disabled direction.
    Inactive,
}

impl Direction {
    pub fn invert(&self) -> Self {
        match self {
            Direction::SendOnly => Direction::RecvOnly,
            Direction::RecvOnly => Direction::SendOnly,
            _ => *self,
        }
    }
}

impl From<&str> for Direction {
    fn from(v: &str) -> Self {
        use Direction::*;
        match v {
            "sendonly" => SendOnly,
            "recvonly" => RecvOnly,
            "sendrecv" => SendRecv,
            _ => Inactive,
        }
    }
}

impl fmt::Display for Direction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Direction::SendOnly => "sendonly",
                Direction::RecvOnly => "recvonly",
                Direction::SendRecv => "sendrecv",
                Direction::Inactive => "inactive",
            }
        )
    }
}
