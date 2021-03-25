use std::future::Future;

pub use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite};
pub use tokio::net::UdpSocket;
pub use tokio::select;
pub use tokio::sync::mpsc;
pub use tokio::sync::oneshot;
pub use tokio::sync::Mutex;

pub fn init() {
    hreq::AsyncRuntime::TokioShared.make_default();
}

pub fn spawn<T>(task: T)
where
    T: Future + Send + 'static,
    T::Output: Send + 'static,
{
    tokio::spawn(task);
}
