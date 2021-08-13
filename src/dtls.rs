use crate::rt::{mpsc, spawn, AsyncRead, AsyncWrite, Mutex};
use crate::sdp::Fingerprint;
use crate::util::unix_time;
use crate::Error;
use futures::future::FutureExt;
use openssl::asn1::{Asn1Integer, Asn1Time};
use openssl::bn::BigNum;
use openssl::ec::EcKey;
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::PKey;
use openssl::rsa::Rsa;
use openssl::ssl::{
    Error as SslError, ErrorCode, HandshakeError, MidHandshakeSslStream, Ssl, SslStream,
};
use openssl::ssl::{SslContext, SslContextBuilder, SslMethod, SslOptions, SslVerifyMode};
use openssl::x509::X509;
use std::io::{Error as IoErr, ErrorKind as IoErrKind, Read, Result as IoResult, Write};
use std::mem::replace;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::Waker;
use std::task::{Context, Poll};

const RSA_F4: u32 = 0x10001;
const DTLS_CIPHERS: &str = "EECDH+AESGCM:EDH+AESGCM:AES256+EECDH:AES256+EDH";
const DTLS_SRTP: &str = "SRTP_AES128_CM_SHA1_80";
const DTLS_EC_CURVE: Nid = Nid::X9_62_PRIME256V1;
const DTLS_KEY_LABEL: &str = "EXTRACTOR-dtls_srtp";

extern "C" {
    pub fn DTLSv1_2_method() -> *const openssl_sys::SSL_METHOD;
}

pub fn dtls_create_ctx() -> Result<(SslContext, Fingerprint), Error> {
    let method = unsafe { SslMethod::from_ptr(DTLSv1_2_method()) };
    let mut ctx = SslContextBuilder::new(method)?;

    ctx.set_cipher_list(DTLS_CIPHERS)?;
    ctx.set_tlsext_use_srtp(DTLS_SRTP)?;

    let mut mode = SslVerifyMode::empty();
    mode.insert(SslVerifyMode::PEER);
    mode.insert(SslVerifyMode::FAIL_IF_NO_PEER_CERT);
    ctx.set_verify_callback(mode, |_ok, _ctx| true);

    let f4 = BigNum::from_u32(RSA_F4).unwrap();
    let key = Rsa::generate_with_e(2048, &f4)?;
    let pkey = PKey::from_rsa(key)?;
    ctx.set_private_key(&pkey)?;

    let mut x509 = X509::builder()?;
    let serial_bn = BigNum::from_u32(1)?;
    let serial = Asn1Integer::from_bn(&serial_bn)?;
    x509.set_serial_number(&serial)?;
    let before = Asn1Time::from_unix(unix_time() - 3600)?;
    x509.set_not_before(&before)?;
    let after = Asn1Time::days_from_now(7)?;
    x509.set_not_after(&after)?;
    x509.set_pubkey(&pkey)?;

    x509.sign(&pkey, MessageDigest::sha1())?;
    let cert = x509.build();

    ctx.set_certificate(&cert)?;

    let mut options = SslOptions::empty();
    options.insert(SslOptions::SINGLE_ECDH_USE);
    options.insert(SslOptions::NO_DTLSV1);
    ctx.set_options(options);

    let ctx = ctx.build();

    let digest: &[u8] = &cert.digest(MessageDigest::sha256())?;
    let fp = Fingerprint {
        hash_func: "sha-256".into(),
        bytes: digest.to_vec(),
    };

    Ok((ctx, fp))
}

pub fn dtls_ssl_create(ctx: &SslContext) -> Result<Ssl, Error> {
    let mut ssl = Ssl::new(ctx)?;

    let eckey = EcKey::from_curve_name(DTLS_EC_CURVE)?;
    ssl.set_tmp_ecdh(&eckey)?;

    Ok(ssl)
}

#[derive(Debug)]
pub struct DtlsStream {
    remote_addr: SocketAddr,
    inner: State,
    rx_waker: WakeCell,
    tx_waker: WakeCell,
    was_running: bool,
    tx_event: mpsc::Sender<DtlsEvent>,
}

#[derive(Debug)]
pub enum DtlsEvent {
    Connected(SocketAddr, Fingerprint, SrtpKeyMaterial),
    Error(SocketAddr, String), // the actual error goes in poll_read/poll_write
}

pub struct SrtpKeyMaterial(pub [u8; 60]);

impl std::fmt::Debug for SrtpKeyMaterial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SrtpKeyMaterial")
    }
}

#[derive(Debug)]
enum State {
    Empty,
    Init(Ssl, SyncStream),
    Handshake(MidHandshakeSslStream<SyncStream>),
    Running(SslStream<SyncStream>),
}

impl State {
    fn as_running(&mut self) -> &mut SslStream<SyncStream> {
        if let State::Running(v) = self {
            return v;
        } else {
            panic!("as_running of non-Running");
        }
    }
}

impl DtlsStream {
    pub fn accept(
        remote_addr: SocketAddr,
        ssl: Ssl,
    ) -> (DtlsTx, DtlsRx, mpsc::Receiver<DtlsEvent>, Self) {
        let (tx_in, rx_in) = mpsc::channel(10);
        let tx = DtlsTx::new(tx_in);
        let rx_waker = tx.waker();

        let (tx_out, rx_out) = mpsc::channel(10);
        let rx = DtlsRx::new(rx_out);
        let tx_waker = rx.waker();

        let stream = SyncStream::new(rx_in, tx_out);

        let (tx_event, rx_event) = mpsc::channel(3);

        (
            tx,
            rx,
            rx_event,
            DtlsStream {
                remote_addr,
                inner: State::Init(ssl, stream),
                rx_waker,
                tx_waker,
                was_running: false,
                tx_event,
            },
        )
    }
}

impl DtlsStream {
    fn poll_init(&mut self, cx: &mut Context<'_>) -> Poll<IoResult<&mut SslStream<SyncStream>>> {
        let state = replace(&mut self.inner, State::Empty);

        match state {
            State::Empty => {
                panic!("Empty inner");
            }

            State::Init(ssl, stream) => match ssl.accept(stream) {
                Ok(v) => {
                    trace!("AsyncSslStream poll_init -> Running");
                    self.inner = State::Running(v);
                }
                Err(e) => {
                    return self.handle_handshake_err(e, cx);
                }
            },

            State::Handshake(v) => match v.handshake() {
                Ok(v) => {
                    trace!("AsyncSslStream poll_init -> Running");
                    self.inner = State::Running(v);
                }
                Err(e) => {
                    return self.handle_handshake_err(e, cx);
                }
            },

            State::Running(ssl) => {
                self.inner = State::Running(ssl);
            }
        }

        if !self.was_running {
            self.was_running = true;

            if self.on_first_running().is_none() {
                // abort
                return Poll::Ready(Err(IoErr::new(
                    IoErrKind::InvalidData,
                    "dtls bad client x509",
                )));
            }
        }

        let running = self.inner.as_running();

        Poll::Ready(Ok(running))
    }

    fn handle_handshake_err<T>(
        &mut self,
        e: HandshakeError<SyncStream>,
        cx: &mut Context<'_>,
    ) -> Poll<IoResult<T>> {
        match e {
            HandshakeError::SetupFailure(e) => {
                let error = Error::from(e);
                trace!("AsyncSslStream poll_init -> Failure: {:?}", error);
                return Poll::Ready(Err(IoErr::new(IoErrKind::Other, error)));
            }

            HandshakeError::Failure(e) => {
                let error = Error::from(e.into_error());
                trace!("AsyncSslStream poll_init -> Error: {:?}", error);
                return Poll::Ready(Err(IoErr::new(IoErrKind::InvalidData, error)));
            }

            HandshakeError::WouldBlock(v) => {
                let waker = cx.waker().clone();
                match v.error().code() {
                    ErrorCode::WANT_READ => {
                        trace!("AsyncSslStream poll_init WouldBlock: WANT_READ");
                        self.rx_waker.set(waker);
                    }
                    ErrorCode::WANT_WRITE => {
                        trace!("AsyncSslStream poll_init WouldBlock: WANT_WRITE");
                        self.tx_waker.set(waker);
                    }
                    _ => panic!("Handshake WouldBlock unknown code: {:?}", v.error().code()),
                }
                self.inner = State::Handshake(v);
                Poll::Pending
            }
        }
    }

    fn on_first_running(&mut self) -> Option<()> {
        let stream = self.inner.as_running();
        let ssl = stream.ssl();

        // remote peer certificate fingerprint
        let x509 = ssl.peer_certificate()?;
        let digest: &[u8] = &x509.digest(MessageDigest::sha256()).ok()?.to_vec();
        let fp = Fingerprint {
            hash_func: "sha-256".into(),
            bytes: digest.to_vec(),
        };

        // extract SRTP keying material
        let mut buf = [0_u8; 60];
        ssl.export_keying_material(&mut buf, DTLS_KEY_LABEL, None)
            .ok()?;
        let mat = SrtpKeyMaterial(buf);

        let tx_event = self.tx_event.clone();
        let event = DtlsEvent::Connected(self.remote_addr.clone(), fp, mat);
        spawn(async move {
            tx_event.send(event).await.ok();
        });

        Some(())
    }

    fn poll_read(&mut self, cx: &mut Context<'_>, buf: &mut [u8]) -> Poll<IoResult<usize>> {
        let ssl = match self.poll_init(cx) {
            Poll::Ready(v) => v,
            Poll::Pending => return Poll::Pending,
        }?;

        match ssl.ssl_read(buf) {
            Ok(n) => {
                trace!("AsyncSslStream ssl_read: {}", n);
                Poll::Ready(Ok(n))
            }
            Err(e) => self.handle_err(e, cx),
        }
    }

    fn poll_write(&mut self, cx: &mut Context<'_>, buf: &[u8]) -> Poll<IoResult<usize>> {
        let ssl = match self.poll_init(cx) {
            Poll::Ready(v) => v,
            Poll::Pending => return Poll::Pending,
        }?;

        match ssl.ssl_write(buf) {
            Ok(n) => {
                trace!("AsyncSslStream ssl_write: {}", n);
                Poll::Ready(Ok(n))
            }
            Err(e) => self.handle_err(e, cx),
        }
    }

    fn handle_err(&mut self, e: SslError, cx: &mut Context<'_>) -> Poll<IoResult<usize>> {
        match e.code() {
            ErrorCode::WANT_READ => {
                trace!("AsyncSslStream: WANT_READ");
                let waker = cx.waker().clone();
                self.rx_waker.set(waker);
                Poll::Pending
            }
            ErrorCode::WANT_WRITE => {
                trace!("AsyncSslStream: WANT_WRITE");
                let waker = cx.waker().clone();
                self.tx_waker.set(waker);
                Poll::Pending
            }
            _ => as_io_err(e),
        }
    }

    fn handle_err_event(&self, e: &IoErr) {
        let tx_event = self.tx_event.clone();
        let event = DtlsEvent::Error(self.remote_addr.clone(), e.to_string());
        spawn(async move {
            tx_event.send(event).await.ok();
        });
    }
}

fn as_io_err(e: SslError) -> Poll<IoResult<usize>> {
    match e.into_io_error() {
        Ok(ioe) if ioe.kind() == IoErrKind::UnexpectedEof => Poll::Ready(Ok(0)),
        Ok(ioe) => Poll::Ready(Err(ioe)),
        Err(e) => Poll::Ready(Err(IoErr::new(IoErrKind::Other, e))),
    }
}

impl AsyncRead for DtlsStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        rbuf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<IoResult<()>> {
        let this = self.get_mut();

        let buf = rbuf.initialize_unfilled();
        match this.poll_read(cx, buf) {
            Poll::Ready(Ok(amount)) => {
                rbuf.advance(amount);
                Ok(()).into()
            }
            Poll::Ready(Err(err)) => {
                this.handle_err_event(&err);
                Err(err).into()
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for DtlsStream {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<IoResult<usize>> {
        let this = self.get_mut();

        let ret = this.poll_write(cx, buf);

        if let Poll::Ready(Err(e)) = &ret {
            this.handle_err_event(e);
        }

        ret
    }
    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<IoResult<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<IoResult<()>> {
        Poll::Ready(Ok(()))
    }
}

#[derive(Debug, Clone)]
struct WakeCell(Arc<Mutex<Option<Waker>>>);

impl WakeCell {
    pub fn new() -> Self {
        WakeCell(Arc::new(Mutex::new(None)))
    }

    pub async fn wake(&self) {
        let mut lock = self.0.lock().await;
        if let Some(waker) = lock.take() {
            waker.wake();
        }
    }

    pub fn set(&self, waker: Waker) {
        // TODO can we improve this?
        let mut lock = loop {
            match self.0.try_lock() {
                Ok(v) => break v,
                Err(_) => continue,
            }
        };
        *lock = Some(waker);
    }
}

impl Drop for WakeCell {
    fn drop(&mut self) {
        let mut lock = loop {
            match self.0.try_lock() {
                Ok(v) => break v,
                Err(_) => continue,
            }
        };
        if let Some(waker) = lock.take() {
            waker.wake();
        }
    }
}

#[derive(Debug)]
pub struct DtlsTx(mpsc::Sender<Vec<u8>>, WakeCell);

impl DtlsTx {
    pub fn new(send: mpsc::Sender<Vec<u8>>) -> Self {
        DtlsTx(send, WakeCell::new())
    }

    fn waker(&self) -> WakeCell {
        self.1.clone()
    }

    pub async fn send(&mut self, value: Vec<u8>) {
        self.0.send(value).await.ok();
        self.1.wake().await;
    }
}

pub struct DtlsRx(mpsc::Receiver<Vec<u8>>, WakeCell);

impl DtlsRx {
    pub fn new(recv: mpsc::Receiver<Vec<u8>>) -> Self {
        DtlsRx(recv, WakeCell::new())
    }

    fn waker(&self) -> WakeCell {
        self.1.clone()
    }

    pub async fn recv(&mut self) -> Option<Vec<u8>> {
        let ret = self.0.recv().await;
        self.1.wake().await;
        ret
    }
}

#[derive(Debug)]
pub struct SyncStream {
    rx_in: mpsc::Receiver<Vec<u8>>,
    tx_out: mpsc::Sender<Vec<u8>>,
    rx_held: Option<Vec<u8>>,
}

impl SyncStream {
    pub fn new(rx_in: mpsc::Receiver<Vec<u8>>, tx_out: mpsc::Sender<Vec<u8>>) -> Self {
        SyncStream {
            rx_in,
            tx_out,
            rx_held: None,
        }
    }
}

impl Read for SyncStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let mut todo = if let Some(v) = self.rx_held.take() {
            v
        } else {
            // This is what we need. See https://github.com/tokio-rs/tokio/issues/3350
            // match self.rx_in.try_recv() {
            //     Ok(v) => v,
            //     Err(e) => match e {
            //         mpsc::error::TryRecvError::Closed => {
            //             return Ok(0);
            //         }
            //         mpsc::error::TryRecvError::Empty => {
            //             trace!("SyncStream read: WouldBlock");
            //             return Err(would_block());
            //         }
            //     },
            // }

            // This is band aid.
            match self.rx_in.recv().now_or_never() {
                Some(v) => match v {
                    Some(v) => v,
                    // channel closed
                    None => return Ok(0),
                },
                None => {
                    trace!("SyncStream read: WouldBlock");
                    return Err(would_block());
                }
            }
        };
        let max = todo.len().min(buf.len());
        (&mut buf[0..max]).copy_from_slice(&todo[0..max]);
        if max < todo.len() {
            let left = todo.split_off(max);
            self.rx_held = Some(left);
        }
        Ok(max)
    }
}

impl Write for SyncStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if let Err(e) = self.tx_out.try_send(buf.to_vec()) {
            match e {
                mpsc::error::TrySendError::Closed(_) => {
                    trace!("SyncStream write: end");
                    return Ok(0);
                }
                mpsc::error::TrySendError::Full(_) => {
                    trace!("SyncStream write: WouldBlock");
                    return Err(would_block());
                }
            }
        }
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn would_block() -> IoErr {
    IoErr::new(IoErrKind::WouldBlock, "would block")
}
