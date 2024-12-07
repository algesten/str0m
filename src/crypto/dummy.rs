#![allow(unused_variables)]

use crate::crypto::srtp::{aead_aes_128_gcm, aes_128_cm_sha1_80};
use crate::crypto::CryptoError;
use crate::crypto::DtlsEvent;
use crate::crypto::Fingerprint;
use crate::net::DatagramSend;
use std::collections::VecDeque;
use std::time::Instant;

#[derive(Clone, Debug)]
pub struct Cert {}

pub struct Dtls {}

#[derive(Debug, thiserror::Error)]
pub enum Error {}

impl Cert {
    pub fn new() -> Self {
        Self {}
    }

    pub fn fingerprint(&self) -> Fingerprint {
        unimplemented!("dummy crypto")
    }
}

impl Dtls {
    pub fn new(_: Cert) -> Result<Self, CryptoError> {
        Ok(Self {})
    }

    pub fn set_active(&mut self, active: bool) {
        unimplemented!("dummy crypto")
    }

    pub fn handle_handshake(&mut self, o: &mut VecDeque<DtlsEvent>) -> Result<bool, CryptoError> {
        unimplemented!("dummy crypto")
    }

    pub fn is_active(&self) -> Option<bool> {
        unimplemented!("dummy crypto")
    }

    pub fn handle_receive(
        &mut self,
        m: &[u8],
        o: &mut VecDeque<DtlsEvent>,
    ) -> Result<(), CryptoError> {
        unimplemented!("dummy crypto")
    }

    pub fn poll_datagram(&mut self) -> Option<DatagramSend> {
        unimplemented!("dummy crypto")
    }

    pub fn poll_timeout(&mut self, now: Instant) -> Option<Instant> {
        unimplemented!("dummy crypto")
    }

    pub fn handle_input(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        unimplemented!("dummy crypto")
    }

    pub fn is_connected(&self) -> bool {
        unimplemented!("dummy crypto")
    }
}

pub struct Aes128CmSha1_80;

pub struct AeadAes128Gcm;

pub fn srtp_aes_128_ecb_round(key: &[u8], input: &[u8], output: &mut [u8]) {
    unimplemented!("dummy crypto")
}

impl Aes128CmSha1_80 {
    pub(crate) fn new(key: aes_128_cm_sha1_80::AesKey, encrypt: bool) -> Self {
        Self {}
    }

    pub(crate) fn encrypt(
        &mut self,
        iv: &aes_128_cm_sha1_80::RtpIv,
        input: &[u8],
        output: &mut [u8],
    ) -> Result<(), CryptoError> {
        unimplemented!("dummy crypto")
    }

    pub(crate) fn decrypt(
        &mut self,
        iv: &aes_128_cm_sha1_80::RtpIv,
        input: &[u8],
        output: &mut [u8],
    ) -> Result<(), CryptoError> {
        unimplemented!("dummy crypto")
    }
}

impl AeadAes128Gcm {
    pub(crate) fn new(key: aead_aes_128_gcm::AeadKey, encrypt: bool) -> Self {
        Self {}
    }

    pub(crate) fn encrypt(
        &mut self,
        iv: &[u8; aead_aes_128_gcm::IV_LEN],
        aad: &[u8],
        input: &[u8],
        output: &mut [u8],
    ) -> Result<(), CryptoError> {
        unimplemented!("dummy crypto")
    }

    pub(crate) fn decrypt(
        &mut self,
        iv: &[u8; aead_aes_128_gcm::IV_LEN],
        aads: &[&[u8]],
        input: &[u8],
        output: &mut [u8],
    ) -> Result<usize, CryptoError> {
        unimplemented!("dummy crypto")
    }
}
