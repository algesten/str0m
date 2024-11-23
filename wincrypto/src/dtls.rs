use std::time::{Duration, Instant};

use super::{WinCryptoCertificate, WinCryptoError};
use std::collections::VecDeque;
use std::sync::Arc;
use windows::Win32::{
    Foundation::{
        SEC_E_MESSAGE_ALTERED, SEC_E_OK, SEC_E_OUT_OF_SEQUENCE, SEC_I_CONTEXT_EXPIRED,
        SEC_I_CONTINUE_NEEDED, SEC_I_MESSAGE_FRAGMENT, SEC_I_RENEGOTIATE,
    },
    Security::{
        Authentication::Identity::{
            AcceptSecurityContext, AcquireCredentialsHandleW, DecryptMessage,
            DeleteSecurityContext, EncryptMessage, FreeContextBuffer, FreeCredentialsHandle,
            InitializeSecurityContextW, QueryContextAttributesExW, QueryContextAttributesW,
            SecBuffer, SecBufferDesc, SecPkgContext_KeyingMaterial,
            SecPkgContext_KeyingMaterialInfo, SecPkgContext_SrtpParameters,
            SecPkgContext_StreamSizes, SetContextAttributesW, ASC_REQ_CONFIDENTIALITY,
            ASC_REQ_DATAGRAM, ASC_REQ_EXTENDED_ERROR, ASC_REQ_INTEGRITY, ASC_REQ_MUTUAL_AUTH,
            ISC_REQ_CONFIDENTIALITY, ISC_REQ_DATAGRAM, ISC_REQ_EXTENDED_ERROR, ISC_REQ_INTEGRITY,
            ISC_REQ_MANUAL_CRED_VALIDATION, ISC_REQ_USE_SUPPLIED_CREDS, SCHANNEL_CRED,
            SCHANNEL_CRED_VERSION, SCH_CRED_MANUAL_CRED_VALIDATION, SECBUFFER_ALERT,
            SECBUFFER_DATA, SECBUFFER_DTLS_MTU, SECBUFFER_EMPTY, SECBUFFER_EXTRA,
            SECBUFFER_SRTP_PROTECTION_PROFILES, SECBUFFER_STREAM_HEADER, SECBUFFER_STREAM_TRAILER,
            SECBUFFER_TOKEN, SECBUFFER_VERSION, SECPKG_ATTR, SECPKG_ATTR_KEYING_MATERIAL,
            SECPKG_ATTR_KEYING_MATERIAL_INFO, SECPKG_ATTR_REMOTE_CERT_CONTEXT,
            SECPKG_ATTR_SRTP_PARAMETERS, SECPKG_ATTR_STREAM_SIZES, SECPKG_CRED_INBOUND,
            SECPKG_CRED_OUTBOUND, SECURITY_NATIVE_DREP, SEC_DTLS_MTU, SP_PROT_DTLS1_2_CLIENT,
            SP_PROT_DTLS1_2_SERVER, UNISP_NAME_W,
        },
        Credentials::SecHandle,
        Cryptography::CERT_CONTEXT,
    },
};

#[repr(C)]
struct SrtpProtectionProfilesBuffer {
    count: u16,
    profiles: [u16; 2], // Big-Endian Encoded values.
}
const SRTP_PROTECTION_PROFILES_BUFFER_INSTANCE: SrtpProtectionProfilesBuffer =
    SrtpProtectionProfilesBuffer {
        count: 4,
        // These are encoded as BE, since SChannel seemingly copies this buffer verbatim.
        profiles: [
            u16::to_be(0x0007), /* SRTP_AES128_GCM (RFC7714 Sec 14.2) */
            u16::to_be(0x0001), /* SRTP_AES128_CM_SHA1_80 (RFC5764 Section 4.1.2) */
        ],
    };
const SRTP_PROTECTION_PROFILES_SECBUFFER: SecBuffer = SecBuffer {
    cbBuffer: std::mem::size_of::<SrtpProtectionProfilesBuffer>() as u32,
    BufferType: SECBUFFER_SRTP_PROTECTION_PROFILES,
    pvBuffer: &SRTP_PROTECTION_PROFILES_BUFFER_INSTANCE as *const _ as *mut _,
};

const DTLS_MTU_BUFFER_INSTANCE: SEC_DTLS_MTU = SEC_DTLS_MTU {
    PathMTU: DATAGRAM_MTU as u16,
};
const DTLS_MTU_SECBUFFER: SecBuffer = SecBuffer {
    cbBuffer: std::mem::size_of::<SEC_DTLS_MTU>() as u32,
    BufferType: SECBUFFER_DTLS_MTU,
    pvBuffer: &DTLS_MTU_BUFFER_INSTANCE as *const _ as *mut _,
};

const DTLS_KEY_LABEL: &[u8] = b"EXTRACTOR-dtls_srtp\0";
const DATAGRAM_MTU: usize = 1150;

#[derive(Clone, Copy, Debug, PartialEq)]
enum EstablishmentState {
    Idle,
    Handshaking,
    Established,
    Failed,
}

pub enum WinCryptoDtlsEvent {
    None,
    WouldBlock,
    Connected {
        srtp_profile_id: u16,
        srtp_keying_material: Vec<u8>,
        peer_fingerprint: [u8; 32],
    },
    Data(Vec<u8>),
}

pub struct WinCryptoDtls {
    cert: Arc<WinCryptoCertificate>,
    is_client: Option<bool>,
    state: EstablishmentState,
    cred_handle: Option<SecHandle>,
    security_ctx: Option<SecHandle>,
    encrypt_message_input_sizes: SecPkgContext_StreamSizes,

    output: VecDeque<Vec<u8>>,
}

impl WinCryptoDtls {
    pub fn new(cert: Arc<WinCryptoCertificate>) -> Result<Self, WinCryptoError> {
        Ok(WinCryptoDtls {
            cert,
            is_client: None,
            state: EstablishmentState::Idle,
            cred_handle: None,
            security_ctx: None,
            encrypt_message_input_sizes: SecPkgContext_StreamSizes::default(),
            output: VecDeque::default(),
        })
    }

    pub fn is_client(&self) -> Option<bool> {
        self.is_client
    }

    pub fn is_connected(&self) -> bool {
        self.state == EstablishmentState::Established
    }

    pub fn set_as_client(&mut self, active: bool) {
        self.is_client = Some(active);

        let mut cert_contexts = [self.cert.0];

        let schannel_cred = SCHANNEL_CRED {
            dwVersion: SCHANNEL_CRED_VERSION,
            hRootStore: windows::Win32::Security::Cryptography::HCERTSTORE(std::ptr::null_mut()),

            grbitEnabledProtocols: if active {
                SP_PROT_DTLS1_2_CLIENT
            } else {
                SP_PROT_DTLS1_2_SERVER
            },

            cCreds: cert_contexts.len() as u32,
            paCred: cert_contexts.as_mut_ptr() as *mut *mut CERT_CONTEXT,

            cMappers: 0,
            aphMappers: std::ptr::null_mut(),

            cSupportedAlgs: 0,
            palgSupportedAlgs: std::ptr::null_mut(),

            dwMinimumCipherStrength: 128,
            dwMaximumCipherStrength: 256,
            dwSessionLifespan: 0,
            dwFlags: SCH_CRED_MANUAL_CRED_VALIDATION,
            dwCredFormat: 0,
        };

        unsafe {
            // These are the outputs of AcquireCredentialsHandleA
            let mut cred_handle = SecHandle::default();
            let mut creds_expiry: i64 = 0;
            AcquireCredentialsHandleW(
                None,
                UNISP_NAME_W,
                if active {
                    SECPKG_CRED_OUTBOUND
                } else {
                    SECPKG_CRED_INBOUND
                },
                None,
                Some(&schannel_cred as *const _ as *const std::ffi::c_void),
                None,
                None,
                &mut cred_handle,
                Some(&mut creds_expiry),
            )
            .expect("Failed to generate creds");

            self.cred_handle = Some(cred_handle);
        }

        self.state = EstablishmentState::Handshaking;
    }

    pub fn handle_receive(
        &mut self,
        datagram: Option<&[u8]>,
    ) -> Result<WinCryptoDtlsEvent, WinCryptoError> {
        let state = self.state;
        match state {
            EstablishmentState::Established => {
                if let Some(datagram) = datagram {
                    self.process_packet(datagram)
                } else {
                    warn!("Unexpectedly asked to process no message!");
                    Ok(WinCryptoDtlsEvent::None)
                }
            }
            EstablishmentState::Handshaking => self.handshake(datagram),
            EstablishmentState::Failed => {
                Err(WinCryptoError("Handshake failed".to_string()).into())
            }
            EstablishmentState::Idle => {
                Err(WinCryptoError("Handshake not initialized".to_string()).into())
            }
        }
    }

    pub fn pull_datagram(&mut self) -> Option<Vec<u8>> {
        self.output.pop_front()
    }

    pub fn next_timeout(&mut self, now: Instant) -> Option<Instant> {
        match self.state {
            EstablishmentState::Idle | EstablishmentState::Handshaking => {
                Some(now + Duration::from_millis(500))
            }
            _ => None,
        }
    }

    // This is DATA sent from client over SCTP/DTLS
    pub fn send_data(&mut self, data: &[u8]) -> Result<bool, WinCryptoError> {
        if self.state != EstablishmentState::Established {
            return Ok(false);
        }
        let ctx_handle = self.security_ctx.as_ref().expect("No ctx!?");

        unsafe {
            let header_size = self.encrypt_message_input_sizes.cbHeader as usize;
            let trailer_size = self.encrypt_message_input_sizes.cbTrailer as usize;
            let message_size = data.len();

            let mut output = vec![0u8; header_size + trailer_size + message_size];
            output[header_size..header_size + message_size].copy_from_slice(data);

            let sec_buffers = [
                SecBuffer {
                    BufferType: SECBUFFER_STREAM_HEADER,
                    cbBuffer: header_size as u32,
                    pvBuffer: &output[0] as *const _ as *mut _,
                },
                SecBuffer {
                    BufferType: SECBUFFER_DATA,
                    cbBuffer: message_size as u32,
                    pvBuffer: &output[header_size] as *const _ as *mut _,
                },
                SecBuffer {
                    BufferType: SECBUFFER_STREAM_TRAILER,
                    cbBuffer: trailer_size as u32,
                    pvBuffer: &output[header_size + message_size] as *const _ as *mut _,
                },
                SecBuffer {
                    cbBuffer: 0,
                    BufferType: SECBUFFER_EMPTY,
                    pvBuffer: std::ptr::null_mut(),
                },
            ];
            let sec_buffer_desc = SecBufferDesc {
                ulVersion: SECBUFFER_VERSION,
                cBuffers: 4,
                pBuffers: &sec_buffers[0] as *const _ as *mut _,
            };

            let status = EncryptMessage(ctx_handle, 0, &sec_buffer_desc, 0);
            match status {
                SEC_E_OK => {
                    self.output.push_back(output);
                    Ok(true)
                }
                status => Err(WinCryptoError(format!(
                    "EncryptMessage returned error, message dropped. Status: {}",
                    status
                ))
                .into()),
            }
        }
    }

    fn handshake(&mut self, datagram: Option<&[u8]>) -> Result<WinCryptoDtlsEvent, WinCryptoError> {
        let is_client = self.is_client.ok_or_else(|| {
            WinCryptoError("handshake attempted without setting is_client".to_string())
        })?;
        let mut new_ctx_handle = SecHandle::default();

        let in_buffer_desc = match datagram {
            Some(datagram) => {
                let buffers = [
                    DTLS_MTU_SECBUFFER,
                    SRTP_PROTECTION_PROFILES_SECBUFFER,
                    SecBuffer {
                        cbBuffer: datagram.len() as u32,
                        BufferType: SECBUFFER_TOKEN,
                        pvBuffer: datagram.as_ptr() as *mut _,
                    },
                    SecBuffer {
                        cbBuffer: 0,
                        BufferType: SECBUFFER_EMPTY,
                        pvBuffer: std::ptr::null_mut(),
                    },
                    SecBuffer {
                        cbBuffer: 0,
                        BufferType: SECBUFFER_EXTRA,
                        pvBuffer: std::ptr::null_mut(),
                    },
                ];
                SecBufferDesc {
                    ulVersion: SECBUFFER_VERSION,
                    cBuffers: buffers.len() as u32,
                    pBuffers: &buffers[0] as *const _ as *mut _,
                }
            }
            None => SecBufferDesc {
                ulVersion: SECBUFFER_VERSION,
                cBuffers: 2,
                pBuffers: &[DTLS_MTU_SECBUFFER, SRTP_PROTECTION_PROFILES_SECBUFFER] as *const _
                    as *mut _,
            },
        };

        let token_buffer = [0u8; DATAGRAM_MTU];
        let alert_buffer = [0u8; DATAGRAM_MTU];
        let out_buffers = [
            SecBuffer {
                cbBuffer: token_buffer.len() as u32,
                BufferType: SECBUFFER_TOKEN,
                pvBuffer: &token_buffer as *const _ as *mut _,
            },
            SecBuffer {
                cbBuffer: alert_buffer.len() as u32,
                BufferType: SECBUFFER_ALERT,
                pvBuffer: &alert_buffer as *const _ as *mut _,
            },
        ];
        let mut out_buffer_desc = SecBufferDesc {
            cBuffers: out_buffers.len() as u32,
            pBuffers: &out_buffers[0] as *const _ as *mut _,
            ulVersion: SECBUFFER_VERSION,
        };

        unsafe {
            let mut attrs = 0;
            let status = if is_client {
                // Client
                debug!("InitializeSecurityContextW {:?}", in_buffer_desc);
                InitializeSecurityContextW(
                    self.cred_handle.as_ref().map(|r| r as *const _),
                    self.security_ctx.as_ref().map(|r| r as *const _),
                    None,
                    ISC_REQ_CONFIDENTIALITY
                        | ISC_REQ_EXTENDED_ERROR
                        | ISC_REQ_INTEGRITY
                        | ISC_REQ_DATAGRAM
                        | ISC_REQ_MANUAL_CRED_VALIDATION
                        | ISC_REQ_USE_SUPPLIED_CREDS,
                    0,
                    SECURITY_NATIVE_DREP,
                    Some(&in_buffer_desc),
                    0,
                    Some(&mut new_ctx_handle),
                    Some(&mut out_buffer_desc),
                    &mut attrs,
                    None,
                )
            } else {
                // Server
                debug!("AcceptSecurityContext {:?}", in_buffer_desc);
                AcceptSecurityContext(
                    self.cred_handle.as_ref().map(|r| r as *const _),
                    self.security_ctx.as_ref().map(|r| r as *const _),
                    Some(&in_buffer_desc),
                    ASC_REQ_CONFIDENTIALITY
                        | ASC_REQ_EXTENDED_ERROR
                        | ASC_REQ_INTEGRITY
                        | ASC_REQ_DATAGRAM
                        | ASC_REQ_MUTUAL_AUTH,
                    SECURITY_NATIVE_DREP,
                    Some(&mut new_ctx_handle),
                    Some(&mut out_buffer_desc),
                    &mut attrs,
                    None,
                )
            };
            debug!("DTLS Handshake status: {status}");
            self.security_ctx = Some(new_ctx_handle);
            if out_buffers[0].cbBuffer > 0 {
                let len = out_buffers[0].cbBuffer;
                self.output.push_back(token_buffer[..len as usize].to_vec());
            }
            return match status {
                SEC_E_OK => {
                    // Move to Done
                    self.transition_to_completed()
                }
                SEC_I_CONTINUE_NEEDED => {
                    // Stay in handshake while we wait for the other side to respond.
                    debug!("Wait for peer");
                    Ok(WinCryptoDtlsEvent::None)
                }
                SEC_I_MESSAGE_FRAGMENT => {
                    // Fragment was sent, we need to call again to send the next fragment.
                    debug!("Sent handshake fragment");
                    self.handshake(None)
                }
                e => {
                    // Failed
                    self.state = EstablishmentState::Failed;
                    Err(WinCryptoError(format!("DTLS handshake failure: {:?}", e)).into())
                }
            };
        }
    }

    fn transition_to_completed(&mut self) -> Result<WinCryptoDtlsEvent, WinCryptoError> {
        unsafe {
            QueryContextAttributesW(
                self.security_ctx.as_ref().unwrap() as *const _,
                SECPKG_ATTR_STREAM_SIZES,
                &mut self.encrypt_message_input_sizes as *mut _ as *mut std::ffi::c_void,
            )
            .map_err(|e| WinCryptoError(format!("SECPKG_ATTR_STREAM_SIZES: {:?}", e)))?;

            let mut srtp_parameters = SecPkgContext_SrtpParameters::default();
            QueryContextAttributesW(
                self.security_ctx.as_ref().unwrap() as *const _,
                SECPKG_ATTR(SECPKG_ATTR_SRTP_PARAMETERS),
                &mut srtp_parameters as *mut _ as *mut std::ffi::c_void,
            )
            .map_err(|e| {
                WinCryptoError(format!("QueryContextAttributesW Keying Material: {:?}", e))
            })?;

            let srtp_profile_id = u16::from_be(srtp_parameters.ProtectionProfile);

            let keying_material_info = SecPkgContext_KeyingMaterialInfo {
                cbLabel: DTLS_KEY_LABEL.len() as u16,
                pszLabel: windows::core::PSTR(DTLS_KEY_LABEL.as_ptr() as *mut u8),
                cbKeyingMaterial: srtp_keying_material_len(srtp_profile_id)?,
                cbContextValue: 0,
                pbContextValue: std::ptr::null_mut(),
            };
            SetContextAttributesW(
                self.security_ctx.as_ref().unwrap() as *const _,
                SECPKG_ATTR_KEYING_MATERIAL_INFO,
                &keying_material_info as *const _ as *const std::ffi::c_void,
                std::mem::size_of::<SecPkgContext_KeyingMaterialInfo>() as u32,
            )
            .map_err(|e| {
                WinCryptoError(format!("SetContextAttributesA Keying Material: {:?}", e))
            })?;

            let mut keying_material = SecPkgContext_KeyingMaterial::default();
            QueryContextAttributesExW(
                self.security_ctx.as_ref().unwrap() as *const _,
                SECPKG_ATTR(SECPKG_ATTR_KEYING_MATERIAL),
                &mut keying_material as *mut _ as *mut std::ffi::c_void,
                std::mem::size_of::<SecPkgContext_KeyingMaterial>() as u32,
            )
            .map_err(|e| {
                WinCryptoError(format!(
                    "QueryContextAttributesExW Keying Material: {:?}",
                    e
                ))
            })?;

            let srtp_keying_material = std::slice::from_raw_parts(
                keying_material.pbKeyingMaterial,
                keying_material.cbKeyingMaterial as usize,
            )
            .to_vec();

            FreeContextBuffer(keying_material.pbKeyingMaterial as *mut _ as *mut std::ffi::c_void)
                .map_err(|e| {
                    WinCryptoError(format!("FreeContextBuffer Keying Material: {:?}", e))
                })?;

            let mut peer_cert_context: *mut CERT_CONTEXT = std::ptr::null_mut();
            QueryContextAttributesW(
                self.security_ctx.as_ref().unwrap() as *const _,
                SECPKG_ATTR_REMOTE_CERT_CONTEXT,
                &mut peer_cert_context as *mut _ as *mut std::ffi::c_void,
            )
            .map_err(|e| WinCryptoError(format!("QueryContextAttributesW: {:?}", e)))?;
            let peer_certificate: WinCryptoCertificate =
                (peer_cert_context as *const CERT_CONTEXT).into();
            let peer_fingerprint = peer_certificate.sha256_fingerprint()?;

            self.state = EstablishmentState::Established;
            Ok(WinCryptoDtlsEvent::Connected {
                srtp_profile_id,
                srtp_keying_material,
                peer_fingerprint,
            })
        }
    }

    fn process_packet(&mut self, datagram: &[u8]) -> Result<WinCryptoDtlsEvent, WinCryptoError> {
        if self.state != EstablishmentState::Established {
            return Ok(WinCryptoDtlsEvent::WouldBlock);
        }
        let security_ctx = self.security_ctx.as_ref().expect("No ctx!?");

        let header_size = self.encrypt_message_input_sizes.cbHeader as usize;
        let trailer_size = self.encrypt_message_input_sizes.cbTrailer as usize;

        let output = datagram.to_vec();
        let alert = [0u8; 512];

        let sec_buffers = [
            SecBuffer {
                BufferType: SECBUFFER_DATA,
                cbBuffer: output.len() as u32,
                pvBuffer: &output[0] as *const _ as *mut _,
            },
            SecBuffer {
                cbBuffer: 0,
                BufferType: SECBUFFER_EMPTY,
                pvBuffer: std::ptr::null_mut(),
            },
            SecBuffer {
                cbBuffer: 0,
                BufferType: SECBUFFER_EMPTY,
                pvBuffer: std::ptr::null_mut(),
            },
            SecBuffer {
                cbBuffer: 0,
                BufferType: SECBUFFER_EMPTY,
                pvBuffer: std::ptr::null_mut(),
            },
            SecBuffer {
                BufferType: SECBUFFER_ALERT,
                cbBuffer: alert.len() as u32,
                pvBuffer: &alert[0] as *const _ as *mut _,
            },
        ];
        let sec_buffer_desc = SecBufferDesc {
            ulVersion: SECBUFFER_VERSION,
            cBuffers: 4,
            pBuffers: &sec_buffers[0] as *const _ as *mut _,
        };

        unsafe {
            let status = DecryptMessage(security_ctx, &sec_buffer_desc, 0, None);
            match status {
                SEC_E_OK => {
                    let data = output[header_size..output.len() - trailer_size].to_vec();
                    Ok(WinCryptoDtlsEvent::Data(data))
                }
                SEC_E_MESSAGE_ALTERED => {
                    warn!("Packet alteration detected, packet dropped");
                    Ok(WinCryptoDtlsEvent::None)
                }
                SEC_E_OUT_OF_SEQUENCE => {
                    warn!("Received out of sequence packet");
                    Ok(WinCryptoDtlsEvent::None)
                }
                SEC_I_CONTEXT_EXPIRED => {
                    self.state = EstablishmentState::Failed;
                    Err(WinCryptoError("Context expired".to_string()).into())
                }
                SEC_I_RENEGOTIATE => {
                    // SChannel provides a token to feed into a new handshake
                    if let Some(token_buffer) =
                        sec_buffers.iter().find(|p| p.BufferType == SECBUFFER_EXTRA)
                    {
                        self.state = EstablishmentState::Handshaking;
                        let data = token_buffer.pvBuffer as *mut u8;
                        let len = token_buffer.cbBuffer as usize;
                        self.handshake(Some(std::slice::from_raw_parts(data, len)))
                    } else {
                        Err(WinCryptoError("Renegotiate didn't include a token".to_string()).into())
                    }
                }
                status => Err(WinCryptoError(format!(
                    "DecryptMessage returned error, message dropped. Status: {}",
                    status
                ))
                .into()),
            }
        }
    }
}

impl Drop for WinCryptoDtls {
    fn drop(&mut self) {
        unsafe {
            if let Some(ctx_handle) = self.security_ctx {
                if let Err(e) = DeleteSecurityContext(&ctx_handle) {
                    error!("DeleteSecurityContext on Drop failed: {:?}", e);
                }
            }
            if let Some(cred_handle) = self.cred_handle {
                if let Err(e) = FreeCredentialsHandle(&cred_handle) {
                    error!("FreeCredentialsHandle on Drop failed: {:?}", e);
                }
            }
        }
    }
}

fn srtp_keying_material_len(srtp_profile_id: u16) -> Result<u32, WinCryptoError> {
    match srtp_profile_id {
        0x0001 => Ok(16 * 2 + 14 * 2),
        0x0007 => Ok(16 * 2 + 12 * 2),
        id => Err(WinCryptoError(format!(
            "Unknown SRTP Profile Requested: {id}"
        ))),
    }
}
