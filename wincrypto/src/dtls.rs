use super::{Certificate, WinCryptoError};
use std::{
    collections::VecDeque,
    sync::Arc,
    time::{Duration, Instant},
};
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

// The label used for SRTP key derivation from: https://datatracker.ietf.org/doc/html/rfc5764#section-4.2
const DTLS_KEY_LABEL: &[u8] = b"EXTRACTOR-dtls_srtp\0";

// This size includes the encaptulation overhead of DTLS. So it must be larger than the MTU Str0m
// uses for SCTP.
const DATAGRAM_MTU: usize = 1200;

#[derive(Clone, Copy, Debug, PartialEq)]
enum EstablishmentState {
    Idle,
    Handshaking,
    Established,
    Failed,
}

pub enum DtlsEvent {
    None,
    WouldBlock,
    Connected {
        srtp_profile_id: u16,
        srtp_keying_material: Vec<u8>,
        peer_fingerprint: [u8; 32],
    },
    Data(Vec<u8>),
}

pub struct Dtls {
    cert: Arc<Certificate>,
    is_client: Option<bool>,
    state: EstablishmentState,
    cred_handle: Option<SecHandle>,
    security_ctx: Option<SecHandle>,
    encrypt_message_input_sizes: SecPkgContext_StreamSizes,

    output_datagrams: VecDeque<Vec<u8>>,
}

impl Dtls {
    pub fn new(cert: Arc<Certificate>) -> Result<Self, WinCryptoError> {
        Ok(Dtls {
            cert,
            is_client: None,
            state: EstablishmentState::Idle,
            cred_handle: None,
            security_ctx: None,
            encrypt_message_input_sizes: SecPkgContext_StreamSizes::default(),
            output_datagrams: VecDeque::default(),
        })
    }

    pub fn is_client(&self) -> Option<bool> {
        self.is_client
    }

    pub fn is_connected(&self) -> bool {
        self.state == EstablishmentState::Established
    }

    pub fn set_as_client(&mut self, active: bool) -> Result<(), WinCryptoError> {
        self.is_client = Some(active);

        let mut cert_contexts = [self.cert.context()];
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

        // These are the outputs of AcquireCredentialsHandleA
        let mut cred_handle = SecHandle::default();
        let mut creds_expiry: i64 = 0;

        // SAFETY: The references passed are all borrow checked, the exception to
        // this is the pointer to the cert_context in schannel_cred, which
        // is kept alive by the `self.cert`.
        unsafe {
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
            )?;
        }
        self.cred_handle = Some(cred_handle);

        self.state = EstablishmentState::Handshaking;
        Ok(())
    }

    pub fn handle_receive(&mut self, datagram: Option<&[u8]>) -> Result<DtlsEvent, WinCryptoError> {
        let state = self.state;
        match state {
            EstablishmentState::Established => {
                if let Some(datagram) = datagram {
                    self.process_packet(datagram)
                } else {
                    warn!("Unexpectedly asked to process no message!");
                    Ok(DtlsEvent::None)
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
        self.output_datagrams.pop_front()
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
        let Some(security_ctx) = self.security_ctx.as_ref() else {
            return Err(WinCryptoError(
                "Security Context not generated.".to_string(),
            ));
        };

        let header_size = self.encrypt_message_input_sizes.cbHeader as usize;
        let trailer_size = self.encrypt_message_input_sizes.cbTrailer as usize;
        let message_size = data.len();

        let mut output = vec![0u8; header_size + trailer_size + message_size];
        output[header_size..header_size + message_size].copy_from_slice(data);

        let mut sec_buffers = [
            SecBuffer {
                BufferType: SECBUFFER_STREAM_HEADER,
                cbBuffer: header_size as u32,
                pvBuffer: output[0..].as_mut_ptr() as *mut _,
            },
            SecBuffer {
                BufferType: SECBUFFER_DATA,
                cbBuffer: message_size as u32,
                pvBuffer: output[header_size..].as_mut_ptr() as *mut _,
            },
            SecBuffer {
                BufferType: SECBUFFER_STREAM_TRAILER,
                cbBuffer: trailer_size as u32,
                pvBuffer: output[header_size + message_size..].as_mut_ptr() as *mut _,
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
            pBuffers: sec_buffers.as_mut_ptr() as *mut _,
        };

        // SAFETY: The references passed are all borrow checked. However,
        // it is important to note that `sec_buffer_desc` holds a pointer to
        // a sequence of SecBuffers. Those SecBuffers must exist for the
        // duration of the unsafe block.
        let status = unsafe { EncryptMessage(security_ctx, 0, &sec_buffer_desc, 0) };

        match status {
            SEC_E_OK => {
                self.output_datagrams.push_back(output);
                Ok(true)
            }
            status => Err(WinCryptoError(format!(
                "EncryptMessage returned error, message dropped. Status: {}",
                status
            ))
            .into()),
        }
    }

    fn handshake(&mut self, datagram: Option<&[u8]>) -> Result<DtlsEvent, WinCryptoError> {
        let is_client = self.is_client.ok_or_else(|| {
            WinCryptoError("handshake attempted without setting is_client".to_string())
        })?;
        let mut new_ctx_handle = SecHandle::default();

        let mut buffers = [
            DTLS_MTU_SECBUFFER,
            SRTP_PROTECTION_PROFILES_SECBUFFER,
            SecBuffer {
                cbBuffer: 0,
                BufferType: SECBUFFER_TOKEN,
                pvBuffer: std::ptr::null_mut(),
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

        let in_buffer_desc = match datagram {
            Some(datagram) => {
                buffers[2].cbBuffer = datagram.len() as u32;
                buffers[2].pvBuffer = datagram as *const _ as *mut _;

                SecBufferDesc {
                    ulVersion: SECBUFFER_VERSION,
                    cBuffers: buffers.len() as u32,
                    pBuffers: buffers.as_mut_ptr() as *mut _,
                }
            }
            None => SecBufferDesc {
                ulVersion: SECBUFFER_VERSION,
                cBuffers: 2,
                pBuffers: buffers.as_mut_ptr() as *mut _,
            },
        };

        let mut token_buffer = [0u8; DATAGRAM_MTU];
        let mut alert_buffer = [0u8; DATAGRAM_MTU];
        let mut out_buffers = [
            SecBuffer {
                cbBuffer: token_buffer.len() as u32,
                BufferType: SECBUFFER_TOKEN,
                pvBuffer: token_buffer.as_mut_ptr() as *mut _,
            },
            SecBuffer {
                cbBuffer: alert_buffer.len() as u32,
                BufferType: SECBUFFER_ALERT,
                pvBuffer: alert_buffer.as_mut_ptr() as *mut _,
            },
        ];
        let mut out_buffer_desc = SecBufferDesc {
            cBuffers: out_buffers.len() as u32,
            pBuffers: out_buffers.as_mut_ptr() as *mut _,
            ulVersion: SECBUFFER_VERSION,
        };

        let mut attrs = 0;

        // SAFETY: The references passed are all borrow checked. However,
        // it is important to note that `in_buffer_desc` and `out_buffer_desc`
        // hold pointers to sequence of SecBuffers. Those SecBuffers must exist
        // for the duration of the unsafe block.
        let status = unsafe {
            if is_client {
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
                debug!(
                    "AcceptSecurityContext {:?} {:?}",
                    in_buffer_desc, out_buffer_desc
                );
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
            }
        };

        debug!("DTLS Handshake status: {status}");
        self.security_ctx = Some(new_ctx_handle);
        if out_buffers[0].cbBuffer > 0 {
            let len = out_buffers[0].cbBuffer;
            self.output_datagrams
                .push_back(token_buffer[..len as usize].to_vec());
        }
        return match status {
            SEC_E_OK => {
                // Move to Done
                self.transition_to_completed()
            }
            SEC_I_CONTINUE_NEEDED => {
                // Stay in handshake while we wait for the other side to respond.
                debug!("Wait for peer");
                Ok(DtlsEvent::None)
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

    fn transition_to_completed(&mut self) -> Result<DtlsEvent, WinCryptoError> {
        let mut srtp_parameters = SecPkgContext_SrtpParameters::default();
        let Some(security_ctx) = self.security_ctx.as_ref() else {
            return Err(WinCryptoError("Security context missing".to_string()));
        };

        // SAFETY: The references used in the unsafe block are all borrow checked.
        unsafe {
            QueryContextAttributesW(
                security_ctx as *const _,
                SECPKG_ATTR_STREAM_SIZES,
                &mut self.encrypt_message_input_sizes as *mut _ as *mut std::ffi::c_void,
            )
            .map_err(|e| WinCryptoError(format!("SECPKG_ATTR_STREAM_SIZES: {:?}", e)))?;

            QueryContextAttributesW(
                security_ctx as *const _,
                SECPKG_ATTR(SECPKG_ATTR_SRTP_PARAMETERS),
                &mut srtp_parameters as *mut _ as *mut std::ffi::c_void,
            )
            .map_err(|e| {
                WinCryptoError(format!("QueryContextAttributesW Keying Material: {:?}", e))
            })?;
        }

        let srtp_profile_id = u16::from_be(srtp_parameters.ProtectionProfile);
        let keying_material_info = SecPkgContext_KeyingMaterialInfo {
            cbLabel: DTLS_KEY_LABEL.len() as u16,
            pszLabel: windows::core::PSTR(DTLS_KEY_LABEL.as_ptr() as *mut u8),
            cbKeyingMaterial: srtp_keying_material_len(srtp_profile_id)?,
            cbContextValue: 0,
            pbContextValue: std::ptr::null_mut(),
        };
        let mut keying_material = SecPkgContext_KeyingMaterial::default();

        // SAFETY: The references used in the unsafe block are all borrow checked. The
        // only pointers used in those structs are to statically defined values.
        let srtp_keying_material = unsafe {
            SetContextAttributesW(
                security_ctx as *const _,
                SECPKG_ATTR_KEYING_MATERIAL_INFO,
                &keying_material_info as *const _ as *const std::ffi::c_void,
                std::mem::size_of::<SecPkgContext_KeyingMaterialInfo>() as u32,
            )
            .map_err(|e| {
                WinCryptoError(format!("SetContextAttributesA Keying Material: {:?}", e))
            })?;

            QueryContextAttributesExW(
                security_ctx as *const _,
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

            // Copy the returned keying material to a Vec.
            let keying_material_vec = std::slice::from_raw_parts(
                keying_material.pbKeyingMaterial,
                keying_material.cbKeyingMaterial as usize,
            )
            .to_vec();

            // Now that we copied the key to the Rust heap, we can free the buffer.
            FreeContextBuffer(keying_material.pbKeyingMaterial as *mut _ as *mut std::ffi::c_void)
                .map_err(|e| {
                    WinCryptoError(format!("FreeContextBuffer Keying Material: {:?}", e))
                })?;

            keying_material_vec
        };

        // SAFETY: All the passed in values are borrow checked. The raw CERT_CONTEXT
        // pointer does not escpae the block, to avoid leaking the unwrapped pointer.
        let peer_certificate: Certificate = unsafe {
            let mut peer_cert_context: *mut CERT_CONTEXT = std::ptr::null_mut();
            QueryContextAttributesW(
                security_ctx as *const _,
                SECPKG_ATTR_REMOTE_CERT_CONTEXT,
                &mut peer_cert_context as *mut _ as *mut std::ffi::c_void,
            )
            .map_err(|e| WinCryptoError(format!("QueryContextAttributesW: {:?}", e)))?;
            (peer_cert_context as *const CERT_CONTEXT).into()
        };

        let peer_fingerprint = peer_certificate.sha256_fingerprint()?;

        self.state = EstablishmentState::Established;
        Ok(DtlsEvent::Connected {
            srtp_profile_id,
            srtp_keying_material,
            peer_fingerprint,
        })
    }

    fn process_packet(&mut self, datagram: &[u8]) -> Result<DtlsEvent, WinCryptoError> {
        if self.state != EstablishmentState::Established {
            return Ok(DtlsEvent::WouldBlock);
        }
        let Some(security_ctx) = self.security_ctx.as_ref() else {
            return Err(WinCryptoError(
                "Security Context not generated.".to_string(),
            ));
        };

        let header_size = self.encrypt_message_input_sizes.cbHeader as usize;
        let trailer_size = self.encrypt_message_input_sizes.cbTrailer as usize;

        let mut output = datagram.to_vec();
        let mut alert = [0u8; 512];

        let mut sec_buffers = [
            SecBuffer {
                BufferType: SECBUFFER_DATA,
                cbBuffer: output.len() as u32,
                pvBuffer: output.as_mut_ptr() as *mut _,
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
                pvBuffer: alert.as_mut_ptr() as *mut _,
            },
        ];
        let sec_buffer_desc = SecBufferDesc {
            ulVersion: SECBUFFER_VERSION,
            cBuffers: 4,
            pBuffers: sec_buffers.as_mut_ptr() as *mut _,
        };

        // SAFETY: All the passed in values are borrow checked. The `sec_buffer_desc`
        // however holds pointers to a SecBuffer list. It's important that those buffers
        // exist through this unsafe block.
        let status = unsafe { DecryptMessage(security_ctx, &sec_buffer_desc, 0, None) };
        match status {
            SEC_E_OK => {
                let data = output[header_size..output.len() - trailer_size].to_vec();
                Ok(DtlsEvent::Data(data))
            }
            SEC_E_MESSAGE_ALTERED => {
                warn!("Packet alteration detected, packet dropped");
                Ok(DtlsEvent::None)
            }
            SEC_E_OUT_OF_SEQUENCE => {
                warn!("Received out of sequence packet");
                Ok(DtlsEvent::None)
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

                    // SAFETY: We don't want to copy the data, so we will create a slice
                    // from the pointer and length, and pass it on. The pointer is required
                    // to actually be part of all of the buffers passed in, so the slice
                    // is valid so long as `sec_buffers` is.
                    self.handshake(Some(unsafe { std::slice::from_raw_parts(data, len) }))
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

impl Drop for Dtls {
    fn drop(&mut self) {
        // SAFETY: The handles here are no longer needed and cannot be accessed outside
        // this struct, so it's safe to Delete/Free them here.
        unsafe {
            if let Some(ctx_handle) = self.security_ctx {
                DeleteSecurityContext(&ctx_handle)
                    .expect("DeleteSecurityContext should always get valid handle");
            }
            if let Some(cred_handle) = self.cred_handle {
                FreeCredentialsHandle(&cred_handle)
                    .expect("FreeCredentialsHandle should always get valid handle");
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
