//! JNI bindings to Android's javax.crypto and java.security APIs.
//!
//! This module provides low-level wrappers around Android's crypto functionality
//! accessed via JNI. Class lookups are cached per-thread to avoid repeated
//! `FindClass` overhead on the hot path.

use std::cell::RefCell;

use jni::objects::{GlobalRef, JByteArray, JClass, JMethodID, JObject, JStaticMethodID, JValue};
use jni::signature::{Primitive, ReturnType};
use jni::sys::jvalue;
use jni::JNIEnv;

use str0m_proto::crypto::CryptoError;

use crate::get_jvm;

/// Cached JNI class and string references to avoid repeated lookups.
///
/// Each field holds a [`GlobalRef`] to a Java class or interned string.
/// These are created once per thread on the first JNI call and reused for
/// all subsequent calls.
struct JniCache {
    // ── Java classes ──────────────────────────────────────────────
    /// `java.security.MessageDigest`
    message_digest: GlobalRef,
    /// `javax.crypto.Mac`
    mac: GlobalRef,
    /// `javax.crypto.spec.SecretKeySpec`
    secret_key_spec: GlobalRef,
    /// `javax.crypto.Cipher`
    cipher: GlobalRef,
    /// `javax.crypto.spec.GCMParameterSpec`
    gcm_parameter_spec: GlobalRef,
    /// `java.security.SecureRandom`
    secure_random: GlobalRef,
    /// `java.security.KeyPairGenerator`
    key_pair_generator: GlobalRef,
    /// `java.security.spec.ECGenParameterSpec`
    ec_gen_parameter_spec: GlobalRef,
    /// `java.security.KeyFactory`
    key_factory: GlobalRef,
    /// `java.security.spec.PKCS8EncodedKeySpec`
    pkcs8_encoded_key_spec: GlobalRef,
    /// `java.security.Signature`
    signature: GlobalRef,
    /// `java.security.spec.X509EncodedKeySpec`
    x509_encoded_key_spec: GlobalRef,
    /// `javax.crypto.KeyAgreement`
    key_agreement: GlobalRef,

    // ── Algorithm / transformation strings ────────────────────────
    str_sha256: GlobalRef,
    str_sha384: GlobalRef,
    str_hmac_sha1: GlobalRef,
    str_hmac_sha256: GlobalRef,
    str_hmac_sha384: GlobalRef,
    str_aes_ecb: GlobalRef,
    str_aes_gcm: GlobalRef,
    str_aes: GlobalRef,
    str_ec: GlobalRef,
    str_secp256r1: GlobalRef,
    str_sha256_ecdsa: GlobalRef,
    str_ecdh: GlobalRef,

    // ── Extra classes needed only for method ID lookups ───────────
    /// `java.security.KeyPair`
    _key_pair: GlobalRef,
    /// `java.security.Key` (interface – used to look up `getEncoded`)
    _key: GlobalRef,

    // ── Cached static method IDs (getInstance) ───────────────────
    mid_message_digest_get_instance: JStaticMethodID,
    mid_mac_get_instance: JStaticMethodID,
    mid_cipher_get_instance: JStaticMethodID,
    mid_kpg_get_instance: JStaticMethodID,
    mid_key_factory_get_instance: JStaticMethodID,
    mid_signature_get_instance: JStaticMethodID,
    mid_key_agreement_get_instance: JStaticMethodID,

    // ── Cached instance method IDs ───────────────────────────────
    mid_digest_digest: JMethodID,
    mid_mac_init: JMethodID,
    mid_mac_do_final: JMethodID,
    mid_cipher_init2: JMethodID,
    mid_cipher_init3: JMethodID,
    mid_cipher_update_aad: JMethodID,
    mid_cipher_do_final: JMethodID,
    mid_secure_random_next_bytes: JMethodID,
    mid_kpg_initialize: JMethodID,
    mid_kpg_generate_key_pair: JMethodID,
    mid_key_pair_get_private: JMethodID,
    mid_key_pair_get_public: JMethodID,
    mid_key_get_encoded: JMethodID,
    mid_key_factory_generate_private: JMethodID,
    mid_key_factory_generate_public: JMethodID,
    mid_signature_init_sign: JMethodID,
    mid_signature_update: JMethodID,
    mid_signature_sign: JMethodID,
    mid_key_agreement_init: JMethodID,
    mid_key_agreement_do_phase: JMethodID,
    mid_key_agreement_generate_secret: JMethodID,
}

thread_local! {
    static JNI_CACHE: RefCell<Option<JniCache>> = const { RefCell::new(None) };
}

/// Look up a Java class and create a [`GlobalRef`] for caching.
fn find_and_cache(env: &mut JNIEnv, name: &str) -> Result<GlobalRef, CryptoError> {
    let class = env
        .find_class(name)
        .map_err(|e| CryptoError::Other(format!("Failed to find class {name}: {e}")))?;
    env.new_global_ref(class)
        .map_err(|e| CryptoError::Other(format!("Failed to create global ref for {name}: {e}")))
}

/// Create a Java string and return a [`GlobalRef`] for caching.
fn cache_string(env: &mut JNIEnv, s: &str) -> Result<GlobalRef, CryptoError> {
    let jstr = env
        .new_string(s)
        .map_err(|e| CryptoError::Other(format!("Failed to create string '{s}': {e}")))?;
    env.new_global_ref(jstr)
        .map_err(|e| CryptoError::Other(format!("Failed to cache string '{s}': {e}")))
}

/// Populate all cached class, string, and method ID references from the JNI environment.
fn init_jni_cache(env: &mut JNIEnv) -> Result<JniCache, CryptoError> {
    let message_digest = find_and_cache(env, "java/security/MessageDigest")?;
    let mac = find_and_cache(env, "javax/crypto/Mac")?;
    let cipher = find_and_cache(env, "javax/crypto/Cipher")?;
    let key_pair_generator = find_and_cache(env, "java/security/KeyPairGenerator")?;
    let key_factory = find_and_cache(env, "java/security/KeyFactory")?;
    let signature = find_and_cache(env, "java/security/Signature")?;
    let key_agreement = find_and_cache(env, "javax/crypto/KeyAgreement")?;
    let key_pair = find_and_cache(env, "java/security/KeyPair")?;
    let key = find_and_cache(env, "java/security/Key")?;
    let secure_random_cls = find_and_cache(env, "java/security/SecureRandom")?;

    // Look up static getInstance method IDs (all have the same signature pattern).
    let mid_message_digest_get_instance = cache_static_method(
        env,
        &message_digest,
        "getInstance",
        "(Ljava/lang/String;)Ljava/security/MessageDigest;",
    )?;
    let mid_mac_get_instance = cache_static_method(
        env,
        &mac,
        "getInstance",
        "(Ljava/lang/String;)Ljavax/crypto/Mac;",
    )?;
    let mid_cipher_get_instance = cache_static_method(
        env,
        &cipher,
        "getInstance",
        "(Ljava/lang/String;)Ljavax/crypto/Cipher;",
    )?;
    let mid_kpg_get_instance = cache_static_method(
        env,
        &key_pair_generator,
        "getInstance",
        "(Ljava/lang/String;)Ljava/security/KeyPairGenerator;",
    )?;
    let mid_key_factory_get_instance = cache_static_method(
        env,
        &key_factory,
        "getInstance",
        "(Ljava/lang/String;)Ljava/security/KeyFactory;",
    )?;
    let mid_signature_get_instance = cache_static_method(
        env,
        &signature,
        "getInstance",
        "(Ljava/lang/String;)Ljava/security/Signature;",
    )?;
    let mid_key_agreement_get_instance = cache_static_method(
        env,
        &key_agreement,
        "getInstance",
        "(Ljava/lang/String;)Ljavax/crypto/KeyAgreement;",
    )?;

    // Look up instance method IDs.
    let mid_digest_digest = cache_method(env, &message_digest, "digest", "([B)[B")?;
    let mid_mac_init = cache_method(env, &mac, "init", "(Ljava/security/Key;)V")?;
    let mid_mac_do_final = cache_method(env, &mac, "doFinal", "([B)[B")?;
    let mid_cipher_init2 = cache_method(env, &cipher, "init", "(ILjava/security/Key;)V")?;
    let mid_cipher_init3 = cache_method(
        env,
        &cipher,
        "init",
        "(ILjava/security/Key;Ljava/security/spec/AlgorithmParameterSpec;)V",
    )?;
    let mid_cipher_update_aad = cache_method(env, &cipher, "updateAAD", "([B)V")?;
    let mid_cipher_do_final = cache_method(env, &cipher, "doFinal", "([B)[B")?;
    let mid_secure_random_next_bytes = cache_method(env, &secure_random_cls, "nextBytes", "([B)V")?;
    let mid_kpg_initialize = cache_method(
        env,
        &key_pair_generator,
        "initialize",
        "(Ljava/security/spec/AlgorithmParameterSpec;)V",
    )?;
    let mid_kpg_generate_key_pair = cache_method(
        env,
        &key_pair_generator,
        "generateKeyPair",
        "()Ljava/security/KeyPair;",
    )?;
    let mid_key_pair_get_private =
        cache_method(env, &key_pair, "getPrivate", "()Ljava/security/PrivateKey;")?;
    let mid_key_pair_get_public =
        cache_method(env, &key_pair, "getPublic", "()Ljava/security/PublicKey;")?;
    let mid_key_get_encoded = cache_method(env, &key, "getEncoded", "()[B")?;
    let mid_key_factory_generate_private = cache_method(
        env,
        &key_factory,
        "generatePrivate",
        "(Ljava/security/spec/KeySpec;)Ljava/security/PrivateKey;",
    )?;
    let mid_key_factory_generate_public = cache_method(
        env,
        &key_factory,
        "generatePublic",
        "(Ljava/security/spec/KeySpec;)Ljava/security/PublicKey;",
    )?;
    let mid_signature_init_sign =
        cache_method(env, &signature, "initSign", "(Ljava/security/PrivateKey;)V")?;
    let mid_signature_update = cache_method(env, &signature, "update", "([B)V")?;
    let mid_signature_sign = cache_method(env, &signature, "sign", "()[B")?;
    let mid_key_agreement_init =
        cache_method(env, &key_agreement, "init", "(Ljava/security/Key;)V")?;
    let mid_key_agreement_do_phase = cache_method(
        env,
        &key_agreement,
        "doPhase",
        "(Ljava/security/Key;Z)Ljava/security/Key;",
    )?;
    let mid_key_agreement_generate_secret =
        cache_method(env, &key_agreement, "generateSecret", "()[B")?;

    Ok(JniCache {
        message_digest,
        mac,
        secret_key_spec: find_and_cache(env, "javax/crypto/spec/SecretKeySpec")?,
        cipher,
        gcm_parameter_spec: find_and_cache(env, "javax/crypto/spec/GCMParameterSpec")?,
        secure_random: secure_random_cls,
        key_pair_generator,
        ec_gen_parameter_spec: find_and_cache(env, "java/security/spec/ECGenParameterSpec")?,
        key_factory,
        pkcs8_encoded_key_spec: find_and_cache(env, "java/security/spec/PKCS8EncodedKeySpec")?,
        signature,
        x509_encoded_key_spec: find_and_cache(env, "java/security/spec/X509EncodedKeySpec")?,
        key_agreement,
        str_sha256: cache_string(env, "SHA-256")?,
        str_sha384: cache_string(env, "SHA-384")?,
        str_hmac_sha1: cache_string(env, "HmacSHA1")?,
        str_hmac_sha256: cache_string(env, "HmacSHA256")?,
        str_hmac_sha384: cache_string(env, "HmacSHA384")?,
        str_aes_ecb: cache_string(env, "AES/ECB/NoPadding")?,
        str_aes_gcm: cache_string(env, "AES/GCM/NoPadding")?,
        str_aes: cache_string(env, "AES")?,
        str_ec: cache_string(env, "EC")?,
        str_secp256r1: cache_string(env, "secp256r1")?,
        str_sha256_ecdsa: cache_string(env, "SHA256withECDSA")?,
        str_ecdh: cache_string(env, "ECDH")?,
        mid_message_digest_get_instance,
        mid_mac_get_instance,
        mid_cipher_get_instance,
        mid_kpg_get_instance,
        mid_key_factory_get_instance,
        mid_signature_get_instance,
        mid_key_agreement_get_instance,
        _key_pair: key_pair,
        _key: key,
        mid_digest_digest,
        mid_mac_init,
        mid_mac_do_final,
        mid_cipher_init2,
        mid_cipher_init3,
        mid_cipher_update_aad,
        mid_cipher_do_final,
        mid_secure_random_next_bytes,
        mid_kpg_initialize,
        mid_kpg_generate_key_pair,
        mid_key_pair_get_private,
        mid_key_pair_get_public,
        mid_key_get_encoded,
        mid_key_factory_generate_private,
        mid_key_factory_generate_public,
        mid_signature_init_sign,
        mid_signature_update,
        mid_signature_sign,
        mid_key_agreement_init,
        mid_key_agreement_do_phase,
        mid_key_agreement_generate_secret,
    })
}

/// Convert a cached [`GlobalRef`] to a [`JClass`] for use with JNI calls.
///
/// # Safety
///
/// The caller must ensure the `GlobalRef` points to a Java class object and
/// remains valid for the lifetime `'a`.
unsafe fn as_class<'a>(global_ref: &GlobalRef) -> JClass<'a> {
    // Safety: the GlobalRef is alive in thread-local storage for the duration
    // of the call. JClass/JObject are thin pointer wrappers with no Drop impl
    // that would release the reference.
    unsafe { JClass::from(JObject::from_raw(global_ref.as_raw())) }
}

/// Convert a cached [`GlobalRef`] to a [`JObject`] for use with JNI calls.
///
/// # Safety
///
/// The caller must ensure the `GlobalRef` remains valid for the lifetime `'a`.
unsafe fn as_obj<'a>(global_ref: &GlobalRef) -> JObject<'a> {
    unsafe { JObject::from_raw(global_ref.as_raw()) }
}

/// Look up a static method ID and return it for caching.
fn cache_static_method(
    env: &mut JNIEnv,
    class: &GlobalRef,
    name: &str,
    sig: &str,
) -> Result<JStaticMethodID, CryptoError> {
    let cls = unsafe { as_class(class) };
    env.get_static_method_id(&cls, name, sig)
        .map_err(|e| CryptoError::Other(format!("Failed to get static method ID {name}: {e}")))
}

/// Look up an instance method ID and return it for caching.
fn cache_method(
    env: &mut JNIEnv,
    class: &GlobalRef,
    name: &str,
    sig: &str,
) -> Result<JMethodID, CryptoError> {
    let cls = unsafe { as_class(class) };
    env.get_method_id(&cls, name, sig)
        .map_err(|e| CryptoError::Other(format!("Failed to get method ID {name}: {e}")))
}

/// Call a cached static `getInstance` method that takes a single `String` argument
/// and returns an object.
///
/// # Safety
///
/// `method_id` must be a valid static method ID for the given `class`.
unsafe fn get_instance<'local>(
    env: &mut JNIEnv<'local>,
    class: &JClass<'_>,
    method_id: JStaticMethodID,
    arg: &JObject<'_>,
) -> Result<JObject<'local>, CryptoError> {
    let args = [jvalue { l: arg.as_raw() }];
    // Safety: method_id is valid for this class, arg is a valid JObject,
    // and the method returns an Object.
    unsafe { env.call_static_method_unchecked(class, method_id, ReturnType::Object, &args) }
        .map_err(|e| CryptoError::Other(format!("getInstance failed: {e}")))?
        .l()
        .map_err(|e| CryptoError::Other(format!("getInstance result not an object: {e}")))
}

/// Call a cached instance method that returns void.
///
/// # Safety
///
/// `method_id` must be a valid method ID for the object's class.
unsafe fn call_void<'local>(
    env: &mut JNIEnv<'local>,
    obj: &JObject<'_>,
    method_id: JMethodID,
    args: &[jvalue],
) -> Result<(), CryptoError> {
    unsafe {
        env.call_method_unchecked(obj, method_id, ReturnType::Primitive(Primitive::Void), args)
    }
    .map_err(|e| CryptoError::Other(format!("method call failed: {e}")))?;
    Ok(())
}

/// Call a cached instance method that returns an object.
///
/// # Safety
///
/// `method_id` must be a valid method ID for the object's class.
unsafe fn call_obj<'local>(
    env: &mut JNIEnv<'local>,
    obj: &JObject<'_>,
    method_id: JMethodID,
    args: &[jvalue],
) -> Result<JObject<'local>, CryptoError> {
    unsafe { env.call_method_unchecked(obj, method_id, ReturnType::Object, args) }
        .map_err(|e| CryptoError::Other(format!("method call failed: {e}")))?
        .l()
        .map_err(|e| CryptoError::Other(format!("method result not an object: {e}")))
}

/// Execute a JNI operation with a cached set of class references.
///
/// Attaches the current thread to the JVM (if not already attached), ensures
/// the per-thread class cache is populated, and calls `$f` with
/// `(&mut JNIEnv, &JniCache)`.
macro_rules! with_jni_env {
    ($f:expr) => {{
        let jvm = get_jvm();
        let mut env = jvm
            .attach_current_thread()
            .map_err(|e| CryptoError::Other(format!("Failed to attach JNI thread: {e}")))?;
        JNI_CACHE.with(|cell| {
            {
                let needs_init = cell.borrow().is_none();
                if needs_init {
                    *cell.borrow_mut() = Some(init_jni_cache(&mut env)?);
                }
            }
            let cache_ref = cell.borrow();
            let classes = cache_ref.as_ref().expect("class cache just initialized");
            $f(&mut env, classes)
        })
    }};
}

/// Compute SHA-256 hash using java.security.MessageDigest.
pub fn sha256(data: &[u8]) -> Result<[u8; 32], CryptoError> {
    with_jni_env!(|env: &mut JNIEnv, classes: &JniCache| {
        let digest_class = unsafe { as_class(&classes.message_digest) };
        let algorithm = unsafe { as_obj(&classes.str_sha256) };

        // Call MessageDigest.getInstance("SHA-256")
        let digest = unsafe {
            get_instance(
                env,
                &digest_class,
                classes.mid_message_digest_get_instance,
                &algorithm,
            )
        }?;

        // Create byte array from input data
        let input_array = env
            .byte_array_from_slice(data)
            .map_err(|e| CryptoError::Other(format!("Failed to create byte array: {e}")))?;

        // Call digest.digest(input)
        let result = unsafe {
            call_obj(
                env,
                &digest,
                classes.mid_digest_digest,
                &[jvalue {
                    l: input_array.as_raw(),
                }],
            )
        }?;

        // Convert result to Rust array
        let result_array: JByteArray = result.into();
        let result_len = env
            .get_array_length(&result_array)
            .map_err(|e| CryptoError::Other(format!("Failed to get array length: {e}")))?
            as usize;

        if result_len != 32 {
            return Err(CryptoError::Other(format!(
                "Unexpected SHA-256 result length: {result_len}"
            )));
        }

        let mut hash = [0u8; 32];
        env.get_byte_array_region(&result_array, 0, bytemuck::cast_slice_mut(&mut hash))
            .map_err(|e| CryptoError::Other(format!("Failed to copy result: {e}")))?;

        Ok(hash)
    })
}

/// Compute HMAC-SHA1 using javax.crypto.Mac.
pub fn hmac_sha1(key: &[u8], data: &[u8]) -> Result<[u8; 20], CryptoError> {
    with_jni_env!(|env: &mut JNIEnv, classes: &JniCache| {
        let mac_class = unsafe { as_class(&classes.mac) };
        let key_spec_class = unsafe { as_class(&classes.secret_key_spec) };
        let algorithm = unsafe { as_obj(&classes.str_hmac_sha1) };

        // Call Mac.getInstance("HmacSHA1")
        let mac =
            unsafe { get_instance(env, &mac_class, classes.mid_mac_get_instance, &algorithm) }?;

        // Create key byte array
        let key_array = env
            .byte_array_from_slice(key)
            .map_err(|e| CryptoError::Other(format!("Failed to create key array: {e}")))?;

        // Create SecretKeySpec(key, "HmacSHA1")
        let key_spec = env
            .new_object(
                &key_spec_class,
                "([BLjava/lang/String;)V",
                &[JValue::Object(&key_array), JValue::Object(&algorithm)],
            )
            .map_err(|e| CryptoError::Other(format!("Failed to create SecretKeySpec: {e}")))?;

        // Call mac.init(keySpec)
        unsafe {
            call_void(
                env,
                &mac,
                classes.mid_mac_init,
                &[jvalue {
                    l: key_spec.as_raw(),
                }],
            )
        }?;

        // Create data byte array
        let data_array = env
            .byte_array_from_slice(data)
            .map_err(|e| CryptoError::Other(format!("Failed to create data array: {e}")))?;

        // Call mac.doFinal(data)
        let result = unsafe {
            call_obj(
                env,
                &mac,
                classes.mid_mac_do_final,
                &[jvalue {
                    l: data_array.as_raw(),
                }],
            )
        }?;

        // Convert result to Rust array
        let result_array: JByteArray = result.into();
        let result_len = env
            .get_array_length(&result_array)
            .map_err(|e| CryptoError::Other(format!("Failed to get array length: {e}")))?
            as usize;

        if result_len != 20 {
            return Err(CryptoError::Other(format!(
                "Unexpected HMAC-SHA1 result length: {result_len}"
            )));
        }

        let mut hmac = [0u8; 20];
        env.get_byte_array_region(&result_array, 0, bytemuck::cast_slice_mut(&mut hmac))
            .map_err(|e| CryptoError::Other(format!("Failed to copy result: {e}")))?;

        Ok(hmac)
    })
}

/// Compute HMAC-SHA256 using javax.crypto.Mac.
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> Result<[u8; 32], CryptoError> {
    with_jni_env!(|env: &mut JNIEnv, classes: &JniCache| {
        let mac_class = unsafe { as_class(&classes.mac) };
        let key_spec_class = unsafe { as_class(&classes.secret_key_spec) };
        let algorithm = unsafe { as_obj(&classes.str_hmac_sha256) };

        // Call Mac.getInstance("HmacSHA256")
        let mac =
            unsafe { get_instance(env, &mac_class, classes.mid_mac_get_instance, &algorithm) }?;

        // Create key byte array
        let key_array = env
            .byte_array_from_slice(key)
            .map_err(|e| CryptoError::Other(format!("Failed to create key array: {e}")))?;

        // Create SecretKeySpec(key, "HmacSHA256")
        let key_spec = env
            .new_object(
                &key_spec_class,
                "([BLjava/lang/String;)V",
                &[JValue::Object(&key_array), JValue::Object(&algorithm)],
            )
            .map_err(|e| CryptoError::Other(format!("Failed to create SecretKeySpec: {e}")))?;

        // Call mac.init(keySpec)
        unsafe {
            call_void(
                env,
                &mac,
                classes.mid_mac_init,
                &[jvalue {
                    l: key_spec.as_raw(),
                }],
            )
        }?;

        // Create data byte array
        let data_array = env
            .byte_array_from_slice(data)
            .map_err(|e| CryptoError::Other(format!("Failed to create data array: {e}")))?;

        // Call mac.doFinal(data)
        let result = unsafe {
            call_obj(
                env,
                &mac,
                classes.mid_mac_do_final,
                &[jvalue {
                    l: data_array.as_raw(),
                }],
            )
        }?;

        // Convert result to Rust array
        let result_array: JByteArray = result.into();
        let result_len = env
            .get_array_length(&result_array)
            .map_err(|e| CryptoError::Other(format!("Failed to get array length: {e}")))?
            as usize;

        if result_len != 32 {
            return Err(CryptoError::Other(format!(
                "Unexpected HMAC-SHA256 result length: {result_len}"
            )));
        }

        let mut hmac = [0u8; 32];
        env.get_byte_array_region(&result_array, 0, bytemuck::cast_slice_mut(&mut hmac))
            .map_err(|e| CryptoError::Other(format!("Failed to copy result: {e}")))?;

        Ok(hmac)
    })
}

/// Compute HMAC-SHA384 using javax.crypto.Mac.
pub fn hmac_sha384(key: &[u8], data: &[u8]) -> Result<[u8; 48], CryptoError> {
    with_jni_env!(|env: &mut JNIEnv, classes: &JniCache| {
        let mac_class = unsafe { as_class(&classes.mac) };
        let key_spec_class = unsafe { as_class(&classes.secret_key_spec) };
        let algorithm = unsafe { as_obj(&classes.str_hmac_sha384) };

        // Call Mac.getInstance("HmacSHA384")
        let mac =
            unsafe { get_instance(env, &mac_class, classes.mid_mac_get_instance, &algorithm) }?;

        // Create key byte array
        let key_array = env
            .byte_array_from_slice(key)
            .map_err(|e| CryptoError::Other(format!("Failed to create key array: {e}")))?;

        // Create SecretKeySpec(key, "HmacSHA384")
        let key_spec = env
            .new_object(
                &key_spec_class,
                "([BLjava/lang/String;)V",
                &[JValue::Object(&key_array), JValue::Object(&algorithm)],
            )
            .map_err(|e| CryptoError::Other(format!("Failed to create SecretKeySpec: {e}")))?;

        // Call mac.init(keySpec)
        unsafe {
            call_void(
                env,
                &mac,
                classes.mid_mac_init,
                &[jvalue {
                    l: key_spec.as_raw(),
                }],
            )
        }?;

        // Create data byte array
        let data_array = env
            .byte_array_from_slice(data)
            .map_err(|e| CryptoError::Other(format!("Failed to create data array: {e}")))?;

        // Call mac.doFinal(data)
        let result = unsafe {
            call_obj(
                env,
                &mac,
                classes.mid_mac_do_final,
                &[jvalue {
                    l: data_array.as_raw(),
                }],
            )
        }?;

        // Convert result to Rust array
        let result_array: JByteArray = result.into();
        let result_len = env
            .get_array_length(&result_array)
            .map_err(|e| CryptoError::Other(format!("Failed to get array length: {e}")))?
            as usize;

        if result_len != 48 {
            return Err(CryptoError::Other(format!(
                "Unexpected HMAC-SHA384 result length: {result_len}"
            )));
        }

        let mut hmac = [0u8; 48];
        env.get_byte_array_region(&result_array, 0, bytemuck::cast_slice_mut(&mut hmac))
            .map_err(|e| CryptoError::Other(format!("Failed to copy result: {e}")))?;

        Ok(hmac)
    })
}

/// Perform AES-ECB encryption using javax.crypto.Cipher.
pub fn aes_ecb_encrypt(key: &[u8], input: &[u8], output: &mut [u8]) -> Result<(), CryptoError> {
    with_jni_env!(|env: &mut JNIEnv, classes: &JniCache| {
        let cipher_class = unsafe { as_class(&classes.cipher) };
        let key_spec_class = unsafe { as_class(&classes.secret_key_spec) };
        let transformation = unsafe { as_obj(&classes.str_aes_ecb) };

        // Call Cipher.getInstance("AES/ECB/NoPadding")
        let cipher = unsafe {
            get_instance(
                env,
                &cipher_class,
                classes.mid_cipher_get_instance,
                &transformation,
            )
        }?;

        // Create key byte array and algorithm string
        let key_array = env
            .byte_array_from_slice(key)
            .map_err(|e| CryptoError::Other(format!("Failed to create key array: {e}")))?;

        let aes_algorithm = unsafe { as_obj(&classes.str_aes) };

        // Create SecretKeySpec(key, "AES")
        let key_spec = env
            .new_object(
                &key_spec_class,
                "([BLjava/lang/String;)V",
                &[JValue::Object(&key_array), JValue::Object(&aes_algorithm)],
            )
            .map_err(|e| CryptoError::Other(format!("Failed to create SecretKeySpec: {e}")))?;

        // Get ENCRYPT_MODE constant (value is 1)
        let encrypt_mode = 1i32;

        // Call cipher.init(ENCRYPT_MODE, keySpec)
        unsafe {
            call_void(
                env,
                &cipher,
                classes.mid_cipher_init2,
                &[
                    jvalue { i: encrypt_mode },
                    jvalue {
                        l: key_spec.as_raw(),
                    },
                ],
            )
        }?;

        // Create input byte array
        let input_array = env
            .byte_array_from_slice(input)
            .map_err(|e| CryptoError::Other(format!("Failed to create input array: {e}")))?;

        // Call cipher.doFinal(input)
        let result = unsafe {
            call_obj(
                env,
                &cipher,
                classes.mid_cipher_do_final,
                &[jvalue {
                    l: input_array.as_raw(),
                }],
            )
        }?;

        // Copy result to output
        let result_array: JByteArray = result.into();
        let result_len = env
            .get_array_length(&result_array)
            .map_err(|e| CryptoError::Other(format!("Failed to get array length: {e}")))?
            as usize;

        if result_len > output.len() {
            return Err(CryptoError::Other(format!(
                "Output buffer too small: need {result_len}, have {}",
                output.len()
            )));
        }

        env.get_byte_array_region(
            &result_array,
            0,
            bytemuck::cast_slice_mut(&mut output[..result_len]),
        )
        .map_err(|e| CryptoError::Other(format!("Failed to copy result: {e}")))?;

        Ok(())
    })
}

/// Perform AES-GCM encryption using javax.crypto.Cipher.
pub fn aes_gcm_encrypt(
    key: &[u8],
    iv: &[u8],
    input: &[u8],
    aad: &[u8],
    output: &mut [u8],
) -> Result<usize, CryptoError> {
    with_jni_env!(|env: &mut JNIEnv, classes: &JniCache| {
        let cipher_class = unsafe { as_class(&classes.cipher) };
        let key_spec_class = unsafe { as_class(&classes.secret_key_spec) };
        let gcm_spec_class = unsafe { as_class(&classes.gcm_parameter_spec) };
        let transformation = unsafe { as_obj(&classes.str_aes_gcm) };

        // Call Cipher.getInstance("AES/GCM/NoPadding")
        let cipher = unsafe {
            get_instance(
                env,
                &cipher_class,
                classes.mid_cipher_get_instance,
                &transformation,
            )
        }?;

        // Create key byte array and algorithm string
        let key_array = env
            .byte_array_from_slice(key)
            .map_err(|e| CryptoError::Other(format!("Failed to create key array: {e}")))?;

        let aes_algorithm = unsafe { as_obj(&classes.str_aes) };

        // Create SecretKeySpec(key, "AES")
        let key_spec = env
            .new_object(
                &key_spec_class,
                "([BLjava/lang/String;)V",
                &[JValue::Object(&key_array), JValue::Object(&aes_algorithm)],
            )
            .map_err(|e| CryptoError::Other(format!("Failed to create SecretKeySpec: {e}")))?;

        // Create IV byte array
        let iv_array = env
            .byte_array_from_slice(iv)
            .map_err(|e| CryptoError::Other(format!("Failed to create IV array: {e}")))?;

        // Create GCMParameterSpec(128, iv) - 128 is the tag length in bits
        let gcm_spec = env
            .new_object(
                &gcm_spec_class,
                "(I[B)V",
                &[JValue::Int(128), JValue::Object(&iv_array)],
            )
            .map_err(|e| CryptoError::Other(format!("Failed to create GCMParameterSpec: {e}")))?;

        // Get ENCRYPT_MODE constant (value is 1)
        let encrypt_mode = 1i32;

        // Call cipher.init(ENCRYPT_MODE, keySpec, gcmSpec)
        unsafe {
            call_void(
                env,
                &cipher,
                classes.mid_cipher_init3,
                &[
                    jvalue { i: encrypt_mode },
                    jvalue {
                        l: key_spec.as_raw(),
                    },
                    jvalue {
                        l: gcm_spec.as_raw(),
                    },
                ],
            )
        }?;

        // Update AAD if present
        if !aad.is_empty() {
            let aad_array = env
                .byte_array_from_slice(aad)
                .map_err(|e| CryptoError::Other(format!("Failed to create AAD array: {e}")))?;

            unsafe {
                call_void(
                    env,
                    &cipher,
                    classes.mid_cipher_update_aad,
                    &[jvalue {
                        l: aad_array.as_raw(),
                    }],
                )
            }?;
        }

        // Create input byte array
        let input_array = env
            .byte_array_from_slice(input)
            .map_err(|e| CryptoError::Other(format!("Failed to create input array: {e}")))?;

        // Call cipher.doFinal(input)
        let result = unsafe {
            call_obj(
                env,
                &cipher,
                classes.mid_cipher_do_final,
                &[jvalue {
                    l: input_array.as_raw(),
                }],
            )
        }?;

        // Copy result to output
        let result_array: JByteArray = result.into();
        let result_len = env
            .get_array_length(&result_array)
            .map_err(|e| CryptoError::Other(format!("Failed to get array length: {e}")))?
            as usize;

        if result_len > output.len() {
            return Err(CryptoError::Other(format!(
                "Output buffer too small: need {result_len}, have {}",
                output.len()
            )));
        }

        env.get_byte_array_region(
            &result_array,
            0,
            bytemuck::cast_slice_mut(&mut output[..result_len]),
        )
        .map_err(|e| CryptoError::Other(format!("Failed to copy result: {e}")))?;

        Ok(result_len)
    })
}

/// Perform AES-GCM decryption using javax.crypto.Cipher.
pub fn aes_gcm_decrypt(
    key: &[u8],
    iv: &[u8],
    input: &[u8],
    aad: &[u8],
    output: &mut [u8],
) -> Result<usize, CryptoError> {
    with_jni_env!(|env: &mut JNIEnv, classes: &JniCache| {
        let cipher_class = unsafe { as_class(&classes.cipher) };
        let key_spec_class = unsafe { as_class(&classes.secret_key_spec) };
        let gcm_spec_class = unsafe { as_class(&classes.gcm_parameter_spec) };
        let transformation = unsafe { as_obj(&classes.str_aes_gcm) };

        // Call Cipher.getInstance("AES/GCM/NoPadding")
        let cipher = unsafe {
            get_instance(
                env,
                &cipher_class,
                classes.mid_cipher_get_instance,
                &transformation,
            )
        }?;

        // Create key byte array and algorithm string
        let key_array = env
            .byte_array_from_slice(key)
            .map_err(|e| CryptoError::Other(format!("Failed to create key array: {e}")))?;

        let aes_algorithm = unsafe { as_obj(&classes.str_aes) };

        // Create SecretKeySpec(key, "AES")
        let key_spec = env
            .new_object(
                &key_spec_class,
                "([BLjava/lang/String;)V",
                &[JValue::Object(&key_array), JValue::Object(&aes_algorithm)],
            )
            .map_err(|e| CryptoError::Other(format!("Failed to create SecretKeySpec: {e}")))?;

        // Create IV byte array
        let iv_array = env
            .byte_array_from_slice(iv)
            .map_err(|e| CryptoError::Other(format!("Failed to create IV array: {e}")))?;

        // Create GCMParameterSpec(128, iv) - 128 is the tag length in bits
        let gcm_spec = env
            .new_object(
                &gcm_spec_class,
                "(I[B)V",
                &[JValue::Int(128), JValue::Object(&iv_array)],
            )
            .map_err(|e| CryptoError::Other(format!("Failed to create GCMParameterSpec: {e}")))?;

        // Get DECRYPT_MODE constant (value is 2)
        let decrypt_mode = 2i32;

        // Call cipher.init(DECRYPT_MODE, keySpec, gcmSpec)
        unsafe {
            call_void(
                env,
                &cipher,
                classes.mid_cipher_init3,
                &[
                    jvalue { i: decrypt_mode },
                    jvalue {
                        l: key_spec.as_raw(),
                    },
                    jvalue {
                        l: gcm_spec.as_raw(),
                    },
                ],
            )
        }?;

        // Update AAD if present
        if !aad.is_empty() {
            let aad_array = env
                .byte_array_from_slice(aad)
                .map_err(|e| CryptoError::Other(format!("Failed to create AAD array: {e}")))?;

            unsafe {
                call_void(
                    env,
                    &cipher,
                    classes.mid_cipher_update_aad,
                    &[jvalue {
                        l: aad_array.as_raw(),
                    }],
                )
            }?;
        }

        // Create input byte array
        let input_array = env
            .byte_array_from_slice(input)
            .map_err(|e| CryptoError::Other(format!("Failed to create input array: {e}")))?;

        // Call cipher.doFinal(input)
        let result = unsafe {
            call_obj(
                env,
                &cipher,
                classes.mid_cipher_do_final,
                &[jvalue {
                    l: input_array.as_raw(),
                }],
            )
        }?;

        // Copy result to output
        let result_array: JByteArray = result.into();
        let result_len = env
            .get_array_length(&result_array)
            .map_err(|e| CryptoError::Other(format!("Failed to get array length: {e}")))?
            as usize;

        if result_len > output.len() {
            return Err(CryptoError::Other(format!(
                "Output buffer too small: need {result_len}, have {}",
                output.len()
            )));
        }

        env.get_byte_array_region(
            &result_array,
            0,
            bytemuck::cast_slice_mut(&mut output[..result_len]),
        )
        .map_err(|e| CryptoError::Other(format!("Failed to copy result: {e}")))?;

        Ok(result_len)
    })
}

/// Generate cryptographically secure random bytes using java.security.SecureRandom.
pub fn secure_random(buf: &mut [u8]) -> Result<(), CryptoError> {
    with_jni_env!(|env: &mut JNIEnv, classes: &JniCache| {
        let random_class = unsafe { as_class(&classes.secure_random) };

        let random = env
            .new_object(&random_class, "()V", &[])
            .map_err(|e| CryptoError::Other(format!("Failed to create SecureRandom: {e}")))?;

        // Create output byte array
        let output_array = env
            .new_byte_array(buf.len() as i32)
            .map_err(|e| CryptoError::Other(format!("Failed to create byte array: {e}")))?;

        // Call random.nextBytes(output)
        unsafe {
            call_void(
                env,
                &random,
                classes.mid_secure_random_next_bytes,
                &[jvalue {
                    l: output_array.as_raw(),
                }],
            )
        }?;

        // Copy result to buffer
        env.get_byte_array_region(&output_array, 0, bytemuck::cast_slice_mut(buf))
            .map_err(|e| CryptoError::Other(format!("Failed to copy random bytes: {e}")))?;

        Ok(())
    })
}

/// SHA-256 hash context for incremental hashing.
pub struct Sha256Context {
    // We store the accumulated data since Android's MessageDigest
    // requires ownership of the object for each operation
    data: Vec<u8>,
}

#[allow(dead_code)]
impl Sha256Context {
    pub fn new() -> Self {
        Self { data: Vec::new() }
    }

    pub fn update(&mut self, data: &[u8]) {
        self.data.extend_from_slice(data);
    }

    pub fn finalize(&self) -> Result<[u8; 32], CryptoError> {
        sha256(&self.data)
    }

    pub fn snapshot(&self) -> Result<[u8; 32], CryptoError> {
        sha256(&self.data)
    }
}

/// SHA-384 hash using java.security.MessageDigest.
pub fn sha384(data: &[u8]) -> Result<[u8; 48], CryptoError> {
    with_jni_env!(|env: &mut JNIEnv, classes: &JniCache| {
        let digest_class = unsafe { as_class(&classes.message_digest) };
        let algorithm = unsafe { as_obj(&classes.str_sha384) };

        // Call MessageDigest.getInstance("SHA-384")
        let digest = unsafe {
            get_instance(
                env,
                &digest_class,
                classes.mid_message_digest_get_instance,
                &algorithm,
            )
        }?;

        // Create byte array from input data
        let input_array = env
            .byte_array_from_slice(data)
            .map_err(|e| CryptoError::Other(format!("Failed to create byte array: {e}")))?;

        // Call digest.digest(input)
        let result = unsafe {
            call_obj(
                env,
                &digest,
                classes.mid_digest_digest,
                &[jvalue {
                    l: input_array.as_raw(),
                }],
            )
        }?;

        // Convert result to Rust array
        let result_array: JByteArray = result.into();
        let result_len = env
            .get_array_length(&result_array)
            .map_err(|e| CryptoError::Other(format!("Failed to get array length: {e}")))?
            as usize;

        if result_len != 48 {
            return Err(CryptoError::Other(format!(
                "Unexpected SHA-384 result length: {result_len}"
            )));
        }

        let mut hash = [0u8; 48];
        env.get_byte_array_region(&result_array, 0, bytemuck::cast_slice_mut(&mut hash))
            .map_err(|e| CryptoError::Other(format!("Failed to copy result: {e}")))?;

        Ok(hash)
    })
}

/// SHA-384 hash context for incremental hashing.
pub struct Sha384Context {
    data: Vec<u8>,
}

#[allow(dead_code)]
impl Sha384Context {
    pub fn new() -> Self {
        Self { data: Vec::new() }
    }

    pub fn update(&mut self, data: &[u8]) {
        self.data.extend_from_slice(data);
    }

    pub fn finalize(&self) -> Result<[u8; 48], CryptoError> {
        sha384(&self.data)
    }

    pub fn snapshot(&self) -> Result<[u8; 48], CryptoError> {
        sha384(&self.data)
    }
}

/// EC key pair for ECDSA signing and ECDH key exchange.
pub struct EcKeyPair {
    /// The private key in PKCS#8 DER format
    pub private_key_der: Vec<u8>,
    /// The public key as uncompressed point (04 || X || Y)
    pub public_key_bytes: Vec<u8>,
}

/// Generate an EC P-256 key pair using java.security.KeyPairGenerator.
pub fn generate_ec_key_pair_p256() -> Result<EcKeyPair, CryptoError> {
    with_jni_env!(|env: &mut JNIEnv, classes: &JniCache| {
        let kpg_class = unsafe { as_class(&classes.key_pair_generator) };
        let ec_spec_class = unsafe { as_class(&classes.ec_gen_parameter_spec) };
        let algorithm = unsafe { as_obj(&classes.str_ec) };

        // Call KeyPairGenerator.getInstance("EC")
        let kpg =
            unsafe { get_instance(env, &kpg_class, classes.mid_kpg_get_instance, &algorithm) }?;

        // Create curve name string
        let curve_name = unsafe { as_obj(&classes.str_secp256r1) };

        // Create ECGenParameterSpec
        let ec_spec = env
            .new_object(
                &ec_spec_class,
                "(Ljava/lang/String;)V",
                &[JValue::Object(&curve_name)],
            )
            .map_err(|e| CryptoError::Other(format!("Failed to create ECGenParameterSpec: {e}")))?;

        // Initialize with the spec
        unsafe {
            call_void(
                env,
                &kpg,
                classes.mid_kpg_initialize,
                &[jvalue {
                    l: ec_spec.as_raw(),
                }],
            )
        }?;

        // Generate key pair
        let key_pair = unsafe { call_obj(env, &kpg, classes.mid_kpg_generate_key_pair, &[]) }?;

        // Get private key
        let private_key =
            unsafe { call_obj(env, &key_pair, classes.mid_key_pair_get_private, &[]) }?;

        // Get public key
        let public_key = unsafe { call_obj(env, &key_pair, classes.mid_key_pair_get_public, &[]) }?;

        // Get encoded private key (PKCS#8 format)
        let private_key_encoded =
            unsafe { call_obj(env, &private_key, classes.mid_key_get_encoded, &[]) }?;

        let private_key_array: JByteArray = private_key_encoded.into();
        let private_key_len = env
            .get_array_length(&private_key_array)
            .map_err(|e| CryptoError::Other(format!("Failed to get private key length: {e}")))?
            as usize;

        let mut private_key_der = vec![0i8; private_key_len];
        env.get_byte_array_region(&private_key_array, 0, &mut private_key_der)
            .map_err(|e| CryptoError::Other(format!("Failed to copy private key: {e}")))?;

        // Get encoded public key (X.509 SubjectPublicKeyInfo format)
        let public_key_encoded =
            unsafe { call_obj(env, &public_key, classes.mid_key_get_encoded, &[]) }?;

        let public_key_array: JByteArray = public_key_encoded.into();
        let public_key_len = env
            .get_array_length(&public_key_array)
            .map_err(|e| CryptoError::Other(format!("Failed to get public key length: {e}")))?
            as usize;

        let mut public_key_der = vec![0i8; public_key_len];
        env.get_byte_array_region(&public_key_array, 0, &mut public_key_der)
            .map_err(|e| CryptoError::Other(format!("Failed to copy public key: {e}")))?;

        // Extract the raw public key bytes from SubjectPublicKeyInfo
        // The structure is: SEQUENCE { AlgorithmIdentifier, BIT STRING { public key } }
        // For EC P-256, the raw public key is 65 bytes (04 || X || Y)
        let public_key_bytes = extract_ec_public_key_from_spki(&public_key_der)?;

        Ok(EcKeyPair {
            private_key_der: private_key_der.iter().map(|&b| b as u8).collect(),
            public_key_bytes,
        })
    })
}

/// Extract raw EC public key bytes from SubjectPublicKeyInfo DER encoding.
fn extract_ec_public_key_from_spki(spki: &[i8]) -> Result<Vec<u8>, CryptoError> {
    // Simple ASN.1 parsing for SubjectPublicKeyInfo
    // SEQUENCE {
    //   AlgorithmIdentifier SEQUENCE { OID, parameters },
    //   BIT STRING { public key }
    // }

    let spki: Vec<u8> = spki.iter().map(|&b| b as u8).collect();

    if spki.len() < 2 {
        return Err(CryptoError::Other("SPKI too short".into()));
    }

    // Skip outer SEQUENCE tag and length
    let (_, rest) = skip_tag_length(&spki, 0x30)?;

    // Skip AlgorithmIdentifier SEQUENCE
    let (_, rest) = skip_tag_length(rest, 0x30)?;

    // Parse BIT STRING
    if rest.is_empty() || rest[0] != 0x03 {
        return Err(CryptoError::Other("Expected BIT STRING tag".into()));
    }

    let (content, _) = skip_tag_length(rest, 0x03)?;

    // BIT STRING has a leading byte for unused bits (should be 0)
    if content.is_empty() || content[0] != 0 {
        return Err(CryptoError::Other("Invalid BIT STRING content".into()));
    }

    // The remaining bytes are the public key (04 || X || Y for uncompressed)
    Ok(content[1..].to_vec())
}

/// Skip ASN.1 tag and length, returning content and remaining bytes.
fn skip_tag_length(data: &[u8], expected_tag: u8) -> Result<(&[u8], &[u8]), CryptoError> {
    if data.is_empty() {
        return Err(CryptoError::Other("Empty data".into()));
    }

    if data[0] != expected_tag {
        return Err(CryptoError::Other(format!(
            "Expected tag 0x{:02x}, got 0x{:02x}",
            expected_tag, data[0]
        )));
    }

    if data.len() < 2 {
        return Err(CryptoError::Other("Data too short for length".into()));
    }

    let (len, header_len) = if data[1] & 0x80 == 0 {
        // Short form length
        (data[1] as usize, 2)
    } else {
        // Long form length
        let num_octets = (data[1] & 0x7f) as usize;
        if data.len() < 2 + num_octets {
            return Err(CryptoError::Other("Data too short for long length".into()));
        }
        let mut len = 0usize;
        for i in 0..num_octets {
            len = (len << 8) | data[2 + i] as usize;
        }
        (len, 2 + num_octets)
    };

    if data.len() < header_len + len {
        return Err(CryptoError::Other("Data too short for content".into()));
    }

    Ok((
        &data[header_len..header_len + len],
        &data[header_len + len..],
    ))
}

/// Sign data using ECDSA with SHA-256 using java.security.Signature.
pub fn ecdsa_sign_sha256(private_key_der: &[u8], data: &[u8]) -> Result<Vec<u8>, CryptoError> {
    with_jni_env!(|env: &mut JNIEnv, classes: &JniCache| {
        let key_factory_class = unsafe { as_class(&classes.key_factory) };
        let key_spec_class = unsafe { as_class(&classes.pkcs8_encoded_key_spec) };
        let signature_class = unsafe { as_class(&classes.signature) };
        let ec_algorithm = unsafe { as_obj(&classes.str_ec) };
        let sig_algorithm = unsafe { as_obj(&classes.str_sha256_ecdsa) };

        // Get KeyFactory for EC
        let key_factory = unsafe {
            get_instance(
                env,
                &key_factory_class,
                classes.mid_key_factory_get_instance,
                &ec_algorithm,
            )
        }?;

        // Create key spec from DER bytes
        let key_bytes = env
            .byte_array_from_slice(private_key_der)
            .map_err(|e| CryptoError::Other(format!("Failed to create key byte array: {e}")))?;

        let key_spec = env
            .new_object(&key_spec_class, "([B)V", &[JValue::Object(&key_bytes)])
            .map_err(|e| {
                CryptoError::Other(format!("Failed to create PKCS8EncodedKeySpec: {e}"))
            })?;

        // Generate private key from spec
        let private_key = unsafe {
            call_obj(
                env,
                &key_factory,
                classes.mid_key_factory_generate_private,
                &[jvalue {
                    l: key_spec.as_raw(),
                }],
            )
        }?;

        // Get Signature instance
        let signature = unsafe {
            get_instance(
                env,
                &signature_class,
                classes.mid_signature_get_instance,
                &sig_algorithm,
            )
        }?;

        // Initialize for signing
        unsafe {
            call_void(
                env,
                &signature,
                classes.mid_signature_init_sign,
                &[jvalue {
                    l: private_key.as_raw(),
                }],
            )
        }?;

        // Update with data
        let data_array = env
            .byte_array_from_slice(data)
            .map_err(|e| CryptoError::Other(format!("Failed to create data array: {e}")))?;

        unsafe {
            call_void(
                env,
                &signature,
                classes.mid_signature_update,
                &[jvalue {
                    l: data_array.as_raw(),
                }],
            )
        }?;

        // Sign
        let sig_bytes = unsafe { call_obj(env, &signature, classes.mid_signature_sign, &[]) }?;

        // Convert to Vec
        let sig_array: JByteArray = sig_bytes.into();
        let sig_len = env
            .get_array_length(&sig_array)
            .map_err(|e| CryptoError::Other(format!("Failed to get signature length: {e}")))?
            as usize;

        let mut result = vec![0i8; sig_len];
        env.get_byte_array_region(&sig_array, 0, &mut result)
            .map_err(|e| CryptoError::Other(format!("Failed to copy signature: {e}")))?;

        Ok(result.iter().map(|&b| b as u8).collect())
    })
}

/// Perform ECDH key agreement using javax.crypto.KeyAgreement.
pub fn ecdh_key_agreement(
    private_key_der: &[u8],
    peer_public_key_bytes: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    with_jni_env!(|env: &mut JNIEnv, classes: &JniCache| {
        let key_factory_class = unsafe { as_class(&classes.key_factory) };
        let pkcs8_spec_class = unsafe { as_class(&classes.pkcs8_encoded_key_spec) };
        let x509_spec_class = unsafe { as_class(&classes.x509_encoded_key_spec) };
        let key_agreement_class = unsafe { as_class(&classes.key_agreement) };
        let ec_algorithm = unsafe { as_obj(&classes.str_ec) };
        let ecdh_algorithm = unsafe { as_obj(&classes.str_ecdh) };

        // Get KeyFactory for EC
        let key_factory = unsafe {
            get_instance(
                env,
                &key_factory_class,
                classes.mid_key_factory_get_instance,
                &ec_algorithm,
            )
        }?;

        // Create private key from PKCS#8 DER
        let private_key_bytes = env
            .byte_array_from_slice(private_key_der)
            .map_err(|e| CryptoError::Other(format!("Failed to create private key array: {e}")))?;

        let private_key_spec = env
            .new_object(
                &pkcs8_spec_class,
                "([B)V",
                &[JValue::Object(&private_key_bytes)],
            )
            .map_err(|e| {
                CryptoError::Other(format!("Failed to create PKCS8EncodedKeySpec: {e}"))
            })?;

        let private_key = unsafe {
            call_obj(
                env,
                &key_factory,
                classes.mid_key_factory_generate_private,
                &[jvalue {
                    l: private_key_spec.as_raw(),
                }],
            )
        }?;

        // Wrap peer public key in X.509 SubjectPublicKeyInfo format
        let peer_spki = wrap_ec_public_key_in_spki(peer_public_key_bytes)?;

        let public_key_bytes = env
            .byte_array_from_slice(&peer_spki)
            .map_err(|e| CryptoError::Other(format!("Failed to create public key array: {e}")))?;

        let public_key_spec = env
            .new_object(
                &x509_spec_class,
                "([B)V",
                &[JValue::Object(&public_key_bytes)],
            )
            .map_err(|e| CryptoError::Other(format!("Failed to create X509EncodedKeySpec: {e}")))?;

        let public_key = unsafe {
            call_obj(
                env,
                &key_factory,
                classes.mid_key_factory_generate_public,
                &[jvalue {
                    l: public_key_spec.as_raw(),
                }],
            )
        }?;

        // Get KeyAgreement instance
        let key_agreement = unsafe {
            get_instance(
                env,
                &key_agreement_class,
                classes.mid_key_agreement_get_instance,
                &ecdh_algorithm,
            )
        }?;

        // Initialize with private key
        unsafe {
            call_void(
                env,
                &key_agreement,
                classes.mid_key_agreement_init,
                &[jvalue {
                    l: private_key.as_raw(),
                }],
            )
        }?;

        // Do phase with public key
        unsafe {
            call_obj(
                env,
                &key_agreement,
                classes.mid_key_agreement_do_phase,
                &[
                    jvalue {
                        l: public_key.as_raw(),
                    },
                    jvalue { z: 1 },
                ],
            )
        }?;

        // Generate shared secret
        let shared_secret = unsafe {
            call_obj(
                env,
                &key_agreement,
                classes.mid_key_agreement_generate_secret,
                &[],
            )
        }?;

        // Convert to Vec
        let secret_array: JByteArray = shared_secret.into();
        let secret_len = env
            .get_array_length(&secret_array)
            .map_err(|e| CryptoError::Other(format!("Failed to get secret length: {e}")))?
            as usize;

        let mut result = vec![0i8; secret_len];
        env.get_byte_array_region(&secret_array, 0, &mut result)
            .map_err(|e| CryptoError::Other(format!("Failed to copy shared secret: {e}")))?;

        Ok(result.iter().map(|&b| b as u8).collect())
    })
}

/// Wrap raw EC public key bytes in X.509 SubjectPublicKeyInfo format.
fn wrap_ec_public_key_in_spki(public_key_bytes: &[u8]) -> Result<Vec<u8>, CryptoError> {
    // SubjectPublicKeyInfo ::= SEQUENCE {
    //   algorithm AlgorithmIdentifier,
    //   subjectPublicKey BIT STRING
    // }
    //
    // AlgorithmIdentifier ::= SEQUENCE {
    //   algorithm OBJECT IDENTIFIER (1.2.840.10045.2.1 for ecPublicKey)
    //   parameters ANY (1.2.840.10045.3.1.7 for P-256)
    // }

    // ecPublicKey OID: 1.2.840.10045.2.1
    let ec_public_key_oid = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01];
    // P-256 (secp256r1) OID: 1.2.840.10045.3.1.7
    let p256_oid = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];

    // Build AlgorithmIdentifier
    let mut algorithm = Vec::new();
    // ecPublicKey OID
    algorithm.push(0x06); // OID tag
    algorithm.push(ec_public_key_oid.len() as u8);
    algorithm.extend_from_slice(ec_public_key_oid);
    // P-256 parameters OID
    algorithm.push(0x06); // OID tag
    algorithm.push(p256_oid.len() as u8);
    algorithm.extend_from_slice(p256_oid);

    // Wrap in SEQUENCE
    let mut alg_seq = vec![0x30]; // SEQUENCE tag
    alg_seq.push(algorithm.len() as u8);
    alg_seq.extend_from_slice(&algorithm);

    // Build BIT STRING with public key
    let mut bit_string = vec![0x03]; // BIT STRING tag
    bit_string.push((public_key_bytes.len() + 1) as u8); // length including unused bits byte
    bit_string.push(0x00); // unused bits
    bit_string.extend_from_slice(public_key_bytes);

    // Combine into SubjectPublicKeyInfo SEQUENCE
    let content_len = alg_seq.len() + bit_string.len();
    let mut spki = vec![0x30]; // SEQUENCE tag
    if content_len < 128 {
        spki.push(content_len as u8);
    } else {
        spki.push(0x81);
        spki.push(content_len as u8);
    }
    spki.extend_from_slice(&alg_seq);
    spki.extend_from_slice(&bit_string);

    Ok(spki)
}
