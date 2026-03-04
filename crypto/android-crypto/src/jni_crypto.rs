//! JNI bindings to Android's javax.crypto and java.security APIs.
//!
//! This module provides low-level wrappers around Android's crypto functionality
//! accessed via JNI.

use jni::objects::{JByteArray, JValue};
use jni::JNIEnv;

use str0m_proto::crypto::CryptoError;

use crate::get_jvm;

/// Execute a JNI operation with proper environment handling.
///
/// This macro attaches the current thread to the JVM if necessary,
/// executes the provided closure, and handles errors.
macro_rules! with_jni_env {
    ($f:expr) => {{
        let jvm = get_jvm();
        let mut env = jvm
            .attach_current_thread()
            .map_err(|e| CryptoError::Other(format!("Failed to attach JNI thread: {e}")))?;
        $f(&mut env)
    }};
}

/// Compute SHA-256 hash using java.security.MessageDigest.
pub fn sha256(data: &[u8]) -> Result<[u8; 32], CryptoError> {
    with_jni_env!(|env: &mut JNIEnv| {
        // Get MessageDigest class
        let digest_class = env
            .find_class("java/security/MessageDigest")
            .map_err(|e| CryptoError::Other(format!("Failed to find MessageDigest class: {e}")))?;

        // Get getInstance method
        let algorithm = env
            .new_string("SHA-256")
            .map_err(|e| CryptoError::Other(format!("Failed to create string: {e}")))?;

        // Call MessageDigest.getInstance("SHA-256")
        let digest = env
            .call_static_method(
                &digest_class,
                "getInstance",
                "(Ljava/lang/String;)Ljava/security/MessageDigest;",
                &[JValue::Object(&algorithm)],
            )
            .map_err(|e| CryptoError::Other(format!("Failed to get SHA-256 instance: {e}")))?
            .l()
            .map_err(|e| CryptoError::Other(format!("Failed to get digest object: {e}")))?;

        // Create byte array from input data
        let input_array = env
            .byte_array_from_slice(data)
            .map_err(|e| CryptoError::Other(format!("Failed to create byte array: {e}")))?;

        // Call digest.digest(input)
        let result = env
            .call_method(&digest, "digest", "([B)[B", &[JValue::Object(&input_array)])
            .map_err(|e| CryptoError::Other(format!("Failed to compute digest: {e}")))?
            .l()
            .map_err(|e| CryptoError::Other(format!("Failed to get result object: {e}")))?;

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
    with_jni_env!(|env: &mut JNIEnv| {
        // Get Mac class
        let mac_class = env
            .find_class("javax/crypto/Mac")
            .map_err(|e| CryptoError::Other(format!("Failed to find Mac class: {e}")))?;

        // Get SecretKeySpec class
        let key_spec_class = env
            .find_class("javax/crypto/spec/SecretKeySpec")
            .map_err(|e| CryptoError::Other(format!("Failed to find SecretKeySpec class: {e}")))?;

        // Create algorithm string
        let algorithm = env
            .new_string("HmacSHA1")
            .map_err(|e| CryptoError::Other(format!("Failed to create string: {e}")))?;

        // Call Mac.getInstance("HmacSHA1")
        let mac = env
            .call_static_method(
                &mac_class,
                "getInstance",
                "(Ljava/lang/String;)Ljavax/crypto/Mac;",
                &[JValue::Object(&algorithm)],
            )
            .map_err(|e| CryptoError::Other(format!("Failed to get Mac instance: {e}")))?
            .l()
            .map_err(|e| CryptoError::Other(format!("Failed to get Mac object: {e}")))?;

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
        env.call_method(
            &mac,
            "init",
            "(Ljava/security/Key;)V",
            &[JValue::Object(&key_spec)],
        )
        .map_err(|e| CryptoError::Other(format!("Failed to init Mac: {e}")))?;

        // Create data byte array
        let data_array = env
            .byte_array_from_slice(data)
            .map_err(|e| CryptoError::Other(format!("Failed to create data array: {e}")))?;

        // Call mac.doFinal(data)
        let result = env
            .call_method(&mac, "doFinal", "([B)[B", &[JValue::Object(&data_array)])
            .map_err(|e| CryptoError::Other(format!("Failed to compute HMAC: {e}")))?
            .l()
            .map_err(|e| CryptoError::Other(format!("Failed to get result object: {e}")))?;

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
    with_jni_env!(|env: &mut JNIEnv| {
        // Get Mac class
        let mac_class = env
            .find_class("javax/crypto/Mac")
            .map_err(|e| CryptoError::Other(format!("Failed to find Mac class: {e}")))?;

        // Get SecretKeySpec class
        let key_spec_class = env
            .find_class("javax/crypto/spec/SecretKeySpec")
            .map_err(|e| CryptoError::Other(format!("Failed to find SecretKeySpec class: {e}")))?;

        // Create algorithm string
        let algorithm = env
            .new_string("HmacSHA256")
            .map_err(|e| CryptoError::Other(format!("Failed to create string: {e}")))?;

        // Call Mac.getInstance("HmacSHA256")
        let mac = env
            .call_static_method(
                &mac_class,
                "getInstance",
                "(Ljava/lang/String;)Ljavax/crypto/Mac;",
                &[JValue::Object(&algorithm)],
            )
            .map_err(|e| CryptoError::Other(format!("Failed to get Mac instance: {e}")))?
            .l()
            .map_err(|e| CryptoError::Other(format!("Failed to get Mac object: {e}")))?;

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
        env.call_method(
            &mac,
            "init",
            "(Ljava/security/Key;)V",
            &[JValue::Object(&key_spec)],
        )
        .map_err(|e| CryptoError::Other(format!("Failed to init Mac: {e}")))?;

        // Create data byte array
        let data_array = env
            .byte_array_from_slice(data)
            .map_err(|e| CryptoError::Other(format!("Failed to create data array: {e}")))?;

        // Call mac.doFinal(data)
        let result = env
            .call_method(&mac, "doFinal", "([B)[B", &[JValue::Object(&data_array)])
            .map_err(|e| CryptoError::Other(format!("Failed to compute HMAC: {e}")))?
            .l()
            .map_err(|e| CryptoError::Other(format!("Failed to get result object: {e}")))?;

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
    with_jni_env!(|env: &mut JNIEnv| {
        // Get Mac class
        let mac_class = env
            .find_class("javax/crypto/Mac")
            .map_err(|e| CryptoError::Other(format!("Failed to find Mac class: {e}")))?;

        // Get SecretKeySpec class
        let key_spec_class = env
            .find_class("javax/crypto/spec/SecretKeySpec")
            .map_err(|e| CryptoError::Other(format!("Failed to find SecretKeySpec class: {e}")))?;

        // Create algorithm string
        let algorithm = env
            .new_string("HmacSHA384")
            .map_err(|e| CryptoError::Other(format!("Failed to create string: {e}")))?;

        // Call Mac.getInstance("HmacSHA384")
        let mac = env
            .call_static_method(
                &mac_class,
                "getInstance",
                "(Ljava/lang/String;)Ljavax/crypto/Mac;",
                &[JValue::Object(&algorithm)],
            )
            .map_err(|e| CryptoError::Other(format!("Failed to get Mac instance: {e}")))?
            .l()
            .map_err(|e| CryptoError::Other(format!("Failed to get Mac object: {e}")))?;

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
        env.call_method(
            &mac,
            "init",
            "(Ljava/security/Key;)V",
            &[JValue::Object(&key_spec)],
        )
        .map_err(|e| CryptoError::Other(format!("Failed to init Mac: {e}")))?;

        // Create data byte array
        let data_array = env
            .byte_array_from_slice(data)
            .map_err(|e| CryptoError::Other(format!("Failed to create data array: {e}")))?;

        // Call mac.doFinal(data)
        let result = env
            .call_method(&mac, "doFinal", "([B)[B", &[JValue::Object(&data_array)])
            .map_err(|e| CryptoError::Other(format!("Failed to compute HMAC: {e}")))?
            .l()
            .map_err(|e| CryptoError::Other(format!("Failed to get result object: {e}")))?;

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
    with_jni_env!(|env: &mut JNIEnv| {
        // Get Cipher class
        let cipher_class = env
            .find_class("javax/crypto/Cipher")
            .map_err(|e| CryptoError::Other(format!("Failed to find Cipher class: {e}")))?;

        // Get SecretKeySpec class
        let key_spec_class = env
            .find_class("javax/crypto/spec/SecretKeySpec")
            .map_err(|e| CryptoError::Other(format!("Failed to find SecretKeySpec class: {e}")))?;

        // Create transformation string
        let transformation = env
            .new_string("AES/ECB/NoPadding")
            .map_err(|e| CryptoError::Other(format!("Failed to create string: {e}")))?;

        // Call Cipher.getInstance("AES/ECB/NoPadding")
        let cipher = env
            .call_static_method(
                &cipher_class,
                "getInstance",
                "(Ljava/lang/String;)Ljavax/crypto/Cipher;",
                &[JValue::Object(&transformation)],
            )
            .map_err(|e| CryptoError::Other(format!("Failed to get Cipher instance: {e}")))?
            .l()
            .map_err(|e| CryptoError::Other(format!("Failed to get Cipher object: {e}")))?;

        // Create key byte array and algorithm string
        let key_array = env
            .byte_array_from_slice(key)
            .map_err(|e| CryptoError::Other(format!("Failed to create key array: {e}")))?;

        let aes_algorithm = env
            .new_string("AES")
            .map_err(|e| CryptoError::Other(format!("Failed to create AES string: {e}")))?;

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
        env.call_method(
            &cipher,
            "init",
            "(ILjava/security/Key;)V",
            &[JValue::Int(encrypt_mode), JValue::Object(&key_spec)],
        )
        .map_err(|e| CryptoError::Other(format!("Failed to init Cipher: {e}")))?;

        // Create input byte array
        let input_array = env
            .byte_array_from_slice(input)
            .map_err(|e| CryptoError::Other(format!("Failed to create input array: {e}")))?;

        // Call cipher.doFinal(input)
        let result = env
            .call_method(
                &cipher,
                "doFinal",
                "([B)[B",
                &[JValue::Object(&input_array)],
            )
            .map_err(|e| CryptoError::Other(format!("Failed to encrypt: {e}")))?
            .l()
            .map_err(|e| CryptoError::Other(format!("Failed to get result object: {e}")))?;

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
    with_jni_env!(|env: &mut JNIEnv| {
        // Get Cipher class
        let cipher_class = env
            .find_class("javax/crypto/Cipher")
            .map_err(|e| CryptoError::Other(format!("Failed to find Cipher class: {e}")))?;

        // Get SecretKeySpec class
        let key_spec_class = env
            .find_class("javax/crypto/spec/SecretKeySpec")
            .map_err(|e| CryptoError::Other(format!("Failed to find SecretKeySpec class: {e}")))?;

        // Get GCMParameterSpec class
        let gcm_spec_class = env
            .find_class("javax/crypto/spec/GCMParameterSpec")
            .map_err(|e| {
                CryptoError::Other(format!("Failed to find GCMParameterSpec class: {e}"))
            })?;

        // Create transformation string
        let transformation = env
            .new_string("AES/GCM/NoPadding")
            .map_err(|e| CryptoError::Other(format!("Failed to create string: {e}")))?;

        // Call Cipher.getInstance("AES/GCM/NoPadding")
        let cipher = env
            .call_static_method(
                &cipher_class,
                "getInstance",
                "(Ljava/lang/String;)Ljavax/crypto/Cipher;",
                &[JValue::Object(&transformation)],
            )
            .map_err(|e| CryptoError::Other(format!("Failed to get Cipher instance: {e}")))?
            .l()
            .map_err(|e| CryptoError::Other(format!("Failed to get Cipher object: {e}")))?;

        // Create key byte array and algorithm string
        let key_array = env
            .byte_array_from_slice(key)
            .map_err(|e| CryptoError::Other(format!("Failed to create key array: {e}")))?;

        let aes_algorithm = env
            .new_string("AES")
            .map_err(|e| CryptoError::Other(format!("Failed to create AES string: {e}")))?;

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
        env.call_method(
            &cipher,
            "init",
            "(ILjava/security/Key;Ljava/security/spec/AlgorithmParameterSpec;)V",
            &[
                JValue::Int(encrypt_mode),
                JValue::Object(&key_spec),
                JValue::Object(&gcm_spec),
            ],
        )
        .map_err(|e| CryptoError::Other(format!("Failed to init Cipher: {e}")))?;

        // Update AAD if present
        if !aad.is_empty() {
            let aad_array = env
                .byte_array_from_slice(aad)
                .map_err(|e| CryptoError::Other(format!("Failed to create AAD array: {e}")))?;

            env.call_method(&cipher, "updateAAD", "([B)V", &[JValue::Object(&aad_array)])
                .map_err(|e| CryptoError::Other(format!("Failed to update AAD: {e}")))?;
        }

        // Create input byte array
        let input_array = env
            .byte_array_from_slice(input)
            .map_err(|e| CryptoError::Other(format!("Failed to create input array: {e}")))?;

        // Call cipher.doFinal(input)
        let result = env
            .call_method(
                &cipher,
                "doFinal",
                "([B)[B",
                &[JValue::Object(&input_array)],
            )
            .map_err(|e| CryptoError::Other(format!("Failed to encrypt: {e}")))?
            .l()
            .map_err(|e| CryptoError::Other(format!("Failed to get result object: {e}")))?;

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
    with_jni_env!(|env: &mut JNIEnv| {
        // Get Cipher class
        let cipher_class = env
            .find_class("javax/crypto/Cipher")
            .map_err(|e| CryptoError::Other(format!("Failed to find Cipher class: {e}")))?;

        // Get SecretKeySpec class
        let key_spec_class = env
            .find_class("javax/crypto/spec/SecretKeySpec")
            .map_err(|e| CryptoError::Other(format!("Failed to find SecretKeySpec class: {e}")))?;

        // Get GCMParameterSpec class
        let gcm_spec_class = env
            .find_class("javax/crypto/spec/GCMParameterSpec")
            .map_err(|e| {
                CryptoError::Other(format!("Failed to find GCMParameterSpec class: {e}"))
            })?;

        // Create transformation string
        let transformation = env
            .new_string("AES/GCM/NoPadding")
            .map_err(|e| CryptoError::Other(format!("Failed to create string: {e}")))?;

        // Call Cipher.getInstance("AES/GCM/NoPadding")
        let cipher = env
            .call_static_method(
                &cipher_class,
                "getInstance",
                "(Ljava/lang/String;)Ljavax/crypto/Cipher;",
                &[JValue::Object(&transformation)],
            )
            .map_err(|e| CryptoError::Other(format!("Failed to get Cipher instance: {e}")))?
            .l()
            .map_err(|e| CryptoError::Other(format!("Failed to get Cipher object: {e}")))?;

        // Create key byte array and algorithm string
        let key_array = env
            .byte_array_from_slice(key)
            .map_err(|e| CryptoError::Other(format!("Failed to create key array: {e}")))?;

        let aes_algorithm = env
            .new_string("AES")
            .map_err(|e| CryptoError::Other(format!("Failed to create AES string: {e}")))?;

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
        env.call_method(
            &cipher,
            "init",
            "(ILjava/security/Key;Ljava/security/spec/AlgorithmParameterSpec;)V",
            &[
                JValue::Int(decrypt_mode),
                JValue::Object(&key_spec),
                JValue::Object(&gcm_spec),
            ],
        )
        .map_err(|e| CryptoError::Other(format!("Failed to init Cipher: {e}")))?;

        // Update AAD if present
        if !aad.is_empty() {
            let aad_array = env
                .byte_array_from_slice(aad)
                .map_err(|e| CryptoError::Other(format!("Failed to create AAD array: {e}")))?;

            env.call_method(&cipher, "updateAAD", "([B)V", &[JValue::Object(&aad_array)])
                .map_err(|e| CryptoError::Other(format!("Failed to update AAD: {e}")))?;
        }

        // Create input byte array
        let input_array = env
            .byte_array_from_slice(input)
            .map_err(|e| CryptoError::Other(format!("Failed to create input array: {e}")))?;

        // Call cipher.doFinal(input)
        let result = env
            .call_method(
                &cipher,
                "doFinal",
                "([B)[B",
                &[JValue::Object(&input_array)],
            )
            .map_err(|e| CryptoError::Other(format!("Failed to decrypt: {e}")))?
            .l()
            .map_err(|e| CryptoError::Other(format!("Failed to get result object: {e}")))?;

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
    with_jni_env!(|env: &mut JNIEnv| {
        // Get SecureRandom class
        let random_class = env
            .find_class("java/security/SecureRandom")
            .map_err(|e| CryptoError::Other(format!("Failed to find SecureRandom class: {e}")))?;

        // Create new SecureRandom instance
        let random = env
            .new_object(&random_class, "()V", &[])
            .map_err(|e| CryptoError::Other(format!("Failed to create SecureRandom: {e}")))?;

        // Create output byte array
        let output_array = env
            .new_byte_array(buf.len() as i32)
            .map_err(|e| CryptoError::Other(format!("Failed to create byte array: {e}")))?;

        // Call random.nextBytes(output)
        env.call_method(
            &random,
            "nextBytes",
            "([B)V",
            &[JValue::Object(&output_array)],
        )
        .map_err(|e| CryptoError::Other(format!("Failed to generate random bytes: {e}")))?;

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
    with_jni_env!(|env: &mut JNIEnv| {
        // Get MessageDigest class
        let digest_class = env
            .find_class("java/security/MessageDigest")
            .map_err(|e| CryptoError::Other(format!("Failed to find MessageDigest class: {e}")))?;

        // Get getInstance method
        let algorithm = env
            .new_string("SHA-384")
            .map_err(|e| CryptoError::Other(format!("Failed to create string: {e}")))?;

        // Call MessageDigest.getInstance("SHA-384")
        let digest = env
            .call_static_method(
                &digest_class,
                "getInstance",
                "(Ljava/lang/String;)Ljava/security/MessageDigest;",
                &[JValue::Object(&algorithm)],
            )
            .map_err(|e| CryptoError::Other(format!("Failed to get SHA-384 instance: {e}")))?
            .l()
            .map_err(|e| CryptoError::Other(format!("Failed to get digest object: {e}")))?;

        // Create byte array from input data
        let input_array = env
            .byte_array_from_slice(data)
            .map_err(|e| CryptoError::Other(format!("Failed to create byte array: {e}")))?;

        // Call digest.digest(input)
        let result = env
            .call_method(&digest, "digest", "([B)[B", &[JValue::Object(&input_array)])
            .map_err(|e| CryptoError::Other(format!("Failed to compute digest: {e}")))?
            .l()
            .map_err(|e| CryptoError::Other(format!("Failed to get result object: {e}")))?;

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
    with_jni_env!(|env: &mut JNIEnv| {
        // Get KeyPairGenerator class
        let kpg_class = env
            .find_class("java/security/KeyPairGenerator")
            .map_err(|e| {
                CryptoError::Other(format!("Failed to find KeyPairGenerator class: {e}"))
            })?;

        // Get ECGenParameterSpec class
        let ec_spec_class = env
            .find_class("java/security/spec/ECGenParameterSpec")
            .map_err(|e| {
                CryptoError::Other(format!("Failed to find ECGenParameterSpec class: {e}"))
            })?;

        // Create algorithm string
        let algorithm = env
            .new_string("EC")
            .map_err(|e| CryptoError::Other(format!("Failed to create string: {e}")))?;

        // Call KeyPairGenerator.getInstance("EC")
        let kpg = env
            .call_static_method(
                &kpg_class,
                "getInstance",
                "(Ljava/lang/String;)Ljava/security/KeyPairGenerator;",
                &[JValue::Object(&algorithm)],
            )
            .map_err(|e| {
                CryptoError::Other(format!("Failed to get KeyPairGenerator instance: {e}"))
            })?
            .l()
            .map_err(|e| {
                CryptoError::Other(format!("Failed to get KeyPairGenerator object: {e}"))
            })?;

        // Create curve name string
        let curve_name = env
            .new_string("secp256r1")
            .map_err(|e| CryptoError::Other(format!("Failed to create curve name string: {e}")))?;

        // Create ECGenParameterSpec
        let ec_spec = env
            .new_object(
                &ec_spec_class,
                "(Ljava/lang/String;)V",
                &[JValue::Object(&curve_name)],
            )
            .map_err(|e| CryptoError::Other(format!("Failed to create ECGenParameterSpec: {e}")))?;

        // Initialize with the spec
        env.call_method(
            &kpg,
            "initialize",
            "(Ljava/security/spec/AlgorithmParameterSpec;)V",
            &[JValue::Object(&ec_spec)],
        )
        .map_err(|e| CryptoError::Other(format!("Failed to initialize KeyPairGenerator: {e}")))?;

        // Generate key pair
        let key_pair = env
            .call_method(&kpg, "generateKeyPair", "()Ljava/security/KeyPair;", &[])
            .map_err(|e| CryptoError::Other(format!("Failed to generate key pair: {e}")))?
            .l()
            .map_err(|e| CryptoError::Other(format!("Failed to get KeyPair object: {e}")))?;

        // Get private key
        let private_key = env
            .call_method(&key_pair, "getPrivate", "()Ljava/security/PrivateKey;", &[])
            .map_err(|e| CryptoError::Other(format!("Failed to get private key: {e}")))?
            .l()
            .map_err(|e| CryptoError::Other(format!("Failed to get private key object: {e}")))?;

        // Get public key
        let public_key = env
            .call_method(&key_pair, "getPublic", "()Ljava/security/PublicKey;", &[])
            .map_err(|e| CryptoError::Other(format!("Failed to get public key: {e}")))?
            .l()
            .map_err(|e| CryptoError::Other(format!("Failed to get public key object: {e}")))?;

        // Get encoded private key (PKCS#8 format)
        let private_key_encoded = env
            .call_method(&private_key, "getEncoded", "()[B", &[])
            .map_err(|e| CryptoError::Other(format!("Failed to get encoded private key: {e}")))?
            .l()
            .map_err(|e| {
                CryptoError::Other(format!("Failed to get encoded private key bytes: {e}"))
            })?;

        let private_key_array: JByteArray = private_key_encoded.into();
        let private_key_len = env
            .get_array_length(&private_key_array)
            .map_err(|e| CryptoError::Other(format!("Failed to get private key length: {e}")))?
            as usize;

        let mut private_key_der = vec![0i8; private_key_len];
        env.get_byte_array_region(&private_key_array, 0, &mut private_key_der)
            .map_err(|e| CryptoError::Other(format!("Failed to copy private key: {e}")))?;

        // Get encoded public key (X.509 SubjectPublicKeyInfo format)
        let public_key_encoded = env
            .call_method(&public_key, "getEncoded", "()[B", &[])
            .map_err(|e| CryptoError::Other(format!("Failed to get encoded public key: {e}")))?
            .l()
            .map_err(|e| {
                CryptoError::Other(format!("Failed to get encoded public key bytes: {e}"))
            })?;

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
    with_jni_env!(|env: &mut JNIEnv| {
        // Get KeyFactory class
        let key_factory_class = env
            .find_class("java/security/KeyFactory")
            .map_err(|e| CryptoError::Other(format!("Failed to find KeyFactory class: {e}")))?;

        // Get PKCS8EncodedKeySpec class
        let key_spec_class = env
            .find_class("java/security/spec/PKCS8EncodedKeySpec")
            .map_err(|e| {
                CryptoError::Other(format!("Failed to find PKCS8EncodedKeySpec class: {e}"))
            })?;

        // Get Signature class
        let signature_class = env
            .find_class("java/security/Signature")
            .map_err(|e| CryptoError::Other(format!("Failed to find Signature class: {e}")))?;

        // Create algorithm strings
        let ec_algorithm = env
            .new_string("EC")
            .map_err(|e| CryptoError::Other(format!("Failed to create EC string: {e}")))?;

        let sig_algorithm = env.new_string("SHA256withECDSA").map_err(|e| {
            CryptoError::Other(format!("Failed to create signature algorithm string: {e}"))
        })?;

        // Get KeyFactory for EC
        let key_factory = env
            .call_static_method(
                &key_factory_class,
                "getInstance",
                "(Ljava/lang/String;)Ljava/security/KeyFactory;",
                &[JValue::Object(&ec_algorithm)],
            )
            .map_err(|e| CryptoError::Other(format!("Failed to get KeyFactory: {e}")))?
            .l()
            .map_err(|e| CryptoError::Other(format!("Failed to get KeyFactory object: {e}")))?;

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
        let private_key = env
            .call_method(
                &key_factory,
                "generatePrivate",
                "(Ljava/security/spec/KeySpec;)Ljava/security/PrivateKey;",
                &[JValue::Object(&key_spec)],
            )
            .map_err(|e| CryptoError::Other(format!("Failed to generate private key: {e}")))?
            .l()
            .map_err(|e| CryptoError::Other(format!("Failed to get private key object: {e}")))?;

        // Get Signature instance
        let signature = env
            .call_static_method(
                &signature_class,
                "getInstance",
                "(Ljava/lang/String;)Ljava/security/Signature;",
                &[JValue::Object(&sig_algorithm)],
            )
            .map_err(|e| CryptoError::Other(format!("Failed to get Signature instance: {e}")))?
            .l()
            .map_err(|e| CryptoError::Other(format!("Failed to get Signature object: {e}")))?;

        // Initialize for signing
        env.call_method(
            &signature,
            "initSign",
            "(Ljava/security/PrivateKey;)V",
            &[JValue::Object(&private_key)],
        )
        .map_err(|e| CryptoError::Other(format!("Failed to init signature: {e}")))?;

        // Update with data
        let data_array = env
            .byte_array_from_slice(data)
            .map_err(|e| CryptoError::Other(format!("Failed to create data array: {e}")))?;

        env.call_method(
            &signature,
            "update",
            "([B)V",
            &[JValue::Object(&data_array)],
        )
        .map_err(|e| CryptoError::Other(format!("Failed to update signature: {e}")))?;

        // Sign
        let sig_bytes = env
            .call_method(&signature, "sign", "()[B", &[])
            .map_err(|e| CryptoError::Other(format!("Failed to sign: {e}")))?
            .l()
            .map_err(|e| CryptoError::Other(format!("Failed to get signature bytes: {e}")))?;

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
    with_jni_env!(|env: &mut JNIEnv| {
        // Get required classes
        let key_factory_class = env
            .find_class("java/security/KeyFactory")
            .map_err(|e| CryptoError::Other(format!("Failed to find KeyFactory class: {e}")))?;

        let pkcs8_spec_class = env
            .find_class("java/security/spec/PKCS8EncodedKeySpec")
            .map_err(|e| {
                CryptoError::Other(format!("Failed to find PKCS8EncodedKeySpec class: {e}"))
            })?;

        let x509_spec_class = env
            .find_class("java/security/spec/X509EncodedKeySpec")
            .map_err(|e| {
                CryptoError::Other(format!("Failed to find X509EncodedKeySpec class: {e}"))
            })?;

        let key_agreement_class = env
            .find_class("javax/crypto/KeyAgreement")
            .map_err(|e| CryptoError::Other(format!("Failed to find KeyAgreement class: {e}")))?;

        // Create algorithm strings
        let ec_algorithm = env
            .new_string("EC")
            .map_err(|e| CryptoError::Other(format!("Failed to create EC string: {e}")))?;

        let ecdh_algorithm = env
            .new_string("ECDH")
            .map_err(|e| CryptoError::Other(format!("Failed to create ECDH string: {e}")))?;

        // Get KeyFactory for EC
        let key_factory = env
            .call_static_method(
                &key_factory_class,
                "getInstance",
                "(Ljava/lang/String;)Ljava/security/KeyFactory;",
                &[JValue::Object(&ec_algorithm)],
            )
            .map_err(|e| CryptoError::Other(format!("Failed to get KeyFactory: {e}")))?
            .l()
            .map_err(|e| CryptoError::Other(format!("Failed to get KeyFactory object: {e}")))?;

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

        let private_key = env
            .call_method(
                &key_factory,
                "generatePrivate",
                "(Ljava/security/spec/KeySpec;)Ljava/security/PrivateKey;",
                &[JValue::Object(&private_key_spec)],
            )
            .map_err(|e| CryptoError::Other(format!("Failed to generate private key: {e}")))?
            .l()
            .map_err(|e| CryptoError::Other(format!("Failed to get private key object: {e}")))?;

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

        let public_key = env
            .call_method(
                &key_factory,
                "generatePublic",
                "(Ljava/security/spec/KeySpec;)Ljava/security/PublicKey;",
                &[JValue::Object(&public_key_spec)],
            )
            .map_err(|e| CryptoError::Other(format!("Failed to generate public key: {e}")))?
            .l()
            .map_err(|e| CryptoError::Other(format!("Failed to get public key object: {e}")))?;

        // Get KeyAgreement instance
        let key_agreement = env
            .call_static_method(
                &key_agreement_class,
                "getInstance",
                "(Ljava/lang/String;)Ljavax/crypto/KeyAgreement;",
                &[JValue::Object(&ecdh_algorithm)],
            )
            .map_err(|e| CryptoError::Other(format!("Failed to get KeyAgreement: {e}")))?
            .l()
            .map_err(|e| CryptoError::Other(format!("Failed to get KeyAgreement object: {e}")))?;

        // Initialize with private key
        env.call_method(
            &key_agreement,
            "init",
            "(Ljava/security/Key;)V",
            &[JValue::Object(&private_key)],
        )
        .map_err(|e| CryptoError::Other(format!("Failed to init KeyAgreement: {e}")))?;

        // Do phase with public key
        env.call_method(
            &key_agreement,
            "doPhase",
            "(Ljava/security/Key;Z)Ljava/security/Key;",
            &[JValue::Object(&public_key), JValue::Bool(1)],
        )
        .map_err(|e| CryptoError::Other(format!("Failed to do ECDH phase: {e}")))?;

        // Generate shared secret
        let shared_secret = env
            .call_method(&key_agreement, "generateSecret", "()[B", &[])
            .map_err(|e| CryptoError::Other(format!("Failed to generate shared secret: {e}")))?
            .l()
            .map_err(|e| CryptoError::Other(format!("Failed to get shared secret: {e}")))?;

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
