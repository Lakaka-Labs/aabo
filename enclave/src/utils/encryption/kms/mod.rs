use crate::utils::encryption::EncryptionError;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use mockall::automock;
use serde::{Deserialize, Serialize};

mod ffi;

#[derive(Debug, Serialize, Deserialize)]
pub struct AWSDecryptConfig {
    #[serde(rename = "awsRegion")]
    pub aws_region: String,
    #[serde(rename = "awsKeyID")]
    pub aws_key_id: String,
    #[serde(rename = "awsSecretKey")]
    pub aws_secret_key: String,
    #[serde(rename = "awsSessionToken")]
    pub aws_session_token: String,
}

#[automock]
pub trait Decrypt {
    fn decrypt(&self, ciphertext_string: &str) -> Result<Vec<u8>, EncryptionError>;
}

impl Decrypt for AWSDecryptConfig {
    fn decrypt(&self, ciphertext_string: &str) -> Result<Vec<u8>, EncryptionError> {
        let ciphertext: &[u8] = &BASE64.decode(ciphertext_string).map_err(|_| {
            EncryptionError::InvalidEncryptedData("Invalid Base64 encoding".to_string())
        })?;

        // Initialize the SDK
        unsafe {
            ffi::aws_nitro_enclaves_library_init(std::ptr::null_mut());
        };

        // Fetch allocator
        let allocator = unsafe { ffi::aws_nitro_enclaves_get_allocator() };
        if allocator.is_null() {
            unsafe {
                ffi::aws_nitro_enclaves_library_clean_up();
            }
            return Err(EncryptionError::SdkInitError);
        }
        // REGION
        let region = unsafe {
            let reg = ffi::aws_string_new_from_array(
                allocator,
                self.aws_region.as_bytes().as_ptr(),
                self.aws_region.as_bytes().len(),
            );
            if reg.is_null() {
                ffi::aws_nitro_enclaves_library_clean_up();
                return Err(EncryptionError::SdkGenericError);
            }
            reg
        };
        // ENDPOINT
        let mut endpoint = {
            let mut ep = ffi::aws_socket_endpoint {
                address: [0; ffi::AWS_ADDRESS_MAX_LEN],
                port: ffi::AWS_NE_VSOCK_PROXY_PORT,
            };
            ep.address[..ffi::AWS_NE_VSOCK_PROXY_ADDR.len()]
                .copy_from_slice(&ffi::AWS_NE_VSOCK_PROXY_ADDR);
            ep
        };
        // AWS_ACCESS_KEY_ID
        let key_id = unsafe {
            let kid = ffi::aws_string_new_from_array(
                allocator,
                self.aws_key_id.as_bytes().as_ptr(),
                self.aws_key_id.as_bytes().len(),
            );
            if kid.is_null() {
                ffi::aws_string_destroy_secure(region);
                ffi::aws_nitro_enclaves_library_clean_up();
                return Err(EncryptionError::SdkGenericError);
            }
            kid
        };
        // AWS_SECRET_ACCESS_KEY
        let secret_key = unsafe {
            let skey = ffi::aws_string_new_from_array(
                allocator,
                self.aws_secret_key.as_bytes().as_ptr(),
                self.aws_secret_key.as_bytes().len(),
            );
            if skey.is_null() {
                ffi::aws_string_destroy_secure(key_id);
                ffi::aws_string_destroy_secure(region);
                ffi::aws_nitro_enclaves_library_clean_up();
                return Err(EncryptionError::SdkGenericError);
            }
            skey
        };
        // AWS_SESSION_TOKEN
        let session_token = unsafe {
            let sess_token = ffi::aws_string_new_from_array(
                allocator,
                self.aws_session_token.as_bytes().as_ptr(),
                self.aws_session_token.as_bytes().len(),
            );
            if sess_token.is_null() {
                ffi::aws_string_destroy_secure(secret_key);
                ffi::aws_string_destroy_secure(key_id);
                ffi::aws_string_destroy_secure(region);
                ffi::aws_nitro_enclaves_library_clean_up();
                return Err(EncryptionError::SdkGenericError);
            }
            sess_token
        };
        // Construct KMS client configuration
        let kms_client_cfg = unsafe {
            // Configure
            let cfg = ffi::aws_nitro_enclaves_kms_client_config_default(
                region,
                &mut endpoint,
                ffi::AWS_SOCKET_VSOCK_DOMAIN,
                key_id,
                secret_key,
                session_token,
            );

            if cfg.is_null() {
                ffi::aws_string_destroy_secure(key_id);
                ffi::aws_string_destroy_secure(secret_key);
                ffi::aws_string_destroy_secure(session_token);
                ffi::aws_string_destroy_secure(region);
                ffi::aws_nitro_enclaves_library_clean_up();
                return Err(EncryptionError::SdkKmsConfigError);
            }
            cfg
        };
        // Construct KMS Client
        let kms_client = unsafe { ffi::aws_nitro_enclaves_kms_client_new(kms_client_cfg) };
        if kms_client.is_null() {
            unsafe {
                ffi::aws_string_destroy_secure(key_id);
                ffi::aws_string_destroy_secure(secret_key);
                ffi::aws_string_destroy_secure(session_token);
                ffi::aws_string_destroy_secure(region);
                ffi::aws_nitro_enclaves_kms_client_config_destroy(kms_client_cfg);
                ffi::aws_nitro_enclaves_library_clean_up();
            }
            return Err(EncryptionError::SdkKmsClientError);
        }
        // Ciphertext
        let ciphertext_buf = unsafe {
            ffi::aws_byte_buf_from_array(ciphertext.as_ptr() as *mut ffi::c_void, ciphertext.len())
        };

        // Decrypt
        let mut plaintext_buf: ffi::aws_byte_buf = unsafe { std::mem::zeroed() };
        let rc = unsafe {
            ffi::aws_kms_decrypt_blocking(kms_client, &ciphertext_buf, &mut plaintext_buf)
        };
        if rc != 0 {
            unsafe {
                ffi::aws_string_destroy_secure(key_id);
                ffi::aws_string_destroy_secure(secret_key);
                ffi::aws_string_destroy_secure(session_token);
                ffi::aws_string_destroy_secure(region);
                ffi::aws_nitro_enclaves_kms_client_config_destroy(kms_client_cfg);
                ffi::aws_nitro_enclaves_kms_client_destroy(kms_client);
                ffi::aws_nitro_enclaves_library_clean_up();
            }
            return Err(EncryptionError::SdkKmsDecryptError);
        }

        // Cleanup
        unsafe {
            ffi::aws_string_destroy_secure(key_id);
            ffi::aws_string_destroy_secure(secret_key);
            ffi::aws_string_destroy_secure(session_token);
            ffi::aws_string_destroy_secure(region);
            ffi::aws_nitro_enclaves_kms_client_config_destroy(kms_client_cfg);
            ffi::aws_nitro_enclaves_kms_client_destroy(kms_client);
            ffi::aws_nitro_enclaves_library_clean_up();
        }

        // Plaintext
        let plaintext = unsafe {
            std::slice::from_raw_parts(plaintext_buf.buffer, plaintext_buf.len as usize).to_vec()
        };
        unsafe { ffi::aws_byte_buf_clean_up_secure(&mut plaintext_buf) };

        Ok(plaintext)
    }
}

pub fn seed_entropy(bytes_to_seed: usize) -> Result<(), ()> {
    let rc = unsafe { ffi::aws_nitro_enclaves_library_seed_entropy(bytes_to_seed) };
    if rc == 0 { Ok(()) } else { Err(()) }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AWSEncryptConfig {
    #[serde(rename = "awsRegion")]
    pub aws_region: String,
    #[serde(rename = "awsKeyId")]
    pub aws_key_id: String,
    #[serde(rename = "awsSecretKey")]
    pub aws_secret_key: String,
    #[serde(rename = "awsSessionToken")]
    pub aws_session_token: String,
    #[serde(rename = "awsKmsKeyId")]
    pub aws_kms_key_id: String,
}

#[automock]
pub trait Encrypt {
    fn encrypt(&self, data: Vec<u8>) -> Result<String, EncryptionError>;
}

impl Encrypt for AWSEncryptConfig {
    fn encrypt(&self, plaintext: Vec<u8>) -> Result<String, EncryptionError> {
        // Initialize the SDK
        unsafe {
            ffi::aws_nitro_enclaves_library_init(std::ptr::null_mut());
        };

        // Fetch allocator
        let allocator = unsafe { ffi::aws_nitro_enclaves_get_allocator() };
        if allocator.is_null() {
            unsafe {
                ffi::aws_nitro_enclaves_library_clean_up();
            }
            return Err(EncryptionError::SdkInitError);
        }
        // REGION
        let region = unsafe {
            let reg = ffi::aws_string_new_from_array(
                allocator,
                self.aws_region.as_bytes().as_ptr(),
                self.aws_region.as_bytes().len(),
            );
            if reg.is_null() {
                ffi::aws_nitro_enclaves_library_clean_up();
                return Err(EncryptionError::SdkGenericError);
            }
            reg
        };
        // ENDPOINT
        let mut endpoint = {
            let mut ep = ffi::aws_socket_endpoint {
                address: [0; ffi::AWS_ADDRESS_MAX_LEN],
                port: ffi::AWS_NE_VSOCK_PROXY_PORT,
            };
            ep.address[..ffi::AWS_NE_VSOCK_PROXY_ADDR.len()]
                .copy_from_slice(&ffi::AWS_NE_VSOCK_PROXY_ADDR);
            ep
        };
        // AWS_ACCESS_KEY_ID
        let key_id = unsafe {
            let kid = ffi::aws_string_new_from_array(
                allocator,
                self.aws_key_id.as_bytes().as_ptr(),
                self.aws_key_id.as_bytes().len(),
            );
            if kid.is_null() {
                ffi::aws_string_destroy_secure(region);
                ffi::aws_nitro_enclaves_library_clean_up();
                return Err(EncryptionError::SdkGenericError);
            }
            kid
        };
        // AWS_SECRET_ACCESS_KEY
        let secret_key = unsafe {
            let skey = ffi::aws_string_new_from_array(
                allocator,
                self.aws_secret_key.as_bytes().as_ptr(),
                self.aws_secret_key.as_bytes().len(),
            );
            if skey.is_null() {
                ffi::aws_string_destroy_secure(key_id);
                ffi::aws_string_destroy_secure(region);
                ffi::aws_nitro_enclaves_library_clean_up();
                return Err(EncryptionError::SdkGenericError);
            }
            skey
        };
        // AWS_SESSION_TOKEN
        let session_token = unsafe {
            let sess_token = ffi::aws_string_new_from_array(
                allocator,
                self.aws_session_token.as_bytes().as_ptr(),
                self.aws_session_token.as_bytes().len(),
            );
            if sess_token.is_null() {
                ffi::aws_string_destroy_secure(secret_key);
                ffi::aws_string_destroy_secure(key_id);
                ffi::aws_string_destroy_secure(region);
                ffi::aws_nitro_enclaves_library_clean_up();
                return Err(EncryptionError::SdkGenericError);
            }
            sess_token
        };
        // AWS KMS Key ID
        let kms_key_id = unsafe {
            let kms_kid = ffi::aws_string_new_from_array(
                allocator,
                self.aws_kms_key_id.as_bytes().as_ptr(),
                self.aws_kms_key_id.as_bytes().len(),
            );
            if kms_kid.is_null() {
                ffi::aws_string_destroy_secure(secret_key);
                ffi::aws_string_destroy_secure(key_id);
                ffi::aws_string_destroy_secure(region);
                ffi::aws_string_destroy_secure(session_token);
                ffi::aws_nitro_enclaves_library_clean_up();
                return Err(EncryptionError::SdkGenericError);
            }
            kms_kid
        };

        // Construct KMS client configuration
        let kms_client_cfg = unsafe {
            // Configure
            let cfg = ffi::aws_nitro_enclaves_kms_client_config_default(
                region,
                &mut endpoint,
                ffi::AWS_SOCKET_VSOCK_DOMAIN,
                key_id,
                secret_key,
                session_token,
            );

            if cfg.is_null() {
                ffi::aws_string_destroy_secure(key_id);
                ffi::aws_string_destroy_secure(secret_key);
                ffi::aws_string_destroy_secure(session_token);
                ffi::aws_string_destroy_secure(region);
                ffi::aws_string_destroy_secure(kms_key_id);
                ffi::aws_nitro_enclaves_library_clean_up();
                return Err(EncryptionError::SdkKmsConfigError);
            }
            cfg
        };
        // Construct KMS Client
        let kms_client = unsafe { ffi::aws_nitro_enclaves_kms_client_new(kms_client_cfg) };
        if kms_client.is_null() {
            unsafe {
                ffi::aws_string_destroy_secure(key_id);
                ffi::aws_string_destroy_secure(secret_key);
                ffi::aws_string_destroy_secure(session_token);
                ffi::aws_string_destroy_secure(region);
                ffi::aws_string_destroy_secure(kms_key_id);
                ffi::aws_nitro_enclaves_kms_client_config_destroy(kms_client_cfg);
                ffi::aws_nitro_enclaves_library_clean_up();
            }
            return Err(EncryptionError::SdkKmsClientError);
        }
        // Plaintext
        let plaintext_buf = unsafe {
            ffi::aws_byte_buf_from_array(plaintext.as_ptr() as *mut ffi::c_void, plaintext.len())
        };

        // Encrypt
        let mut ciphertext_buf: ffi::aws_byte_buf = unsafe { std::mem::zeroed() };
        let rc = unsafe {
            ffi::aws_kms_encrypt_blocking(
                kms_client,
                kms_key_id,
                &plaintext_buf,
                &mut ciphertext_buf,
            )
        };
        if rc != 0 {
            unsafe {
                ffi::aws_string_destroy_secure(key_id);
                ffi::aws_string_destroy_secure(secret_key);
                ffi::aws_string_destroy_secure(session_token);
                ffi::aws_string_destroy_secure(region);
                ffi::aws_string_destroy_secure(kms_key_id);
                ffi::aws_nitro_enclaves_kms_client_config_destroy(kms_client_cfg);
                ffi::aws_nitro_enclaves_kms_client_destroy(kms_client);
                ffi::aws_nitro_enclaves_library_clean_up();
            }
            return Err(EncryptionError::SdkKmsEncryptError);
        }

        // Cleanup
        unsafe {
            ffi::aws_string_destroy_secure(key_id);
            ffi::aws_string_destroy_secure(secret_key);
            ffi::aws_string_destroy_secure(session_token);
            ffi::aws_string_destroy_secure(region);
            ffi::aws_string_destroy_secure(kms_key_id);
            ffi::aws_nitro_enclaves_kms_client_config_destroy(kms_client_cfg);
            ffi::aws_nitro_enclaves_kms_client_destroy(kms_client);
            ffi::aws_nitro_enclaves_library_clean_up();
        }

        // Ciphertext
        let ciphertext = unsafe {
            std::slice::from_raw_parts(ciphertext_buf.buffer, ciphertext_buf.len as usize).to_vec()
        };
        unsafe { ffi::aws_byte_buf_clean_up_secure(&mut ciphertext_buf) };

        Ok(BASE64.encode(ciphertext))
    }
}
