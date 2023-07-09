use crate::msgs::{message::{Message, MessagePayload}, handshake::{HandshakePayload, Random}};
#[cfg(feature = "logging")]
use crate::log::{debug, trace};
use ring::digest::{digest, SHA512, SHA256};

// use aes_gcm to support 512bits long nonce (not supported by ring)
use aes_gcm::{
    AesGcm, aes::Aes256,
    KeyInit,
    aead::consts::U64, AeadInPlace // Or `Aes128Gcm`
};


#[derive(Clone)]
/// JLS Configuration
pub struct JlsConfig {
    /// user password of a JLS peer
    pub user_pwd: String,
    /// user iv for a JLS peer
    pub user_iv: String,
}

impl Default for JlsConfig {
    fn default()->JlsConfig{
        JlsConfig { 
            user_pwd: "3070111071563328618171495819203123318".into(),
            user_iv: "3070111071563328618171495819203123318".into(),
        }
    }  
}

impl JlsConfig {
    /// Create a new JlsConfig
    pub fn new(user_pwd: &str, user_iv: &str) -> JlsConfig{
        JlsConfig{
            user_pwd: String::from(user_pwd),
            user_iv: String::from(user_iv),
        }
    }

    /// Build a fake random from a true random with given keyshare
    pub fn build_fake_random(&self, random: &[u8;16], keyshare: &[u8]) -> [u8;32] {
        let mut iv = self.user_iv.as_bytes().to_vec();
        iv.extend_from_slice(keyshare);
        let pwd = self.user_pwd.as_bytes().to_vec();

        let iv = digest(&SHA512, iv.as_ref());
        let pwd = digest(&SHA256, pwd.as_ref());
        trace!("ch iv: {:?}", iv.as_ref());
        trace!("pwd: {:?}", pwd.as_ref());

        let cipher = AesGcm::<Aes256, U64>::new(pwd.as_ref().into());
    
        let mut buffer = Vec::<u8>::from(random.as_slice());
        cipher.encrypt_in_place(iv.as_ref().into(), b"", & mut buffer).unwrap();

        buffer.try_into().unwrap()
    }
    
    /// Check if it's a valid fake random 
    pub fn check_fake_random(&self,fake_random: &[u8;32], keyshare: &[u8]) -> bool {
        let mut iv = self.user_iv.as_bytes().to_vec();
        iv.extend_from_slice(keyshare);
        let pwd = self.user_pwd.as_bytes().to_vec();

        let iv = digest(&SHA512, iv.as_ref());
        let pwd = digest(&SHA256, pwd.as_ref());
        trace!("ch iv: {:?}", iv.as_ref());
        trace!("pwd: {:?}", pwd.as_ref());

        let cipher = AesGcm::<Aes256, U64>::new(pwd.as_ref().into());

        let mut buffer = Vec::from(fake_random.as_ref());

        let is_valid = cipher.decrypt_in_place(iv.as_ref().into(), b"", & mut buffer).is_ok();
        is_valid
    }
}
