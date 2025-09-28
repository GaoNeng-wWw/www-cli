
use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Key, Nonce,
};
use pbkdf2::pbkdf2_hmac;
use sha2::Sha256;
use std::fs::File;
use std::io::{Read, Write};

use crate::utils::log::{err, success};

const SALT_SIZE: usize = 16;
const NONCE_SIZE: usize = 12;
const KEY_SIZE: usize = 32;
const PBKDF2_ITERATIONS: u32 = 100_000;

pub struct FileEncryptor {
    password: String,
}

impl FileEncryptor {
    pub fn new(password: String) -> Self {
        Self { password }
    }

    // 从密码生成密钥
    fn derive_key(&self, salt: &[u8]) -> [u8; KEY_SIZE] {
        let mut key = [0u8; KEY_SIZE];
        pbkdf2_hmac::<Sha256>(
            self.password.as_bytes(),
            salt,
            PBKDF2_ITERATIONS,
            &mut key,
        );
        key
    }

    // 加密文件
    pub fn encrypt_file(&self, input_path: &str, output_path: &str) -> Result<(), Box<dyn std::error::Error>> {
        // 读取原文件
        let mut file = File::open(input_path)?;
        let mut plaintext = Vec::new();
        file.read_to_end(&mut plaintext)?;

        // 生成随机盐和nonce
        let salt = generate_random_bytes(SALT_SIZE);
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

        // 从密码派生密钥
        let key_bytes = self.derive_key(&salt);
        let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
        
        // 创建加密器
        let cipher = Aes256Gcm::new(key);
        
        // 加密数据
        let ciphertext = cipher.encrypt(&nonce, plaintext.as_ref())
            .map_err(|e| format!("加密失败: {}", e))?;

        // 写入加密文件：盐 + nonce + 密文
        let mut output_file = File::create(output_path)?;
        output_file.write_all(&salt)?;
        output_file.write_all(&nonce)?;
        output_file.write_all(&ciphertext)?;

        success(&format!("文件加密成功: {} -> {}", input_path, output_path));
        Ok(())
    }

    // 解密文件
    pub fn decrypt_file(&self, input_path: &str, output_path: &str) -> Result<(), Box<dyn std::error::Error>> {
        // 读取加密文件
        let mut file = File::open(input_path)?;
        let mut encrypted_data = Vec::new();
        file.read_to_end(&mut encrypted_data)?;

        // 检查文件大小
        if encrypted_data.len() < SALT_SIZE + NONCE_SIZE {
            return Err("加密文件格式错误".into());
        }

        // 提取盐、nonce和密文
        let salt = &encrypted_data[..SALT_SIZE];
        let nonce_bytes = &encrypted_data[SALT_SIZE..SALT_SIZE + NONCE_SIZE];
        let ciphertext = &encrypted_data[SALT_SIZE + NONCE_SIZE..];

        // 从密码派生密钥
        let key_bytes = self.derive_key(salt);
        let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
        
        // 创建解密器
        let cipher = Aes256Gcm::new(key);
        let nonce = Nonce::from_slice(nonce_bytes);
        
        // 解密数据
        let plaintext = cipher.decrypt(nonce, ciphertext);
        if let Err(error) = plaintext {
          err(&format!("{0}", error.to_string()));
          return Err(error.to_string().into());
        }
        let plaintext = plaintext.unwrap();

        // 写入解密文件
        let mut output_file = File::create(output_path)?;
        output_file.write_all(&plaintext)?;
        
        success(&format!("文件解密成功: {} -> {}", input_path, output_path));
        Ok(())
    }
}

// 生成随机字节
fn generate_random_bytes(size: usize) -> Vec<u8> {
    use rand::RngCore;
    let mut bytes = vec![0u8; size];
    rand::thread_rng().fill_bytes(&mut bytes);
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn test_encrypt_decrypt_success() {
        let dir = tempdir().unwrap();
        let original_file = dir.path().join("test.txt");
        let encrypted_file = dir.path().join("test.txt.enc");
        let decrypted_file = dir.path().join("test_decrypted.txt");

        // 创建测试文件
        let test_data = "这是一个测试文件，用于验证加密解密功能。";
        fs::write(&original_file, test_data).unwrap();

        let password = "test_password_123".to_string();
        let encryptor = FileEncryptor::new(password);

        // 测试加密
        encryptor.encrypt_file(
            original_file.to_str().unwrap(),
            encrypted_file.to_str().unwrap()
        ).unwrap();

        // 验证加密文件存在且不同于原文件
        assert!(encrypted_file.exists());
        let encrypted_data = fs::read(&encrypted_file).unwrap();
        assert_ne!(encrypted_data, test_data.as_bytes());

        // 测试解密
        encryptor.decrypt_file(
            encrypted_file.to_str().unwrap(),
            decrypted_file.to_str().unwrap()
        ).unwrap();

        // 验证解密结果
        let decrypted_data = fs::read_to_string(&decrypted_file).unwrap();
        assert_eq!(decrypted_data, test_data);
    }

    #[test]
    fn test_decrypt_with_wrong_password() {
        let dir = tempdir().unwrap();
        let original_file = dir.path().join("test.txt");
        let encrypted_file = dir.path().join("test.txt.enc");
        let decrypted_file = dir.path().join("test_decrypted.txt");

        // 创建测试文件
        fs::write(&original_file, "测试数据").unwrap();

        // 用一个密码加密
        let encrypt_password = "correct_password".to_string();
        let encryptor = FileEncryptor::new(encrypt_password);
        encryptor.encrypt_file(
            original_file.to_str().unwrap(),
            encrypted_file.to_str().unwrap()
        ).unwrap();

        // 用错误密码尝试解密
        let wrong_password = "wrong_password".to_string();
        let decryptor = FileEncryptor::new(wrong_password);
        let result = decryptor.decrypt_file(
            encrypted_file.to_str().unwrap(),
            decrypted_file.to_str().unwrap()
        );

        // 应该解密失败
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("解密失败"));
    }
}
