//! Server passwords and keys at rest. On Windows they are sealed with DPAPI
//! for the current Windows user, so the file is useless on another account or
//! computer. Elsewhere a random key in a file only the user can read seals them.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;

const ENTROPY: &[u8] = b"ReTunl server access v1";

pub fn seal(plain: &[u8]) -> Result<String, String> {
    imp::protect(plain).map(|b| B64.encode(b))
}

pub fn open(sealed: &str) -> Result<Vec<u8>, String> {
    let blob = B64.decode(sealed.trim()).map_err(|_| "сохранённый пароль повреждён".to_string())?;
    imp::unprotect(&blob)
}

#[cfg(windows)]
mod imp {
    use windows_sys::Win32::Foundation::{LocalFree, HLOCAL};
    use windows_sys::Win32::Security::Cryptography::{
        CryptProtectData, CryptUnprotectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
    };

    fn blob(data: &[u8]) -> CRYPT_INTEGER_BLOB {
        CRYPT_INTEGER_BLOB { cbData: data.len() as u32, pbData: data.as_ptr() as *mut u8 }
    }

    fn take(out: CRYPT_INTEGER_BLOB) -> Vec<u8> {
        // SAFETY: the system allocated `cbData` bytes at `pbData`; we copy and free them once.
        unsafe {
            let v = std::slice::from_raw_parts(out.pbData, out.cbData as usize).to_vec();
            LocalFree(out.pbData as HLOCAL);
            v
        }
    }

    pub fn protect(plain: &[u8]) -> Result<Vec<u8>, String> {
        let input = blob(plain);
        let entropy = blob(super::ENTROPY);
        let mut out = CRYPT_INTEGER_BLOB { cbData: 0, pbData: std::ptr::null_mut() };
        // SAFETY: all pointers are valid for the call; `out` is filled by the system.
        let ok = unsafe {
            CryptProtectData(&input, std::ptr::null(), &entropy, std::ptr::null(), std::ptr::null(), CRYPTPROTECT_UI_FORBIDDEN, &mut out)
        };
        if ok == 0 {
            return Err(format!("Windows не дал зашифровать пароль (код {})", std::io::Error::last_os_error()));
        }
        Ok(take(out))
    }

    pub fn unprotect(sealed: &[u8]) -> Result<Vec<u8>, String> {
        let input = blob(sealed);
        let entropy = blob(super::ENTROPY);
        let mut out = CRYPT_INTEGER_BLOB { cbData: 0, pbData: std::ptr::null_mut() };
        // SAFETY: as above.
        let ok = unsafe {
            CryptUnprotectData(&input, std::ptr::null_mut(), &entropy, std::ptr::null(), std::ptr::null(), CRYPTPROTECT_UI_FORBIDDEN, &mut out)
        };
        if ok == 0 {
            return Err("пароль сохранён под другой учётной записью Windows или на другом компьютере — введите его заново".into());
        }
        Ok(take(out))
    }
}

#[cfg(not(windows))]
mod imp {
    use chacha20poly1305::aead::{Aead, KeyInit, Payload};
    use chacha20poly1305::{XChaCha20Poly1305, XNonce};
    use rand_core::{OsRng, RngCore};
    use std::os::unix::fs::OpenOptionsExt;
    use std::path::PathBuf;

    fn key_file() -> PathBuf {
        crate::paths::Paths::locate().data_dir.join("server-access.key")
    }

    fn key() -> Result<[u8; 32], String> {
        let path = key_file();
        if let Ok(b) = std::fs::read(&path) {
            if let Ok(k) = <[u8; 32]>::try_from(b.as_slice()) {
                return Ok(k);
            }
        }
        let mut k = [0u8; 32];
        OsRng.fill_bytes(&mut k);
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir).map_err(|e| format!("не удалось создать папку данных: {e}"))?;
        }
        use std::io::Write;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&path)
            .map_err(|e| format!("не удалось создать ключ для паролей: {e}"))?;
        f.write_all(&k).map_err(|e| e.to_string())?;
        Ok(k)
    }

    pub fn protect(plain: &[u8]) -> Result<Vec<u8>, String> {
        let cipher = XChaCha20Poly1305::new(&key()?.into());
        let mut nonce = [0u8; 24];
        OsRng.fill_bytes(&mut nonce);
        let mut out = nonce.to_vec();
        out.extend(
            cipher
                .encrypt(XNonce::from_slice(&nonce), Payload { msg: plain, aad: super::ENTROPY })
                .map_err(|_| "не удалось зашифровать пароль".to_string())?,
        );
        Ok(out)
    }

    pub fn unprotect(sealed: &[u8]) -> Result<Vec<u8>, String> {
        if sealed.len() < 24 {
            return Err("сохранённый пароль повреждён".into());
        }
        let cipher = XChaCha20Poly1305::new(&key()?.into());
        cipher
            .decrypt(XNonce::from_slice(&sealed[..24]), Payload { msg: &sealed[24..], aad: super::ENTROPY })
            .map_err(|_| "сохранённый пароль не расшифровывается — введите его заново".into())
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn round_trip() {
        let sealed = super::seal(b"root:hunter2").unwrap();
        assert!(!sealed.contains("hunter2"));
        assert_eq!(super::open(&sealed).unwrap(), b"root:hunter2");
        assert!(super::open("bm90IHNlYWxlZA==").is_err());
    }
}
