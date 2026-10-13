//! A request-scoped curl header file. Only its path travels in process argv.
//! Unix permissions reduce incidental disclosure; the same user/root can still
//! read the file or process memory. SIGKILL can leave the file behind.

use std::path::PathBuf;

pub(super) struct BearerHeader {
    directory: PathBuf,
    argument: String,
}

impl BearerHeader {
    pub(super) fn create(token: &str) -> Result<Self, &'static str> {
        // A header file is line-oriented. Never reinterpret a token as another
        // header, or allow a NUL to silently truncate it. Do not echo the token.
        if token.bytes().any(|b| matches!(b, b'\r' | b'\n' | 0)) {
            return Err("invalid HTTP bearer header");
        }
        #[cfg(unix)]
        {
            Self::create_in(token, &std::env::temp_dir())
        }
        #[cfg(not(unix))]
        {
            Err("private HTTP bearer headers require Unix permissions")
        }
    }

    #[cfg(unix)]
    fn create_in(token: &str, parent: &std::path::Path) -> Result<Self, &'static str> {
        use std::fs::{DirBuilder, OpenOptions};
        use std::io::Write;
        use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
        use std::sync::atomic::{AtomicU64, Ordering};
        use std::time::{SystemTime, UNIX_EPOCH};

        static NEXT: AtomicU64 = AtomicU64::new(0);
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| "could not create private HTTP bearer header")?
            .as_nanos();
        for _ in 0..128 {
            let directory = parent.join(format!(
                "arcora-prove-header-{}-{stamp}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            match DirBuilder::new().mode(0o700).create(&directory) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(_) => return Err("could not create private HTTP bearer header"),
            }
            // Construct the owner immediately so every later error cleans up
            // only this newly created directory and its fixed header filename.
            let mut owner = Self {
                directory,
                argument: String::new(),
            };
            let path = owner.directory.join("authorization");
            let path_text = path
                .to_str()
                .ok_or("could not create private HTTP bearer header")?;
            owner.argument = format!("@{path_text}");
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&path)
                .map_err(|_| "could not create private HTTP bearer header")?;
            file.write_all(b"Authorization: Bearer ")
                .and_then(|_| file.write_all(token.as_bytes()))
                .and_then(|_| file.write_all(b"\n"))
                .map_err(|_| "could not write private HTTP bearer header")?;
            // Close the writer before curl reads. Owner lives through curl reap.
            drop(file);
            return Ok(owner);
        }
        Err("could not create private HTTP bearer header")
    }

    pub(super) fn argument(&self) -> &str {
        &self.argument
    }
}

impl Drop for BearerHeader {
    fn drop(&mut self) {
        // Never recursively delete an unexpected entry. Cleanup is best effort
        // if permissions/filesystem state change; no crash-cleanup guarantee.
        let _ = std::fs::remove_file(self.directory.join("authorization"));
        let _ = std::fs::remove_dir(&self.directory);
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::BearerHeader;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn private_header_preserves_bytes_and_cleans_up_on_drop() {
        let token = "public-synthetic-token / + = ü";
        let header = BearerHeader::create(token).unwrap();
        let path = header.directory.join("authorization");
        assert_eq!(
            std::fs::metadata(&header.directory)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            std::fs::read(&path).unwrap(),
            format!("Authorization: Bearer {token}\n").as_bytes()
        );
        assert!(!header.argument().contains(token));
        let directory = header.directory.clone();
        drop(header);
        assert!(!path.exists());
        assert!(!directory.exists());
    }

    #[test]
    fn concurrent_requests_get_distinct_header_files() {
        let first = BearerHeader::create("public-first").unwrap();
        let second = BearerHeader::create("public-second").unwrap();
        assert_ne!(first.argument(), second.argument());
        assert_eq!(
            std::fs::read(first.directory.join("authorization")).unwrap(),
            b"Authorization: Bearer public-first\n"
        );
        assert_eq!(
            std::fs::read(second.directory.join("authorization")).unwrap(),
            b"Authorization: Bearer public-second\n"
        );
    }

    #[test]
    fn header_control_characters_fail_without_echoing_input() {
        for token in ["public\rinjected", "public\ninjected", "public\0injected"] {
            let error = BearerHeader::create(token).err().unwrap();
            assert_eq!(error, "invalid HTTP bearer header");
            assert!(!error.contains("public"));
        }
    }

    #[test]
    fn creation_failure_is_redacted() {
        let error = BearerHeader::create_in(
            "public-synthetic-token",
            std::path::Path::new("/dev/null/absent"),
        )
        .err()
        .unwrap();
        assert_eq!(error, "could not create private HTTP bearer header");
        assert!(!error.contains("public-synthetic-token"));
    }
}
