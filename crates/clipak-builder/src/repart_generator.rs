//! Integration with `systemd-repart` for disk image partitioning.
//!
//! Generates partition drop-in definition files (`00-root.conf`, `10-verity.conf`,
//! `20-verity-sig.conf`) and invokes `systemd-repart` when available on the host.

use anyhow::Result;
use std::fs;
use std::path::Path;
use std::process::Command;

/// Generates systemd-repart configuration files conforming to UAPI.3 DDI.
pub struct RepartGenerator;

impl RepartGenerator {
    /// Writes repart definition drop-in files to target directory
    pub fn write_definitions<P: AsRef<Path>>(
        repart_dir: P,
        app_source_dir: &Path,
        filesystem: &str,
    ) -> Result<()> {
        let dir = repart_dir.as_ref();
        fs::create_dir_all(dir)?;

        // 00-root.conf
        let root_conf = format!(
            r#"[Partition]
Type=root
Format={}
CopyFiles={}
Minimize=guess
"#,
            filesystem,
            app_source_dir.display()
        );
        fs::write(dir.join("00-root.conf"), root_conf)?;

        // 10-verity.conf
        let verity_conf = r#"[Partition]
Type=root-verity
Verity=data
"#;
        fs::write(dir.join("10-verity.conf"), verity_conf)?;

        // 20-verity-sig.conf
        let sig_conf = r#"[Partition]
Type=root-verity-sig
Verity=hash
"#;
        fs::write(dir.join("20-verity-sig.conf"), sig_conf)?;

        Ok(())
    }

    /// Invokes systemd-repart to build DDI if systemd-repart is available
    pub fn invoke_systemd_repart(
        definitions_dir: &Path,
        output_ddi: &Path,
        private_key_path: Option<&Path>,
        certificate_path: Option<&Path>,
    ) -> Result<bool> {
        let mut cmd = Command::new("systemd-repart");
        cmd.arg("--definitions").arg(definitions_dir);
        cmd.arg("--empty=create");
        cmd.arg("--size=auto");

        if let (Some(k), Some(c)) = (private_key_path, certificate_path) {
            cmd.arg(format!("--private-key={}", k.display()));
            cmd.arg(format!("--certificate={}", c.display()));
        }

        cmd.arg(output_ddi);

        let output = cmd.output();
        match output {
            Ok(out) => Ok(out.status.success()),
            Err(_) => Ok(false),
        }
    }
}
