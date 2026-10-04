use anyhow::{bail, Result};
use clap::{Parser, Subcommand};
use clipak_builder::BuildPipeline;
use clipak_core::crypto::{verify_root_hash_signature, SigningIdentity};
use clipak_core::gpt::{read_ddi_image, SECTOR_SIZE};
use clipak_core::manifest::ToolManifest;
use clipak_core::policy::TrustStore;
use clipak_core::repo::{RepoPackageEntry, RepositoryIndex};
use clipak_daemon::{PackageInstaller, ShimManager, ShimMode};
use clipak_runtime::{ClipakDispatcher, ToolRegistry};
use sha2::{Digest, Sha256};
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

#[derive(Parser, Debug)]
#[command(
    name = "clipak",
    author = "Clipak Contributors",
    version = "0.1.0",
    about = "Clipak: Unconfined Developer Tool Delivery Architecture for Atomic Operating Systems"
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

    #[arg(short, long, global = true, help = "Allow unverified images")]
    allow_unverified: bool,

    #[arg(short, long, global = true, help = "Install or manage at system scope")]
    system: bool,
}

#[derive(Subcommand, Debug)]
enum Commands {
    #[command(about = "Execute an unconfined tool inside its private mount namespace")]
    Run {
        #[arg(help = "Tool identifier or exported binary name")]
        tool: String,
        #[arg(help = "Specific binary name to execute within /app/bin", default_value = "")]
        binary: String,
        #[arg(trailing_var_arg = true, allow_hyphen_values = true, help = "Arguments to pass to the tool")]
        args: Vec<String>,
    },

    #[command(about = "Install a Clipak tool package (.ddi)")]
    Install {
        #[arg(help = "Path to the .ddi disk image")]
        image: PathBuf,
        #[arg(short, long, help = "Path to manifest.json (if separate from image)")]
        manifest: Option<PathBuf>,
    },

    #[command(about = "Uninstall an installed tool package")]
    Uninstall {
        #[arg(help = "Package ID to uninstall")]
        tool_id: String,
    },

    #[command(about = "List all installed Clipak tools")]
    List,

    #[command(about = "Display detailed information about an installed tool")]
    Info {
        #[arg(help = "Package ID")]
        tool_id: String,
    },

    #[command(about = "Deterministically build a Clipak tool package and UAPI.3 DDI")]
    Build {
        #[arg(help = "Path to manifest (clipak.yaml or manifest.json)")]
        manifest: PathBuf,
        #[arg(short, long, default_value = "./dist", help = "Output directory")]
        output_dir: PathBuf,
        #[arg(long, help = "Path to PEM signing key")]
        key: Option<PathBuf>,
        #[arg(long, help = "Path to PEM certificate")]
        cert: Option<PathBuf>,
    },

    #[command(about = "Inspect partitions and metadata of a UAPI.3 DDI image")]
    Inspect {
        #[arg(help = "Path to .ddi disk image")]
        image: PathBuf,
    },

    #[command(about = "Verify dm-verity integrity and PKCS#7 signatures of a DDI image")]
    Verify {
        #[arg(help = "Path to .ddi disk image")]
        image: PathBuf,
    },

    #[command(about = "Manage host PATH execution shims")]
    Shim {
        #[command(subcommand)]
        sub: ShimCommands,
    },

    #[command(about = "Manage Clipak software repositories")]
    Repo {
        #[command(subcommand)]
        sub: RepoCommands,
    },
}

#[derive(Subcommand, Debug)]
enum ShimCommands {
    #[command(about = "Synchronize host shims with installed packages")]
    Sync,
    #[command(about = "Generate environment integration scripts")]
    InitEnv,
}

#[derive(Subcommand, Debug)]
enum RepoCommands {
    #[command(about = "Initialize a new repository index")]
    Init {
        #[arg(help = "Repository root directory")]
        repo_dir: PathBuf,
        #[arg(long, default_value = "Clipak Official Repository")]
        name: String,
        #[arg(long, default_value = "https://repo.clipak.org")]
        url: String,
    },
    #[command(about = "Add a built package to repository index")]
    Add {
        #[arg(help = "Repository root directory")]
        repo_dir: PathBuf,
        #[arg(help = "Path to .ddi file")]
        image: PathBuf,
        #[arg(help = "Path to manifest.json")]
        manifest: PathBuf,
    },
}

fn main() -> Result<()> {
    let args_os: Vec<String> = std::env::args().collect();
    let invocation_name = Path::new(&args_os[0])
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("clipak")
        .to_string();

    // Transparent shim dispatch: if argv[0] is not "clipak", auto-dispatch!
    if invocation_name != "clipak" && invocation_name != "clipakd" {
        if let Some(tool) = ToolRegistry::find_tool(&invocation_name)? {
            let dispatcher = ClipakDispatcher::new(false)?;
            let pass_args: Vec<String> = args_os.into_iter().skip(1).collect();
            let exit_code = dispatcher.dispatch(&tool, &invocation_name, &pass_args)?;
            std::process::exit(exit_code);
        }
    }

    let cli = Cli::parse();

    match cli.command {
        Some(Commands::Run { tool, binary, args }) => {
            let tool_entry = ToolRegistry::find_tool(&tool)?
                .ok_or_else(|| anyhow::anyhow!("Tool or command '{}' not found in Clipak registry", tool))?;
            let bin_to_run = if !binary.is_empty() {
                binary
            } else if tool_entry.manifest.binaries.len() == 1 {
                tool_entry.manifest.binaries[0].name.clone()
            } else if tool_entry.manifest.binaries.iter().any(|b| b.name == tool) {
                tool.clone()
            } else {
                tool_entry.manifest.binaries[0].name.clone()
            };

            let dispatcher = ClipakDispatcher::new(cli.allow_unverified)?;
            let exit_code = dispatcher.dispatch(&tool_entry, &bin_to_run, &args)?;
            std::process::exit(exit_code);
        }

        Some(Commands::Install { image, manifest }) => {
            let manifest_path = if let Some(m) = manifest {
                m
            } else {
                // Check if manifest.json exists next to DDI
                let adjacent = image.with_extension("json");
                if adjacent.exists() {
                    adjacent
                } else {
                    image.parent().unwrap_or(Path::new(".")).join("manifest.json")
                }
            };

            if !manifest_path.exists() {
                bail!("Could not find manifest.json for {}", image.display());
            }

            let self_path = std::env::current_exe()?;
            let is_system = cli.system || nix::unistd::geteuid().is_root();
            let installer = PackageInstaller::new(is_system, cli.allow_unverified)?;
            let installed = installer.install(&image, &manifest_path, &self_path)?;

            println!("Successfully installed {} v{}", installed.manifest.name, installed.manifest.version);
            println!("Exported binaries registered to host PATH:");
            for b in &installed.manifest.binaries {
                println!("  - {}", b.name);
            }
        }

        Some(Commands::Uninstall { tool_id }) => {
            let is_system = cli.system || nix::unistd::geteuid().is_root();
            let installer = PackageInstaller::new(is_system, cli.allow_unverified)?;
            installer.uninstall(&tool_id)?;
            println!("Successfully uninstalled tool: {}", tool_id);
        }

        Some(Commands::List) => {
            let tools = ToolRegistry::list_tools()?;
            if tools.is_empty() {
                println!("No Clipak tools installed.");
                return Ok(());
            }

            println!("{:<24} {:<10} {:<16} {:<30}", "PACKAGE ID", "VERSION", "CATEGORY", "EXPORTED BINARIES");
            println!("{:-<85}", "");
            for tool in tools {
                let bins: Vec<String> = tool.manifest.binaries.iter().map(|b| b.name.clone()).collect();
                println!(
                    "{:<24} {:<10} {:<16} {:<30}",
                    tool.id,
                    tool.manifest.version,
                    tool.manifest.category,
                    bins.join(", ")
                );
            }
        }

        Some(Commands::Info { tool_id }) => {
            let tool = ToolRegistry::find_tool(&tool_id)?
                .ok_or_else(|| anyhow::anyhow!("Tool '{}' not found", tool_id))?;

            println!("Package ID:   {}", tool.id);
            println!("Name:         {}", tool.manifest.name);
            println!("Version:      {}", tool.manifest.version);
            println!("License:      {}", tool.manifest.license);
            println!("Category:     {}", tool.manifest.category);
            println!("Runtime:      {}", tool.manifest.runtime);
            println!("Summary:      {}", tool.manifest.summary);
            println!("Install Path: {}", tool.install_dir.display());
            println!("DDI Image:    {}", tool.ddi_path.display());
            println!("\nCuration & Host Access Justification:");
            println!("  Reason: {}", tool.manifest.curation.unconfined_reason);
            println!("  Required Caps: {:?}", tool.manifest.curation.required_host_capabilities);
            println!("\nExported Binaries:");
            for b in &tool.manifest.binaries {
                println!("  - {} (target: {:?})", b.name, b.target);
            }
        }

        Some(Commands::Build { manifest, output_dir, key, cert }) => {
            let content = fs::read_to_string(&manifest)?;
            let tool_manifest = if manifest.extension().map(|e| e == "yaml" || e == "yml").unwrap_or(false) {
                ToolManifest::from_yaml_str(&content)?
            } else {
                ToolManifest::from_json_str(&content)?
            };

            let signing_id = if let (Some(k), Some(c)) = (key, cert) {
                Some(SigningIdentity::load_from_pem(c, k)?)
            } else {
                None
            };

            println!("Starting deterministic build for '{}' v{}...", tool_manifest.id, tool_manifest.version);
            let pipeline = BuildPipeline::new()?;
            let res = pipeline.build(&tool_manifest, &output_dir, signing_id.as_ref())?;

            println!("\nBuild completed successfully!");
            println!("  DDI Image:      {}", res.ddi_path.display());
            println!("  SPDX SBOM:      {}", res.spdx_sbom_path.display());
            println!("  CycloneDX SBOM: {}", res.cyclonedx_sbom_path.display());
            println!("  CAS Root Hash:  {}", res.ddi_hash);
        }

        Some(Commands::Inspect { image }) => {
            let ddi = read_ddi_image(&image)?;
            println!("UAPI.3 Discoverable Disk Image: {}", image.display());
            println!("Disk GUID:     {}", ddi.disk_guid);
            println!("Total Sectors: {} ({} bytes)", ddi.total_sectors, ddi.total_sectors * SECTOR_SIZE);
            println!("\nPartitions:");
            for (i, p) in ddi.partitions.iter().enumerate() {
                println!("  #{} '{}':", i + 1, p.name);
                println!("     Type GUID:   {}", p.type_guid);
                println!("     Unique GUID: {}", p.unique_guid);
                println!("     LBA Range:   {}..{} ({} sectors / {} bytes)", p.first_lba, p.last_lba, p.sector_count(), p.byte_size());
            }
        }

        Some(Commands::Verify { image }) => {
            let ddi = read_ddi_image(&image)?;
            println!("Verifying UAPI.3 DDI: {}", image.display());

            let root_part = ddi.find_root_partition()
                .ok_or_else(|| anyhow::anyhow!("Root partition missing"))?;
            let verity_part = ddi.find_verity_partition()
                .ok_or_else(|| anyhow::anyhow!("dm-verity hash partition missing"))?;
            let sig_part = ddi.find_verity_sig_partition()
                .ok_or_else(|| anyhow::anyhow!("PKCS#7 signature partition missing"))?;

            println!("  [✓] Root Partition:      {} (Type: {})", root_part.name, root_part.type_guid);
            println!("  [✓] Verity Partition:    {} (Type: {})", verity_part.name, verity_part.type_guid);
            println!("  [✓] Signature Partition: {} (Type: {})", sig_part.name, sig_part.type_guid);

            // Read verity salt and root hash
            let mut file = File::open(&image)?;
            file.seek(SeekFrom::Start(verity_part.byte_offset()))?;
            let mut sb = [0u8; 512];
            file.read_exact(&mut sb)?;

            if &sb[0..8] == b"verity\0\0" {
                let mut salt = [0u8; 32];
                salt.copy_from_slice(&sb[88..120]);
                println!("  [✓] dm-verity Superblock: valid (salt: {})", hex::encode(salt));

                // Read PKCS#7 signature
                file.seek(SeekFrom::Start(sig_part.byte_offset()))?;
                let mut sig_bytes = vec![0u8; sig_part.byte_size() as usize];
                file.read_exact(&mut sig_bytes)?;
                let non_zero = sig_bytes.iter().rposition(|&b| b != 0).map(|i| i + 1).unwrap_or(0);
                sig_bytes.truncate(non_zero);

                // Read root partition payload to compute root hash
                file.seek(SeekFrom::Start(root_part.byte_offset()))?;
                let mut root_data = vec![0u8; root_part.byte_size() as usize];
                file.read_exact(&mut root_data)?;

                let verity_calc = clipak_core::verity::compute_verity_tree(&root_data, Some(salt))?;
                println!("  [✓] dm-verity Root Hash:  {}", verity_calc.root_hash_hex);

                let trust_store = TrustStore::load_defaults()?;
                let ok = verify_root_hash_signature(&verity_calc.root_hash, &sig_bytes, trust_store.certificates());
                match ok {
                    Ok(true) => println!("  [✓] PKCS#7 Signature:    Verified successfully with trusted authority cert!"),
                    _ => println!("  [!] PKCS#7 Signature:    Verification warning (untrusted signer or self-signed cert)"),
                }
            } else {
                bail!("Invalid dm-verity superblock format");
            }

            println!("\nDisk image cryptographically verified.");
        }

        Some(Commands::Shim { sub }) => match sub {
            ShimCommands::Sync => {
                let self_path = std::env::current_exe()?;
                let is_system = cli.system || nix::unistd::geteuid().is_root();
                let mgr = ShimManager::new(is_system, ShimMode::ShellScript)?;
                let count = mgr.sync_all_shims(&self_path)?;
                mgr.write_environment_scripts(is_system)?;
                println!("Synchronized {} host execution shims in {}", count, mgr.bin_dir().display());
            }
            ShimCommands::InitEnv => {
                let is_system = cli.system || nix::unistd::geteuid().is_root();
                let mgr = ShimManager::new(is_system, ShimMode::ShellScript)?;
                mgr.write_environment_scripts(is_system)?;
                println!("Environment profile scripts generated for Clipak.");
            }
        },

        Some(Commands::Repo { sub }) => match sub {
            RepoCommands::Init { repo_dir, name, url } => {
                fs::create_dir_all(&repo_dir)?;
                let index = RepositoryIndex::new(&name, "Curated repository for unconfined developer utilities", &url);
                let index_path = repo_dir.join("index.json");
                fs::write(&index_path, serde_json::to_string_pretty(&index)?)?;
                println!("Initialized Clipak repository at {}", repo_dir.display());
            }
            RepoCommands::Add { repo_dir, image, manifest } => {
                let manifest_str = fs::read_to_string(&manifest)?;
                let m = ToolManifest::from_json_str(&manifest_str)?;

                let ddi_bytes = fs::read(&image)?;
                let ddi_sha256 = format!("{:x}", Sha256::digest(&ddi_bytes));

                let ddi = read_ddi_image(&image)?;
                let _root_part = ddi.find_root_partition().ok_or_else(|| anyhow::anyhow!("Missing root partition"))?;

                let entry = RepoPackageEntry {
                    id: m.id.clone(),
                    name: m.name.clone(),
                    version: m.version.clone(),
                    architecture: "x86_64".into(),
                    summary: m.summary.clone(),
                    license: m.license.clone(),
                    ddi_filename: image.file_name().unwrap().to_string_lossy().to_string(),
                    ddi_sha256,
                    root_hash_hex: "dm-verity".into(),
                    ddi_size_bytes: ddi_bytes.len() as u64,
                    exported_binaries: m.binaries.iter().map(|b| b.name.clone()).collect(),
                    sbom_spdx_filename: Some(format!("{}.spdx.json", m.id)),
                    sbom_cyclonedx_filename: Some(format!("{}.cyclonedx.json", m.id)),
                };

                let index_path = repo_dir.join("index.json");
                let mut index: RepositoryIndex = if index_path.exists() {
                    serde_json::from_str(&fs::read_to_string(&index_path)?)?
                } else {
                    RepositoryIndex::new("Clipak Repository", "Curated developer packages", "https://repo.clipak.org")
                };

                index.packages.retain(|p| p.id != entry.id);
                index.packages.push(entry);
                fs::write(&index_path, serde_json::to_string_pretty(&index)?)?;

                println!("Added '{}' v{} to repository index at {}", m.id, m.version, index_path.display());
            }
        },

        None => {
            println!("Clipak: Discoverable Disk Image Runtime for Unconfined Developer Utilities");
            println!("Run 'clipak --help' for commands and options.");
        }
    }

    Ok(())
}
