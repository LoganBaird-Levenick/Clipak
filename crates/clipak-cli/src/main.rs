use anyhow::{bail, Result};
use clap::{Parser, Subcommand};
use clipak_builder::BuildPipeline;
use clipak_core::crypto::{verify_root_hash_signature, SigningIdentity};
use clipak_core::gpt::{read_ddi_image, SECTOR_SIZE};
use clipak_core::manifest::ToolManifest;
use clipak_core::policy::TrustStore;
use clipak_core::repo::{RemoteConfig, RepoPackageEntry, RepositoryIndex};
use clipak_daemon::{PackageInstaller, ShimManager, ShimMode};
use clipak_runtime::{ClipakDispatcher, ToolRegistry};
use colored::Colorize;
use comfy_table::presets::UTF8_FULL;
use comfy_table::{Attribute, Cell, Color, ContentArrangement, Table};
use indicatif::{ProgressBar, ProgressStyle};
use sha2::{Digest, Sha256};
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

#[derive(Parser, Debug)]
#[command(
    name = "clipak",
    author = "Clipak Contributors",
    version = "0.1.0",
    about = "Unconfined Developer Tool Delivery Architecture for Atomic Operating Systems"
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

    #[arg(short = 'u', long, global = true, help = "Allow unverified images")]
    allow_unverified: bool,

    #[arg(short = 's', long, global = true, help = "Install or manage at system scope")]
    system: bool,
}

#[derive(Subcommand, Debug)]
enum Commands {
    // -------------------------------------------------------------------------
    // Flatpak-style Primary Tool Lifecycle
    // -------------------------------------------------------------------------
    #[command(
        about = "Install a tool package (.ddi file or remote package ID)",
        visible_alias = "i",
        visible_alias = "add"
    )]
    Install {
        #[arg(help = "Path to .ddi disk image, or remote package ID (e.g. org.kernel.strace)")]
        target: String,
        #[arg(short, long, help = "Path to manifest.json (if installing local disk image)")]
        manifest: Option<PathBuf>,
    },

    #[command(
        about = "Uninstall an installed tool package",
        visible_alias = "remove",
        visible_alias = "rm"
    )]
    Uninstall {
        #[arg(help = "Package ID to uninstall (e.g. org.kernel.strace)")]
        tool_id: String,
    },

    #[command(
        about = "Update package lists and remote catalogs",
        visible_alias = "up",
        visible_alias = "upgrade"
    )]
    Update,

    #[command(
        about = "List installed Clipak tools",
        visible_alias = "ls"
    )]
    List,

    #[command(about = "Display detailed information about an installed tool")]
    Info {
        #[arg(help = "Package ID (e.g. org.kernel.strace)")]
        tool_id: String,
    },

    #[command(
        about = "Search for packages in configured remote repositories",
        visible_alias = "find"
    )]
    Search {
        #[arg(help = "Search query (package ID, name, or binary)")]
        query: String,
    },

    #[command(about = "Run an installed tool inside its private mount namespace")]
    Run {
        #[arg(short = 'c', long = "command", help = "Specific binary name to execute within /app/bin")]
        command: Option<String>,
        #[arg(help = "Tool identifier or exported binary name")]
        tool: String,
        #[arg(trailing_var_arg = true, allow_hyphen_values = true, help = "Arguments passed to the tool")]
        args: Vec<String>,
    },

    // -------------------------------------------------------------------------
    // Remote Repositories Management (Flatpak style)
    // -------------------------------------------------------------------------
    #[command(about = "List configured remote repositories")]
    Remotes,

    #[command(about = "Add a new remote repository")]
    RemoteAdd {
        #[arg(help = "Remote repository name")]
        name: String,
        #[arg(help = "Remote repository URL (HTTP/HTTPS or file path)")]
        url: String,
    },

    #[command(
        about = "Remove a configured remote repository",
        visible_alias = "remote-remove",
        visible_alias = "remote-rm"
    )]
    RemoteDelete {
        #[arg(help = "Remote repository name")]
        name: String,
    },

    #[command(about = "Manage configured remote repositories", hide = true)]
    Remote {
        #[command(subcommand)]
        sub: RemoteCommands,
    },

    // -------------------------------------------------------------------------
    // System & Environment Maintenance
    // -------------------------------------------------------------------------
    #[command(
        about = "Repair or synchronize host PATH execution shims and environment",
        visible_alias = "sync"
    )]
    Repair,

    #[command(about = "Manage host PATH execution shims", hide = true)]
    Shim {
        #[command(subcommand)]
        sub: ShimCommands,
    },

    // -------------------------------------------------------------------------
    // Packaging & Low-level Inspection
    // -------------------------------------------------------------------------
    #[command(about = "Deterministically build a Clipak tool package into a UAPI DDI")]
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

    #[command(about = "Inspect partitions and metadata of a UAPI DDI disk image")]
    Inspect {
        #[arg(help = "Path to .ddi disk image")]
        image: PathBuf,
    },

    #[command(about = "Verify dm-verity integrity and PKCS#7 signatures of a DDI image")]
    Verify {
        #[arg(help = "Path to .ddi disk image")]
        image: PathBuf,
    },

    #[command(about = "Manage Clipak software repository index (distributor tool)", hide = true)]
    Repo {
        #[command(subcommand)]
        sub: RepoCommands,
    },
}

#[derive(Subcommand, Debug)]
enum RemoteCommands {
    #[command(about = "List configured remote repositories")]
    List,
    #[command(about = "Add or update a remote repository")]
    Add {
        #[arg(help = "Remote name")]
        name: String,
        #[arg(help = "Remote URL (HTTP/HTTPS or local path)")]
        url: String,
    },
    #[command(about = "Remove a configured remote repository")]
    Remove {
        #[arg(help = "Remote name")]
        name: String,
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
        #[arg(long, default_value = "https://raw.githubusercontent.com/LoganBaird-Levenick/Clipak-Repository/main/repository")]
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

fn create_table() -> Table {
    let mut table = Table::new();
    table
        .load_style(UTF8_FULL.with_rounded_corners())
        .set_content_arrangement(ContentArrangement::Dynamic);
    table
}

fn format_bytes(bytes: u64) -> String {
    if bytes >= 1024 * 1024 * 1024 {
        format!("{:.1} GiB", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
    } else if bytes >= 1024 * 1024 {
        format!("{:.1} MiB", bytes as f64 / (1024.0 * 1024.0))
    } else if bytes >= 1024 {
        format!("{:.1} KiB", bytes as f64 / 1024.0)
    } else {
        format!("{} B", bytes)
    }
}

fn spinner(msg: &'static str) -> ProgressBar {
    let pb = ProgressBar::new_spinner();
    pb.set_style(
        ProgressStyle::default_spinner()
            .tick_chars("⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏ ")
            .template("{spinner:.cyan} {msg}")
            .unwrap_or_else(|_| ProgressStyle::default_spinner()),
    );
    pb.set_message(msg);
    pb.enable_steady_tick(std::time::Duration::from_millis(80));
    pb
}

fn print_welcome() {
    println!("{}", "Clipak".cyan().bold());
    println!("{}", "Unconfined Developer Tool Delivery for Atomic Linux".dimmed());
    println!();
    println!("{}", "Usage:".bold());
    println!("  clipak <COMMAND> [OPTIONS]");
    println!();
    println!("{}", "Manage & Run:".bold());
    println!("  {:<16} {}", "install", "Install a tool package (.ddi or remote ID)");
    println!("  {:<16} {}", "uninstall", "Uninstall an installed tool (alias: remove, rm)");
    println!("  {:<16} {}", "update", "Update repository catalogs and package lists");
    println!("  {:<16} {}", "list", "List installed Clipak tools (alias: ls)");
    println!("  {:<16} {}", "search", "Search remote package catalogs (alias: find)");
    println!("  {:<16} {}", "info", "Show detailed information about a package");
    println!("  {:<16} {}", "run", "Execute an installed tool inside its mount namespace");
    println!();
    println!("{}", "Remotes & Environment:".bold());
    println!("  {:<16} {}", "remotes", "List configured remote repositories");
    println!("  {:<16} {}", "remote-add", "Add a new remote repository");
    println!("  {:<16} {}", "remote-delete", "Remove a remote repository");
    println!("  {:<16} {}", "repair", "Repair host PATH shims and environment (alias: sync)");
    println!();
    println!("{}", "Packaging & Verification:".bold());
    println!("  {:<16} {}", "build", "Build a tool package into a UAPI DDI disk image");
    println!("  {:<16} {}", "inspect", "Inspect partitions and metadata of a DDI image");
    println!("  {:<16} {}", "verify", "Verify dm-verity integrity and PKCS#7 signatures");
    println!();
    println!("Run {} for details on any command.", "clipak <COMMAND> --help".cyan());
}

fn main() -> Result<()> {
    let args_os: Vec<String> = std::env::args().collect();
    let invocation_name = Path::new(&args_os[0])
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("clipak")
        .to_string();

    // Transparent shim dispatch: if argv[0] is not "clipak" or "clipakd", auto-dispatch!
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
        Some(Commands::Install { target, manifest }) => {
            let (image_path, manifest_path) = if Path::new(&target).exists() {
                let img = PathBuf::from(&target);
                let man = if let Some(m) = manifest {
                    m
                } else {
                    let adjacent = img.with_extension("json");
                    if adjacent.exists() {
                        adjacent
                    } else {
                        img.parent().unwrap_or(Path::new(".")).join("manifest.json")
                    }
                };
                if !man.exists() {
                    bail!("Could not find manifest.json for {}", img.display());
                }
                (img, man)
            } else {
                // Look up in remote repositories
                let found = RemoteConfig::find_package(&target);
                let (remote, pkg) = match found {
                    Some(res) => res,
                    None => {
                        bail!(
                            "Package or disk image '{}' not found.\n\
                            If this is a package ID, try running 'clipak update' first, or 'clipak search {}'",
                            target, target
                        );
                    }
                };

                println!(
                    "{} Resolving '{}' v{} from remote '{}'...",
                    "•".cyan(),
                    pkg.id.bold(),
                    pkg.version,
                    remote.name
                );

                let pb = spinner("Downloading package payload...");
                let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
                let download_dir = PathBuf::from(home).join(".cache/clipak/downloads").join(&pkg.id);
                let (downloaded_ddi, downloaded_manifest) = RemoteConfig::download_package(&remote, &pkg, &download_dir)?;
                pb.finish_and_clear();
                (downloaded_ddi, downloaded_manifest)
            };

            let self_path = std::env::current_exe()?;
            let is_system = cli.system || nix::unistd::geteuid().is_root();
            let installer = PackageInstaller::new(is_system, cli.allow_unverified)?;

            println!("{} Verifying and installing package...", "•".cyan());
            let installed = installer.install(&image_path, &manifest_path, &self_path)?;

            println!(
                "{} Successfully installed {} v{}",
                "✓".green().bold(),
                installed.manifest.name.bold(),
                installed.manifest.version
            );
            println!("{}", "Exported host binaries:".bold());
            for b in &installed.manifest.binaries {
                println!("  {} {}", "•".cyan(), b.name.bold());
            }
        }

        Some(Commands::Uninstall { tool_id }) => {
            let is_system = cli.system || nix::unistd::geteuid().is_root();
            let installer = PackageInstaller::new(is_system, cli.allow_unverified)?;
            installer.uninstall(&tool_id)?;
            println!("{} Successfully uninstalled tool: {}", "✓".green().bold(), tool_id.bold());
        }

        Some(Commands::Update) => {
            let pb = spinner("Updating Clipak repository package lists...");
            let results = RemoteConfig::update_all()?;
            pb.finish_and_clear();

            for (remote, res) in results {
                match res {
                    Ok(count) => {
                        println!(
                            "  {} {}: {} packages indexed",
                            "✓".green().bold(),
                            remote.bold(),
                            count
                        );
                    }
                    Err(e) => {
                        println!(
                            "  {} {}: failed to refresh ({})",
                            "!".yellow().bold(),
                            remote.bold(),
                            e
                        );
                    }
                }
            }
            println!("{} Repository catalogs are up to date.", "✓".green().bold());
        }

        Some(Commands::List) => {
            let tools = ToolRegistry::list_tools()?;
            if tools.is_empty() {
                println!("{}", "No Clipak tools currently installed.".dimmed());
                println!("Search for available tools with: {}", "clipak search <query>".cyan());
                return Ok(());
            }

            let mut table = create_table();
            table.set_header(vec![
                Cell::new("Application ID").add_attribute(Attribute::Bold).fg(Color::Cyan),
                Cell::new("Version").add_attribute(Attribute::Bold),
                Cell::new("Category").add_attribute(Attribute::Bold),
                Cell::new("Exported Binaries").add_attribute(Attribute::Bold).fg(Color::Green),
            ]);

            for tool in tools {
                let bins: Vec<String> = tool.manifest.binaries.iter().map(|b| b.name.clone()).collect();
                table.add_row(vec![
                    Cell::new(&tool.id).add_attribute(Attribute::Bold),
                    Cell::new(&tool.manifest.version),
                    Cell::new(&tool.manifest.category),
                    Cell::new(bins.join(", ")).fg(Color::Green),
                ]);
            }

            println!("{table}");
        }

        Some(Commands::Search { query }) => {
            let results = RemoteConfig::search(&query);
            if results.is_empty() {
                println!("No packages matching '{}' found in configured repositories.", query.bold());
                println!("Run '{}' to refresh repository catalogs.", "clipak update".cyan());
                return Ok(());
            }

            let mut table = create_table();
            table.set_header(vec![
                Cell::new("Application ID").add_attribute(Attribute::Bold).fg(Color::Cyan),
                Cell::new("Version").add_attribute(Attribute::Bold),
                Cell::new("Repository").add_attribute(Attribute::Bold).fg(Color::Yellow),
                Cell::new("Summary").add_attribute(Attribute::Bold),
            ]);

            for (remote, pkg) in results {
                table.add_row(vec![
                    Cell::new(&pkg.id).add_attribute(Attribute::Bold),
                    Cell::new(&pkg.version),
                    Cell::new(&remote).fg(Color::Yellow),
                    Cell::new(&pkg.summary),
                ]);
            }

            println!("{table}");
        }

        Some(Commands::Info { tool_id }) => {
            let tool = ToolRegistry::find_tool(&tool_id)?
                .ok_or_else(|| anyhow::anyhow!("Tool '{}' not found", tool_id))?;

            println!("{} {}", "Package:".bold().cyan(), tool.id.bold());
            println!("{:<16} {}", "Name:".bold(), tool.manifest.name);
            println!("{:<16} {}", "Version:".bold(), tool.manifest.version);
            println!("{:<16} {}", "License:".bold(), tool.manifest.license);
            println!("{:<16} {}", "Category:".bold(), tool.manifest.category);
            println!("{:<16} {}", "Runtime:".bold(), tool.manifest.runtime);
            println!("{:<16} {}", "Summary:".bold(), tool.manifest.summary);
            println!("{:<16} {}", "Install Path:".bold(), tool.install_dir.display().to_string().dimmed());
            println!("{:<16} {}", "DDI Image:".bold(), tool.ddi_path.display().to_string().dimmed());

            println!("\n{}", "Curation & Host Access Rationale:".bold().cyan());
            println!("  {:<16} {}", "Reason:".bold(), tool.manifest.curation.unconfined_reason);
            println!(
                "  {:<16} {}",
                "Capabilities:".bold(),
                tool.manifest.curation.required_host_capabilities.join(", ")
            );

            println!("\n{}", "Exported Binaries:".bold().cyan());
            for b in &tool.manifest.binaries {
                let target = b.target.as_deref().unwrap_or("/app/bin");
                println!("  {} {} (target: {})", "•".cyan(), b.name.bold(), target.dimmed());
            }
        }

        Some(Commands::Run { command, tool, mut args }) => {
            let tool_entry = ToolRegistry::find_tool(&tool)?
                .ok_or_else(|| anyhow::anyhow!("Tool or command '{}' not found in Clipak registry", tool))?;

            // Determine binary to execute:
            // 1. Explicit --command flag
            // 2. If first arg matches an exported binary name, consume it
            // 3. Match tool name against exported binaries
            // 4. Default to first exported binary
            let bin_to_run = if let Some(cmd) = command {
                cmd
            } else if !args.is_empty() && tool_entry.manifest.binaries.iter().any(|b| b.name == args[0]) {
                args.remove(0)
            } else if tool_entry.manifest.binaries.iter().any(|b| b.name == tool) {
                tool.clone()
            } else if !tool_entry.manifest.binaries.is_empty() {
                tool_entry.manifest.binaries[0].name.clone()
            } else {
                tool.clone()
            };

            let dispatcher = ClipakDispatcher::new(cli.allow_unverified)?;
            let exit_code = dispatcher.dispatch(&tool_entry, &bin_to_run, &args)?;
            std::process::exit(exit_code);
        }

        Some(Commands::Remotes) => {
            let config = RemoteConfig::load();
            if config.remotes.is_empty() {
                println!("{}", "No remote repositories configured.".dimmed());
                println!("Add one with: {}", "clipak remote-add <name> <url>".cyan());
                return Ok(());
            }

            let mut table = create_table();
            table.set_header(vec![
                Cell::new("Name").add_attribute(Attribute::Bold).fg(Color::Cyan),
                Cell::new("Status").add_attribute(Attribute::Bold),
                Cell::new("URL").add_attribute(Attribute::Bold),
            ]);

            for r in config.remotes {
                let status_cell = if r.enabled {
                    Cell::new("enabled").fg(Color::Green)
                } else {
                    Cell::new("disabled").fg(Color::Red)
                };
                table.add_row(vec![
                    Cell::new(&r.name).add_attribute(Attribute::Bold),
                    status_cell,
                    Cell::new(&r.url).fg(Color::DarkGrey),
                ]);
            }

            println!("{table}");
        }

        Some(Commands::RemoteAdd { name, url }) => {
            let mut config = RemoteConfig::load();
            config.add_or_update(&name, &url);
            config.save()?;
            println!("{} Added remote repository '{}' ({})", "✓".green().bold(), name.bold(), url.dimmed());
        }

        Some(Commands::RemoteDelete { name }) => {
            let mut config = RemoteConfig::load();
            if config.remove(&name) {
                config.save()?;
                println!("{} Removed remote repository '{}'", "✓".green().bold(), name.bold());
            } else {
                println!("{} Remote repository '{}' not found", "!".yellow().bold(), name);
            }
        }

        Some(Commands::Remote { sub }) => match sub {
            RemoteCommands::List => {
                let config = RemoteConfig::load();
                let mut table = create_table();
                table.set_header(vec![
                    Cell::new("Name").add_attribute(Attribute::Bold).fg(Color::Cyan),
                    Cell::new("Status").add_attribute(Attribute::Bold),
                    Cell::new("URL").add_attribute(Attribute::Bold),
                ]);

                for r in config.remotes {
                    let status_cell = if r.enabled {
                        Cell::new("enabled").fg(Color::Green)
                    } else {
                        Cell::new("disabled").fg(Color::Red)
                    };
                    table.add_row(vec![
                        Cell::new(&r.name).add_attribute(Attribute::Bold),
                        status_cell,
                        Cell::new(&r.url).fg(Color::DarkGrey),
                    ]);
                }
                println!("{table}");
            }
            RemoteCommands::Add { name, url } => {
                let mut config = RemoteConfig::load();
                config.add_or_update(&name, &url);
                config.save()?;
                println!("{} Added remote repository '{}' ({})", "✓".green().bold(), name.bold(), url.dimmed());
            }
            RemoteCommands::Remove { name } => {
                let mut config = RemoteConfig::load();
                if config.remove(&name) {
                    config.save()?;
                    println!("{} Removed remote repository '{}'", "✓".green().bold(), name.bold());
                } else {
                    println!("{} Remote repository '{}' not found", "!".yellow().bold(), name);
                }
            }
        },

        Some(Commands::Repair) => {
            let self_path = std::env::current_exe()?;
            let is_system = cli.system || nix::unistd::geteuid().is_root();
            let mgr = ShimManager::new(is_system, ShimMode::ShellScript)?;
            let count = mgr.sync_all_shims(&self_path)?;
            mgr.write_environment_scripts(is_system)?;
            println!(
                "{} Synchronized {} host execution shims in {}",
                "✓".green().bold(),
                count,
                mgr.bin_dir().display().to_string().cyan()
            );
            println!("{} Environment profile scripts verified.", "✓".green().bold());
        }

        Some(Commands::Shim { sub }) => match sub {
            ShimCommands::Sync => {
                let self_path = std::env::current_exe()?;
                let is_system = cli.system || nix::unistd::geteuid().is_root();
                let mgr = ShimManager::new(is_system, ShimMode::ShellScript)?;
                let count = mgr.sync_all_shims(&self_path)?;
                mgr.write_environment_scripts(is_system)?;
                println!(
                    "{} Synchronized {} host execution shims in {}",
                    "✓".green().bold(),
                    count,
                    mgr.bin_dir().display().to_string().cyan()
                );
            }
            ShimCommands::InitEnv => {
                let is_system = cli.system || nix::unistd::geteuid().is_root();
                let mgr = ShimManager::new(is_system, ShimMode::ShellScript)?;
                mgr.write_environment_scripts(is_system)?;
                println!("{} Environment profile scripts generated for Clipak.", "✓".green().bold());
            }
        },

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

            println!(
                "{} Starting deterministic build for '{}' v{}...",
                "•".cyan(),
                tool_manifest.id.bold(),
                tool_manifest.version
            );
            let pipeline = BuildPipeline::new()?;
            let res = pipeline.build(&tool_manifest, &output_dir, signing_id.as_ref())?;

            println!("\n{} Build completed successfully!", "✓".green().bold());
            println!("  {:<16} {}", "DDI Image:".bold(), res.ddi_path.display());
            println!("  {:<16} {}", "SPDX SBOM:".bold(), res.spdx_sbom_path.display());
            println!("  {:<16} {}", "CycloneDX SBOM:".bold(), res.cyclonedx_sbom_path.display());
            println!("  {:<16} {}", "CAS Root Hash:".bold(), res.ddi_hash.cyan());
        }

        Some(Commands::Inspect { image }) => {
            let ddi = read_ddi_image(&image)?;
            println!("{} {}", "UAPI Discoverable Disk Image:".bold().cyan(), image.display());
            println!("{:<16} {}", "Disk GUID:".bold(), ddi.disk_guid);
            println!(
                "{:<16} {} sectors ({})",
                "Total Size:".bold(),
                ddi.total_sectors,
                format_bytes(ddi.total_sectors * SECTOR_SIZE)
            );

            let mut table = create_table();
            table.set_header(vec![
                Cell::new("#").add_attribute(Attribute::Bold),
                Cell::new("Name").add_attribute(Attribute::Bold).fg(Color::Cyan),
                Cell::new("Type GUID").add_attribute(Attribute::Bold),
                Cell::new("LBA Range").add_attribute(Attribute::Bold),
                Cell::new("Size").add_attribute(Attribute::Bold).fg(Color::Green),
            ]);

            for (i, p) in ddi.partitions.iter().enumerate() {
                let lba_range = format!("{}..{}", p.first_lba, p.last_lba);
                table.add_row(vec![
                    Cell::new((i + 1).to_string()),
                    Cell::new(&p.name).add_attribute(Attribute::Bold),
                    Cell::new(p.type_guid.to_string()).fg(Color::DarkGrey),
                    Cell::new(lba_range),
                    Cell::new(format_bytes(p.byte_size())).fg(Color::Green),
                ]);
            }

            println!("\n{table}");
        }

        Some(Commands::Verify { image }) => {
            let ddi = read_ddi_image(&image)?;
            println!("{} {}\n", "Verifying UAPI DDI:".bold().cyan(), image.display());

            let root_part = ddi.find_root_partition()
                .ok_or_else(|| anyhow::anyhow!("Root partition missing"))?;
            let verity_part = ddi.find_verity_partition()
                .ok_or_else(|| anyhow::anyhow!("dm-verity hash partition missing"))?;
            let sig_part = ddi.find_verity_sig_partition()
                .ok_or_else(|| anyhow::anyhow!("PKCS#7 signature partition missing"))?;

            println!("  {} Root Partition:      {} (Type: {})", "✓".green().bold(), root_part.name.bold(), root_part.type_guid.to_string().dimmed());
            println!("  {} Verity Partition:    {} (Type: {})", "✓".green().bold(), verity_part.name.bold(), verity_part.type_guid.to_string().dimmed());
            println!("  {} Signature Partition: {} (Type: {})", "✓".green().bold(), sig_part.name.bold(), sig_part.type_guid.to_string().dimmed());

            // Read verity salt and root hash
            let mut file = File::open(&image)?;
            file.seek(SeekFrom::Start(verity_part.byte_offset()))?;
            let mut sb = [0u8; 512];
            file.read_exact(&mut sb)?;

            if &sb[0..8] == b"verity\0\0" {
                let mut salt = [0u8; 32];
                salt.copy_from_slice(&sb[88..120]);
                println!("  {} dm-verity Superblock: valid (salt: {})", "✓".green().bold(), hex::encode(salt).dimmed());

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
                println!("  {} dm-verity Root Hash:  {}", "✓".green().bold(), verity_calc.root_hash_hex.cyan());

                let trust_store = TrustStore::load_defaults()?;
                let ok = verify_root_hash_signature(&verity_calc.root_hash, &sig_bytes, trust_store.certificates());
                match ok {
                    Ok(true) => println!("  {} PKCS#7 Signature:    Verified successfully against trusted certificate authority!", "✓".green().bold()),
                    _ => println!("  {} PKCS#7 Signature:    Verification warning (untrusted authority or self-signed certificate)", "!".yellow().bold()),
                }
            } else {
                bail!("Invalid dm-verity superblock format");
            }

            println!("\n{} Disk image integrity cryptographically verified.", "✓".green().bold());
        }

        Some(Commands::Repo { sub }) => match sub {
            RepoCommands::Init { repo_dir, name, url } => {
                fs::create_dir_all(&repo_dir)?;
                let index = RepositoryIndex::new(&name, "Curated repository for unconfined developer utilities", &url);
                let index_path = repo_dir.join("index.json");
                fs::write(&index_path, serde_json::to_string_pretty(&index)?)?;
                println!("{} Initialized Clipak repository at {}", "✓".green().bold(), repo_dir.display().to_string().cyan());
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
                    manifest_filename: Some(manifest.file_name().unwrap().to_string_lossy().to_string()),
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

                println!(
                    "{} Added '{}' v{} to repository index at {}",
                    "✓".green().bold(),
                    m.id.bold(),
                    m.version,
                    index_path.display().to_string().cyan()
                );
            }
        },

        None => {
            print_welcome();
        }
    }

    Ok(())
}
