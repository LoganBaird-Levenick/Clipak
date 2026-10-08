//! Deterministic packaging pipeline and DDI image generation for Clipak.
//!
//! Provides the tooling to turn application binaries and recipes into
//! production-ready, signed Discoverable Disk Images (DDIs):
//! - [`pipeline`]: End-to-end build workflow and validation gatekeeper.
//! - [`bundler`]: Auto-detection and bundling of non-baseline shared libraries into `/app/lib`.
//! - [`ddi_packager`]: Erofs/Squashfs filesystem packaging, dm-verity computation, and GPT assembly.
//! - [`repart_generator`]: Drop-in configuration generation for `systemd-repart`.

pub mod bundler;
pub mod ddi_packager;
pub mod pipeline;
pub mod repart_generator;

pub use bundler::DependencyBundler;
pub use ddi_packager::DdiPackager;
pub use pipeline::{BuildPipeline, BuildResult};
pub use repart_generator::RepartGenerator;
