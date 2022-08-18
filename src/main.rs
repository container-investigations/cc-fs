//! Confidential Container file-system tools.
//!
//! Provides tools to create integrity protected file-systems for use in
//! confidential containers.
//!
//! # Creating an index
//! Use the `index` subcommand to create an index for a layer's tar file or
//! folder.
//! ```bash
//!  $ cc-fs index layer.tar -d a65a803efce5eec96deeff2d556c6294059e64a6dedd1f2935be9c862f28a319
//!  wrote layer.tar.index, size = 19589587 bytes
//! ```
//! If the supplied digest does not match the computed digest, then an error is raised.
//! ```bash
//! $ cc-fs index layer.tar -d aabbccddeeffaabbccddeeffaabbccddeeffaabbccddeeffaabbccddeeffaabb
//! Error: layer.tar: Computed digest a65a803efce5eec96deeff2d556c6294059e64a6dedd1f2935be9c862f28a319 != supplied digest aabbccddeeffaabbccddeeffaabbccddeeffaabbccddeeffaabbccddeeffaabb
//! ```
//! # Performance
//! cc-fs has only a tiny overhead compared to computing the sha256sum of a tar
//! file. For performance measurements, we create a 2.8GB tar file.
//!
//! ```bash
//! $ image=oeciteam/oetools-20.04@sha256:3118bbfc78b0bde43ef49bdb96bae45e6c342a9ef4a56b482bc24bb4e24fea75
//! $ docker pull $image
//! $ id=$(docker create -t $image)
//! $ docker export $id > large.tar
//! ```
//!
//! Measurements are done on a VM with 1 vcpu and 2048 MB memory which is the
//! default configuration of a kata container's VM.
//!
//! Computing the sha256sum of the tar file takes *2.71 seconds* on average.
//! ```bash
//! $ hyperfine --warmup 5 --prepare "echo 3 | sudo tee -a /proc/sys/vm/drop_caches; sync; sleep 1; sync; sleep 1; sync; sleep 1" \
//!   "sha256sum-rs large.tar" -m 10
//! Benchmark 1: sha256sum-rs large.tar
//!   Time (mean ± σ):      2.719 s ±  0.180 s    [User: 1.735 s, System: 0.699 s]
//!   Range (min … max):    2.578 s …  3.054 s    10 runs
//! ```
//!
//! Indexing the same 2.8G tar file takes `2.97 seconds` on average.
//! ```bash
//! $ hyperfine --warmup 5 --prepare "echo 3 | sudo tee -a /proc/sys/vm/drop_caches; sync; sleep 1; sync; sleep 1; sync; sleep 1" \
//!   "target/release/cc-fs index large.tar -d fdbff9d86aa49c0fcbf596624b40c9c2191efeccb2fb75675881a7344d4dd87f" -m 10
//! Benchmark 1: target/release/cc-fs index large.tar -d fdbff9d86aa49c0fcbf596624b40c9c2191efeccb2fb75675881a7344d4dd87f
//!   Time (mean ± σ):      2.978 s ±  0.201 s    [User: 1.826 s, System: 0.823 s]
//!   Range (min … max):    2.756 s …  3.289 s    10 runs
//! ```
//!
//! # Serialization
//! cc-fs uses [serde](https://serde.rs/) framework for serialization. Thus the
//! index can be stored in any format for which a serde adapter has been
//! implemented. E.g: JSON, Postcard, CBOR, MessagePack, FlexBuffers etc.
//! By default, serialization is performed in [bincode](https://crates.io/crates/bincode)
//! format which compact and fast.
//! See [Comparison](https://blog.logrocket.com/rust-serialization-whats-ready-for-production-today/)
//!
//! ```bash
//! $ ls -sh large.tar.index
//! 40M large.tar.index
//! ````
use anyhow::Result;
use clap::{Parser, Subcommand};

mod hash;
mod index;
mod tar;

mod fs;

/// Confidential container file-system tools.
#[doc(hidden)]
#[derive(Parser)]
#[clap(author, version, about, long_about = None)]
struct Cli {
    #[clap(subcommand)]
    command: Commands,
}

#[doc(hidden)]
#[derive(Subcommand)]
enum Commands {
    /// Create confidential container file-system index.
    Index {
        /// Expected digest of the tar file.
        #[clap(short, long, name = "digest")]
        digest: Option<String>,

        /// Path of the tar file/folder.
        #[clap(value_parser, name = "path", required = true)]
        path: String,
    },

    /// Mount confidential container file-system.
    Mount {
        /// Colon separated list of indexes.
        #[clap(short, long, name = "index")]
        index: String,

        /// Path of the tar file/folder.
        #[clap(value_parser, name = "path", required = true)]
        path: String,

        /// Mount directory.
        #[clap(value_parser, name = "mountpoint", required = true)]
        mount_point: String,
    },
}

#[doc(hidden)]
fn main() -> Result<()> {
    // Parse and dispatch commands.
    let cli = Cli::parse();
    match &cli.command {
        Commands::Index { digest, path } => tar::index(digest, path),
        Commands::Mount {
            index,
            path,
            mount_point,
        } => fs::mount(index, path, mount_point),
    }
}
