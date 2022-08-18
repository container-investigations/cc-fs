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
//!
//! # Mounting a Confidential Container File System
//! Use the `mount` subcommand to mount a cc file-system using a given index and
//! tar file.
//! ```bash
//! $ mkdir m
//! $ cc-fs mount --index layer.tar.index layer.tar m
//! $ $ ls -lah m
//! total 7.5K
//! drwxr-xr-x  2 root     root     4.0K Dec 31  1969 ./
//! drwxrwxr-x 10 anakrish anakrish 4.0K Aug 23 00:17 ../
//! drwxr-xr-x  1 root     root     4.0K Dec  7  2021 etc/
//! drwxr-xr-x  1 root     root     4.0K Nov  2  2021 libsgx-pce-logic/
//! drwxr-xr-x  1 root     root     4.0K Nov  2  2021 libsgx-qe3-logic/
//! drwxr-xr-x  1 root     root     4.0K Dec  7  2021 opt/
//! drwxr-xr-x  1 root     root     4.0K Dec  7  2021 usr/
//! drwxr-xr-x  1 root     root     4.0K Oct  6  2021 var/
//! ```
//!
//! Support for mounting an existing folder and applying index over it, is not
//! implemented yet.
//!
//! # Performance
//! cc-fs has only a tiny overhead compared to computing the sha256sum of a tar
//! file. For performance measurements, we create a 2.8GB tar file.
//!
//! ```bash
//! $ image=oeciteam/oetools-20.04@sha256:3118bbfc78b0bde43ef49bdb96bae45e6c342a9ef4a56b482bc24bb4e24fea75
//! $ docker pull $image
//! $ id=$(docker create -t $image)
//! $ docker export $id > large.tar
//! $ docker rm $id
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
//! Indexing the same 2.8G tar file takes *2.97 seconds* on average.
//! ```bash
//! $ hyperfine --warmup 5 --prepare "echo 3 | sudo tee -a /proc/sys/vm/drop_caches; sync; sleep 1; sync; sleep 1; sync; sleep 1" \
//!   "target/release/cc-fs index large.tar -d fdbff9d86aa49c0fcbf596624b40c9c2191efeccb2fb75675881a7344d4dd87f" -m 10
//! Benchmark 1: target/release/cc-fs index large.tar -d fdbff9d86aa49c0fcbf596624b40c9c2191efeccb2fb75675881a7344d4dd87f
//!   Time (mean ± σ):      2.978 s ±  0.201 s    [User: 1.826 s, System: 0.823 s]
//!   Range (min … max):    2.756 s …  3.289 s    10 runs
//! ```
//!
//!
//! It takes *812 ms* to execute the tree command on the file-system with caching
//! disabled, and *556 ms* with caching enabled. On native file-system (ie ext4),
//! the same operations take *818 ms* and *295 ms* respectively.
//!
//! ```bash
//! $ # mount cc file-system
//! $ mkdir m
//! $ cc-fs mount --index large.tar.index large.tar m
//!
//! $ # Measure with caching disabled
//! $ $ hyperfine --warmup 5 --prepare "echo 3 | sudo tee -a /proc/sys/vm/drop_caches; sync; sleep 1; sync; sleep 1; sync; sleep 1" \
//! $   "tree m" -m 10
//! Benchmark 1: tree m
//!   Time (mean ± σ):     812.1 ms ±  30.4 ms    [User: 156.1 ms, System: 323.2 ms]
//!   Range (min … max):   786.5 ms … 880.4 ms    10 runs
//!
//! $ # Measure with caching enable
//! $ $ hyperfine --warmup 5 --prepare "" "tree m" -m 10
//! Benchmark 1: tree m
//!   Time (mean ± σ):     556.4 ms ± 159.7 ms    [User: 153.9 ms, System: 200.6 ms]
//!   Range (min … max):   392.6 ms … 709.6 ms    10 runs
//!
//! $ # Create native file-system
//! $ mkdir native; cd native; tar xf ../large.tar; cd ..
//! $
//! $ # Measure native with caching disabled
//! $ hyperfine --warmup 5 --prepare "echo 3 | sudo tee -a /proc/sys/vm/drop_caches; sync; sleep 1; sync; sleep 1; sync; sleep 1" \
//!   "tree native" -m 10
//! Benchmark 1: tree native
//!   Time (mean ± σ):     818.9 ms ±  35.4 ms    [User: 188.1 ms, System: 270.0 ms]
//!   Range (min … max):   755.1 ms … 871.6 ms    10 runs
//!
//! $ # Measure native with caching enabled
//! $ hyperfine --warmup 5 --prepare "" "tree native" -m 10
//! Benchmark 1: tree native
//!   Time (mean ± σ):     295.0 ms ±   2.4 ms    [User: 168.1 ms, System: 111.4 ms]
//!   Range (min … max):   291.0 ms … 299.1 ms    10 runs
//! ```
//!
//! Recursive copy of the entire file-system takes *10.7 seconds* without cahing
//! and *14.29 seconds* with caching. The same operations take *9.26 seconds*
//! and *12.08 seconds* respectively on native file-system (ext4).
//!
//! ```bash
//! $ # Measure copy without caching
//! $ hyperfine --warmup 5 --prepare "rm -rf m1; echo 3 | sudo tee -a /proc/sys/vm/drop_caches; sync; sleep 1; sync; sleep 1; sync; sleep 1" \
//!   "cp -r m m1 || echo ok" -m 10
//! Benchmark 1: cp -r m m1 || echo ok
//!   Time (mean ± σ):     10.705 s ±  0.485 s    [User: 0.174 s, System: 3.294 s]
//!   Range (min … max):    9.942 s … 11.784 s    10 runs
//!
//! $ # Measure copy with caching
//! $ hyperfine --warmup 5 --prepare "rm -rf m1" "cp -r m m1 || echo ok" -m 10
//! Benchmark 1: cp -r m m1 || echo ok
//!   Time (mean ± σ):     14.293 s ±  1.025 s    [User: 0.203 s, System: 3.545 s]
//!  Range (min … max):   12.974 s … 16.379 s    10 runs
//!
//! $ # Measure native copy without caching.
//! $ hyperfine --warmup 5 --prepare "rm -rf m1; echo 3 | sudo tee -a /proc/sys/vm/drop_caches; sync; sleep 1; sync; sleep 1; sync; sleep 1" \
//!  "cp -r native m1 || echo ok" -m 10
//! Benchmark 1: cp -r native m1 || echo ok
//!   Time (mean ± σ):      9.266 s ±  0.332 s    [User: 0.171 s, System: 3.583 s]
//!   Range (min … max):    8.863 s …  9.995 s    10 runs
//!
//! $ # Measure native copy with caching
//! $ hyperfine --warmup 5 --prepare "rm -rf m1" "cp -r native m1 || echo ok" -m 10
//! Benchmark 1: cp -r native m1 || echo ok
//!   Time (mean ± σ):     12.085 s ±  1.039 s    [User: 0.168 s, System: 3.838 s]
//!   Range (min … max):   10.765 s … 14.273 s    10 runs

//! ```

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
