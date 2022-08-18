//! Fuse-based confidential container file-system backed by tar files or folders.
use std::cmp::min;
use std::ffi::OsStr;
use std::fs::File;
use std::os::unix::fs::FileExt;
use std::time::{Duration, UNIX_EPOCH};

use anyhow::Result;

use fuser::{
    FileAttr, FileType, Filesystem, MountOption, ReplyAttr, ReplyData,
    ReplyDirectory, ReplyEntry, ReplyOpen, Request,
};
use libc::{ENAMETOOLONG, ENOENT};

use crate::index::{self, *};

/// Maximum permitted length of a name.
const MAX_NAME_LENGTH: u32 = 255;

/// FUSE file system with integrity protection backed by a tar file.
struct CcFs {
    /// Index for the tar file.
    index: Index,

    /// Tar file backing store for the layer.
    tar: File,

    /// The next available file handle.
    next_file_handle: u64,
}

impl CcFs {
    /// Create a new CcFs instance backed by a tar file.
    ///
    /// # Arguments
    /// * `index` - The index file to use for enforcing integrity.
    /// * `tar` - The tar file to use for file content backing store.
    pub fn new(index: &String, tar: &String) -> Result<CcFs> {
        let mut fs = CcFs {
            index: Index::from_file(&index)?,
            tar: File::open(tar)?,
            next_file_handle: 1,
        };

        // Process the index.
        fs.index.process()?;

        Ok(fs)
    }

    /// Map from CcFs FileType to FUSE FileType.
    ///
    /// # Arguments
    /// * `typeflag` - The CcFs FileType of the inode.
    ///
    fn to_file_type(typeflag: &index::FileType) -> FileType {
        match typeflag {
            index::FileType::RegularFile => FileType::RegularFile,
            index::FileType::Directory => FileType::Directory,
            index::FileType::SymLink => FileType::Symlink,
            index::FileType::HardLink => FileType::RegularFile,
            _ => panic!("unhandled typeflag {:#?}", typeflag),
        }
    }

    /// Fetch FUSE attributes for an inode.
    ///
    /// # Arguments
    /// * `ino` - Number of the inode.
    /// * `inode` - The inode.
    fn inode_to_attr(ino: u64, inode: &Inode) -> FileAttr {
        let mtime = UNIX_EPOCH + Duration::from_secs(inode.mtime);
        let size = match &inode.typeflag {
            // Show directory size as 4096
            index::FileType::Directory => 4096,
            index::FileType::SymLink => {
                if let Some(e) = &inode.extra {
                    e.link.len() as u64
                } else {
                    panic!("empty link")
                }
            }
            _ => inode.size as u64,
        };
        FileAttr {
            ino: ino,
            size: size,
            blocks: size / 4096,
            atime: mtime,
            mtime: mtime,
            ctime: mtime,
            crtime: mtime,
            kind: CcFs::to_file_type(&inode.typeflag),
            perm: inode.mode as u16,
            nlink: inode.links as u32,
            uid: inode.uid,
            gid: inode.gid,
            rdev: 0,  // TODO
            flags: 0, // MacOS only
            blksize: 4096,
        }
    }
}

/// Time to retain lookups for.
/// Larger values result in faster file-system performance.
/// Default value is 1 seconds, consistent with libfuse.
const TTL: Duration = Duration::new(1, 0);

impl Filesystem for CcFs {
    /// Lookup a child with given name in the parent inode.
    ///
    /// # Arguments
    /// * `_req` - Request object. Unused.
    /// * `parent` - Inode number of the parent directory.
    /// * `name` - Name of the child.
    /// * `reply` - The ReplyEntry to populate.
    fn lookup(
        &mut self,
        _req: &Request,
        parent: u64,
        name: &OsStr,
        reply: ReplyEntry,
    ) {
        // Enforce name length.
        if name.len() > MAX_NAME_LENGTH as usize {
            reply.error(ENAMETOOLONG);
            return;
        }

        // Check that the parent is valid.
        let parent_usize = parent as usize;
        if parent_usize >= self.index.inodes.len() {
            reply.error(ENOENT);
            return;
        }

        // Ensure that name is a valid string.
        let name = match name.to_str() {
            Some(s) => s.to_string(),
            _ => {
                reply.error(ENOENT);
                return;
            }
        };

        // TODO: Handle `.` and `..`.

        // Fetch the parent node, and the starting and ending indices of
        // children.
        let inode = &self.index.inodes[parent_usize];
        let child_start = inode.child_inode as usize;
        let child_end = child_start + inode.num_children as usize;

        // Search for node within given name in the set of children.
        let children = &self.index.inodes[child_start..child_end];
        match children.binary_search_by(|a| a.name.cmp(&name)) {
            Ok(idx) => {
                let mut child_ino = (child_start + idx) as u32;
                // If the child node is a hard-link, resolve it.
                let resolved_ino = self.index.get_hard_link_target(child_ino);

                // A hard-link and its target must share the same inode.
                // Therefore, for hard-link, use the target's inode number as
                // well as the inode object.
                let child = if resolved_ino > 0 {
                    child_ino = resolved_ino;
                    &self.index.inodes[resolved_ino as usize]
                } else {
                    &self.index.inodes[child_ino as usize]
                };

                // Return data to FUSE.
                let attr = CcFs::inode_to_attr(child_ino as u64, child);
                reply.entry(&TTL, &attr, 0);
                return;
            }
            _ => (),
        }
        reply.error(ENOENT);
    }

    /// Get the attributes of a given inode.
    ///
    /// # Arguments
    /// * `_req` - Request object. Unused.
    /// * `ino` - Number of the inode.
    /// * `reply` - The ReplyAttr to populate.
    fn getattr(&mut self, _req: &Request, ino: u64, reply: ReplyAttr) {
        // Resolve hard-links.
        // TODO: This can likely be removed since the inode number of the link
        // is never passed to FUSE.
        let ino = self.index.get_hard_link_target(ino as u32) as u64;
        let ino_usize = ino as usize;

        // Ensure valid index.
        if ino_usize >= self.index.inodes.len() {
            reply.error(ENOENT);
            return;
        }

        // Return the attributes of the inode.
        let inode = &self.index.inodes[ino_usize];
        reply.attr(&TTL, &CcFs::inode_to_attr(ino, &inode))
    }

    /// Read the contents of a given directory.
    ///
    /// # Arguments
    /// * `_req` - Request object. Unused.
    /// * `ino` - The inode number of the directoy.
    /// * `_fh` - The file handle of the directory. Unused.
    /// * `offset` - A hint supplied to FUSE in previous readdir call.
    /// * `reply` - The ReplyDirectory to populate.
    ///
    /// The entries of the directory may not be read in a single readdir call.
    /// The strategy is to provide the `offset` of next child along with each
    /// child  until the buffer is full or there are no more children.
    /// The next readdir will be called back with the offset of the next child
    /// to read.
    fn readdir(
        &mut self,
        _req: &Request,
        ino: u64,
        _fh: u64,
        offset: i64,
        mut reply: ReplyDirectory,
    ) {
        // Ensure valid inode number.
        let ino_usize = ino as usize;
        if ino_usize >= self.index.inodes.len() {
            reply.error(ENOENT);
            return;
        }

        // Populate `.` and `..`.
        let inode = &self.index.inodes[ino_usize];
        if offset <= 2 {
            let _ = reply.add(ino, 2, FileType::Directory, ".");
            match self.index.find(&inode.parent, 0, ino as usize) {
                Ok(p) => reply.add(p as u64, 3, FileType::Directory, ".."),
                _ => panic!("Could not find parent."),
            };
        }

        // Loop through the child nodes. Begin processing only after specified
        // offset has been reached.
        for i in 0..inode.num_children as i64 {
            let o = i + 2;
            if o >= offset {
                // Get the child inode.
                let child_ino = inode.child_inode as usize + i as usize;
                let child = &self.index.inodes[child_ino];
                let kind = CcFs::to_file_type(&child.typeflag);
                // Try adding the child node.
                if reply.add(child_ino as u64, o + 1, kind, &child.name) {
                    // Failure indicates that the buffer is full.
                    break;
                }
            }
        }

        reply.ok();
    }

    /// Read a link.
    ///
    /// # Arguments
    /// * `_req` - Request object. Unused.
    /// * `ino` - The inode number of the link.
    /// * `reply` - The ReplyData to populate.
    fn readlink(&mut self, _req: &Request, ino: u64, reply: ReplyData) {
        // Ensure that the ino is valid.
        let ino_usize = ino as usize;
        if ino_usize >= self.index.inodes.len() {
            reply.error(ENOENT);
            return;
        }

        // Check whether the inode is a symlink.
        let inode = &self.index.inodes[ino_usize];
        if let index::FileType::SymLink = inode.typeflag {
            match &inode.extra {
                Some(e) => {
                    // Write out the link target as-is.
                    reply.data(&e.link.as_bytes());
                    return;
                }
                _ => (),
            };
        }
        reply.error(ENOENT);
    }

    /// Open a given inode.
    ///
    /// # Arguments
    /// * `_req` - Request object. Unused.
    /// * `ino` - The number of the inode.
    /// * `flags` - Flags to open. Unused.
    /// * `reply` - The ReplyData to populate.
    fn open(
        &mut self,
        _req: &Request,
        ino: u64,
        _flags: i32,
        reply: ReplyOpen,
    ) {
        // Ensure that the inode is valid.
        let ino_usize = ino as usize;
        if ino_usize >= self.index.inodes.len() {
            reply.error(ENOENT);
            return;
        }

        // TODO: Decide what to do with flags (e.g direct-io).
        // Generate a new handle number and return it.
        // TODO: Handle cc-passthrough scenario.
        let _inode = &self.index.inodes[ino_usize];
        let open_flags = 0;
        reply.opened(self.next_file_handle, open_flags);
        self.next_file_handle += 1;
    }

    /// Read bytes from given inode.
    ///
    /// # Arguments
    /// * `_req` - Request object. Unused.
    /// * `ino` - The inode number of the file.
    /// * `_fh` - File handle. Unused.
    /// * `offset` - The offset to read from.
    /// * `size` - Number of bytes to read.
    /// * `_flags` - Ignored.
    /// * `_lock_owner` - Ignored.
    /// * `reply` - The ReplyData to populate.
    fn read(
        &mut self,
        _req: &Request,
        ino: u64,
        _fh: u64,
        offset: i64,
        size: u32,
        _flags: i32,
        _lock_owner: Option<u64>,
        reply: ReplyData,
    ) {
        // Ensure that the inode is valid.
        let ino_usize = ino as usize;
        if ino_usize >= self.index.inodes.len() {
            reply.error(ENOENT);
            return;
        }

        // Ensure the the inode is a regular file.
        let inode = &self.index.inodes[ino_usize];
        match inode.typeflag {
            index::FileType::RegularFile => (),
            _ => {
                reply.error(ENOENT);
                return;
            }
        }

        // Clip size to file size.
        let size = min(size, inode.size);

        // Compute the end offset.
        let end = offset + size as i64;

        // Starting offset aligned to page boundary.
        let start = (offset / 4096) * 4096;

        // Bytes to read.
        let bytes = end - start;

        // Buffer size. Aligned to 512 byte-boundary.
        let buf_size = (bytes + 511) / 512 * 512;
        let mut buf = vec![0u8; buf_size as usize];

        // Offset within tar.
        let tar_offset = (inode.offset * 512 + start as u32) as u64;

        // Read bytes.
        let reader = &self.tar;
        let slice = &mut buf[0..bytes as usize];
        let _ = reader.read_exact_at(slice, tar_offset);

        // Send read bytes.
        reply.data(&slice[offset as usize % 4096..]);

        // Verify the pages.
        let mut page_num = start as u32 / 4096 + inode.hash_index;
        let mut pos = 0;
        while pos < buf.len() {
            let len = min(buf.len() - pos, 4096);
            match self.index.hasher.verify(page_num, &buf[pos..pos + len]) {
                Ok(true) => (),
                _ => panic!("integrity verification failed!"),
            }
            page_num += 1;
            pos += 4096;
        }
    }
}

/// Mount a Confidential Container file-system.
///
/// # Arguments
/// * `index` - Path of the index file.
/// * `tar` - The tar file which will act as the backing store.
/// * `mount_point` - The directory to mount to.
///
/// Mount currently only supports tar backed file-system. It is not too much
/// work to support a filtered passthrough file-system that will add integrity
/// protection to an existing directory.
pub fn mount(index: &String, tar: &String, mount_point: &String) -> Result<()> {
    let options = vec![
        MountOption::FSName("cc-fs".to_string()),
        // Enable permission checking in the kernel.
        // This avoids having to implement permissions checking in the file-system.
        MountOption::DefaultPermissions,
        // Read-only.
        MountOption::RO,
        // Honor set-user-id and set-groupd-id bits on files.
        MountOption::Suid,
        // Allow execution of binaries.
        MountOption::Exec,
        // Don't update inode access time.
        MountOption::NoAtime,
        // Async io.
        MountOption::Async,
    ];

    let tarfs = CcFs::new(index, tar)?;
    fuser::mount2(tarfs, mount_point, &options)?;
    Ok(())
}
