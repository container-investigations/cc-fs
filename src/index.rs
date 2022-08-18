//! Representation of indexes of confidential container file-systems.
//!
//! An Index contains a set of Inodes representing the entries in a file-system,
//! and also the hash states for veryfying the integrity of the file-system.
//! The contents of each regular file in the file-system resides outside the index
//! and can be provided from original tar files of container layers or from files
//! in regular file-systems.
//!
//! An Index is optimized both for lookup as well as memory consumption. The inodes
//! are maintained in a sorted vec ordered by nesting depth, parent path, and name.
//! Each directory inode also holds the position of its first child in the vec, and
//! the number of children.
//!
//! Indexes are serialized/deserialized using [bincode](https://crates.io/crates/bincode)
//! which is a fast, compact binary format. Due to use of `serde` derive, use of many
//! other formats (cbor, messagepack, postcard, json) is possible.
use std::cmp::Ordering;
use std::fs::File;
use std::io::{BufReader, BufWriter};

use anyhow::{anyhow, Result};
use bincode::{deserialize_from, serialize_into};
use serde::{Deserialize, Serialize};

use crate::hash::Hasher;

/// Type of an item in the file-system.
#[derive(Serialize, Deserialize, Default, Debug, Clone)]
pub enum FileType {
    /// A file.
    /// The `before` and `after` hash state of each page in the file is saved in
    /// the Hasher and used to enfore integrity.
    #[default]
    RegularFile,

    /// Hard Link.
    ///
    /// See [Gnu Tar Hard Link](https://www.gnu.org/software/tar/manual/html_node/hard-links.html)
    HardLink,

    /// Symbolic link to another item.
    SymLink,

    /// A character device.
    CharDevice,

    /// A directory.
    Directory,
}

/// Infrequent properties of an item. Usually specified using PAX extensions.
#[derive(Serialize, Deserialize, Default, Debug, Clone)]
pub struct Extra {
    pub link: String,
    pub uname: String,
    pub gname: String,
    pub xattrs: Vec<(String, String)>,
}

/// Index node (Inode) of an item in file system.
#[derive(Serialize, Deserialize, Default, Clone, Debug)]
pub struct Inode {
    /// File type.
    pub typeflag: FileType,

    /// Name of the item.
    pub name: String,

    /// Path of the directory containing the item.
    /// The parent path must begin and end with '/'.
    pub parent: String,

    // Stat fields.
    pub size: u32,
    pub uid: u32,
    pub gid: u32,
    pub mode: u32,
    pub mtime: u64,

    /// Infrequently occuring properties.
    pub extra: Option<Extra>,

    /// The inode number of this inode.
    pub num: u32,

    /// Index of starting hash state.
    pub hash_index: u32,

    /// Inode number of first child.
    pub child_inode: u32,

    /// Number of (direct) children.
    pub num_children: u32,

    /// 512-block offset of the file in the backing tar file.
    /// Meaningful only for regular files.
    pub offset: u32,

    /// The nesting level of this inode.
    pub depth: u16,

    /// Number of hard links to this inode.
    pub links: u16,

    /// Inode number of hard-link target.
    pub target_ino: u32,
}

/// Implementation.
impl Inode {
    /// Check whether the inode has given path.
    pub fn path_eq(&self, path: &String) -> bool {
        // Unless the path is "/", remove trailing '/'.
        let path = if path.ends_with("/") && path.len() > 1 {
            &path[0..path.len() - 1]
        } else {
            &path[0..]
        };

        // Check length, name and parent.
        (path.len() == self.name.len() + self.parent.len())
            && self.name.eq(&path[self.parent.len()..])
            && self.parent.eq(&path[0..self.parent.len()])
    }
}

/// Index of a confidential container file-system.
#[derive(Serialize, Deserialize, Default, Debug, Clone)]
pub struct Index {
    /// List of inodes.
    pub inodes: Vec<Inode>,

    /// Hasher instance for integrity verification.
    pub hasher: Hasher,
}

/// Implemenation of Index.
impl Index {
    /// Create a new Index instance.
    ///
    /// # Arguments
    /// * `hint_num_inodes` - Reserve memory for so many inodes.
    /// * `hint_num_states` - Estimated number of intermediate hash states.
    pub fn new(hint_num_inodes: u32, hint_num_states: u32) -> Result<Index> {
        Ok(Index {
            inodes: Vec::<Inode>::with_capacity(hint_num_inodes as usize),
            hasher: Hasher::new(hint_num_states)?,
        })
    }

    /// Write the index to given file. Overwrites existing file.
    ///
    /// # Arguments
    /// * `path` - Path of file to write.
    /// * `returns` - Number of bytes written.
    pub fn to_file(&self, path: &String) -> Result<u64> {
        let file = &File::create(path)?;
        serialize_into(BufWriter::new(file), self)?;
        Ok(file.metadata().unwrap().len())
    }

    /// Read index from given file.
    ///
    /// # Arguments
    /// * `path` - Path of index file.
    pub fn from_file(path: &String) -> Result<Index> {
        let mut index: Index =
            deserialize_from(&mut BufReader::new(&File::open(path)?))?;

        // Give up an extra reserved memory.
        index.hasher.shrink_to_fit();
        index.inodes.shrink_to_fit();
        Ok(index)
    }

    /// Compare two inodes.
    ///
    /// Ordering is done using first the depth, then the parent path length,
    /// then the parent path, and then the name.
    fn cmp_inodes(a: &Inode, b: &Inode) -> Ordering {
        // Compare depths first.
        match a.depth.cmp(&b.depth) {
            Ordering::Equal => {
                // Compare parent lengths.
                match a.parent.len().cmp(&b.parent.len()) {
                    Ordering::Equal => {
                        // Compare parents.
                        match a.parent.cmp(&b.parent) {
                            // Compare names.
                            Ordering::Equal => a.name.cmp(&b.name),
                            o => o,
                        }
                    }
                    o => o,
                }
            }
            o => o,
        }
    }

    /// Find inode with given path in a slice of inodes.
    ///
    /// # Arguments
    /// * `path` - Path to search for.
    /// * `start_ino` - Starting inode number in slice to look for.
    /// * `end_ino` - Ending inode number in slice to look for.
    /// * `returns` - Position of the inode in full vector.
    pub fn find(
        &self,
        path: &String,
        start_ino: usize,
        end_ino: usize,
    ) -> Result<usize> {
        // If path is empty or "/" return the root inode.
        if path.eq("/") || path.len() == 0 {
            return Ok(1);
        }

        // Remove trailing '/'.
        let path = if path.ends_with("/") {
            &path[0..path.len() - 1]
        } else {
            &path[0..]
        };

        // Find parent and name from path.
        let p = path.rfind("/").ok_or(anyhow!("{} not found", path))?;
        let parent = path[0..p + 1].to_string();
        let inode = Inode {
            name: path[p + 1..].to_string(),
            depth: (parent.split("/").count() - 1) as u16,
            parent: parent,
            ..Inode::default()
        };

        // TODO: Alternative: Try searching from root, path part by part.
        // Perform binary search in slice.
        let v = &self.inodes[start_ino as usize..end_ino as usize];
        match v.binary_search_by(|a| Index::cmp_inodes(a, &inode)) {
            // Return index in original vector.
            Ok(p) => Ok(start_ino + p),
            _ => Err(anyhow!("{} not found", path)),
        }
    }

    /// Recursively fetch the target of a hard link.
    ///
    /// # Arguments
    /// * `ino` - Inode number of the link node.
    ///
    /// Returns the inode number of link target. If the link is invalid,
    /// return 0. Returns input inode number if the inode is not a hard link.
    pub fn get_hard_link_target(&self, ino: u32) -> u32 {
        let mut ino = ino as usize;
        loop {
            match (&self.inodes[ino].extra, &self.inodes[ino].typeflag) {
                (Some(e), FileType::HardLink) => {
                    // For hard links, ensure that link starts with "/"
                    let link = if e.link.starts_with('/') {
                        e.link.to_string()
                    } else {
                        "/".to_owned() + &e.link
                    };
                    match self.find(&link, 0, self.inodes.len()) {
                        // Resolve link recursively.
                        Ok(p) => ino = p,
                        // Invalid link
                        _ => return 0,
                    }
                }
                // Not a link.
                _ => break,
            };
        }

        // Return ino of the inode that was not a hard-link.
        ino as u32
    }

    /// Process index for use in mounting file-systems.
    ///
    /// Processing involves the following steps.
    ///  - Sort inodes in lexicographical order of depth, parent length, parent
    ///    and name.
    ///  - For each directory inode, find the index of the first child, as
    ///    well as the number of children.
    ///  - For each hard-link, increment the link count of the target and hold
    pub fn process(&mut self) -> Result<()> {
        // Sort the inodes.
        self.inodes.sort_by(Index::cmp_inodes);

        // Start with the root node as the current parent.
        let mut cur_parent = 1;
        // The child of the root node immediately follows it.
        self.inodes[1].child_inode = 2;

        // Process each subsequent node.
        for i in 2..self.inodes.len() {
            // Check whether the node's parent path is current parent.
            if self.inodes[cur_parent].path_eq(&self.inodes[i].parent) {
                // This node is also a child of the current parent.
            } else {
                // Find index of parent. The parent needs to be searched only
                // in the slice preceeding the current node.
                cur_parent = self.find(&self.inodes[i].parent, 1, i)?;

                // Assert that the parent's child has not been determined.
                assert!(self.inodes[cur_parent].child_inode == 0);

                // Record first child.
                self.inodes[cur_parent].child_inode = i as u32;
            }

            // Increment child count.
            self.inodes[cur_parent].num_children += 1;
        }

        // Set number of links of root node to 2 ('.' and '..')
        self.inodes[1].links = 2;

        // Process each hard link.
        for i in 2..self.inodes.len() as u32 {
            // Set number of links to 1.
            self.inodes[i as usize].links = 1;

            // If this inode is a hard-link, fetch the target.
            let ino = self.get_hard_link_target(i);
            if ino > 0 && ino != i {
                // Increment link count of the target.
                self.inodes[ino as usize].links += 1;

                // Use the child_inode field to point to target.
                self.inodes[i as usize].target_ino = ino;
            }
        }

        Ok(())
    }
}
