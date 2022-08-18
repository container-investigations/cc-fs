//! Parse and index tar files.
//!
//! See [Tar Format](https://www.ibm.com/docs/en/zos/2.1.0?topic=formats-tar-format-tar-archives) for description of each field of the tar header.
use std::fs::File;
use std::io::{BufReader, Read};
use std::mem;
use std::slice;
use std::str;

use anyhow::{anyhow, Context, Result};

use crate::index::*;

/// Tar header binary compatible with Posix specification.
/// See [UStar format](https://en.wikipedia.org/wiki/Tar_(computing)#UStar_format)
#[repr(C)]
#[derive(Debug)]
struct PosixHeader {
    /// File name. Maximum 100 characters. Null terminated.
    name: [u8; 100],

    /// File mode (octal).
    mode: [u8; 8],

    /// Owner user ID (octal).
    uid: [u8; 8],

    /// Owner group ID (octal).
    gid: [u8; 8],

    /// File size in bytes (octal).
    /// Size is zero if the header describes a link.
    size: [u8; 12],

    /// Last modification time in Unix time format (octal).
    mtime: [u8; 12],

    /// Checksum of all the bytes in the header (with blank chksum field).
    /// Ignored.
    chksum: [u8; 8],

    /// Type of the file.
    /// Supported values are:
    ///
    /// | Value            | Meaning             |
    /// |------------------|---------------------|
    /// | '0' or ASCII NUL | Normal file         |
    /// | '1'              | Hard Link           |
    /// | '3'              | Character Device    |
    /// | '4'              | Block Device        |
    /// | '5'              | Directory           |
    /// | 'x'              | PAX Extended Header |
    ///
    typeflag: u8,

    /// Target of a link. Maximum 100 characters.
    // Null terminated unless the name takes the full field.
    linkname: [u8; 100],

    /// Format indicator. E.g USTAR. Null terminated.
    magic: [u8; 6],

    /// Format version number.
    version: [u8; 2],

    /// Owner user name. Maximum 32 characters. Null terminated.
    uname: [u8; 32],

    /// Owner group name. Maximum 32 characters. Null terminated.
    gname: [u8; 32],

    /// Device major number. Octal.
    devmajor: [u8; 8],

    /// Device minor number. Octal.
    devminor: [u8; 8],

    /// Filename prefix. 155 characters. Thus allowing maximum 255 character long names.
    /// Null terminated unless the name takes the full field.
    /// Prefix is null unless the name exceeds 100 characters.
    prefix: [u8; 155],

    /// Padding for 512 byte alignment.
    padding: [u8; 12],
}

/// Parse ascii octal number.
/// A trailing null indicates end of the octal number.
fn ascii_octal_to_u64(buf: &[u8]) -> Result<u64> {
    let mut n: u64 = 0;

    for c in buf {
        let ch = *c;
        if ch >= b'0' && ch <= b'7' {
            n = n * 8 + (ch - b'0') as u64;
        } else if *c == 0 {
            break;
        } else {
            return Err(anyhow!("illegal octal character {0}", c));
        }
    }
    Ok(n)
}

/// Parse ascii decimal number.
/// A trailing null indicates end of the decimal number.
fn ascii_decimal_to_u64(buf: &[u8]) -> Result<u64> {
    let mut n: u64 = 0;

    for c in buf {
        let ch = *c;
        if ch >= b'0' && ch <= b'9' {
            n = n * 10 + (ch - b'0') as u64;
        } else if *c == 0 {
            break;
        } else if *c == b'.' {
            return Err(anyhow!("floating point is unsupported."));
        } else {
            return Err(anyhow!("illegal decimal character {0}", c));
        }
    }
    Ok(n)
}

#[doc(hidden)]
/// Extend one tar string with another.
fn extend(dest: &mut Vec<u8>, src: &[u8]) {
    for ch in src.iter() {
        if *ch != 0 {
            dest.push(*ch);
        } else {
            break;
        }
    }
}

/// Parses a tar file and creates an index.
pub struct Parser {
    /// Tar file reader with buffering.
    /// The contents of the file are read only once, in order.
    reader: BufReader<File>,

    /// Current Posix tar header.
    header: PosixHeader,

    /// Size of the current item.
    size: u64,

    /// Size rounded up to 512 byte boundary.
    rsize: u64,

    /// The current Inode.
    inode: Inode,

    /// Extra properties of current inode.
    extra: Extra,

    /// Buffer for reading data.
    buf: Vec<u8>,

    /// File-system index
    index: Index,

    /// Current offset within the tar file.
    offset: u32,
}

impl Parser {
    /// Create new instance of Parser.
    ///
    /// The number of pages in the file is used as a hint to the hasher.
    /// A formula derived from oetools-20.04 container's largest layer is
    /// used to estimate the number of inodes.
    pub fn new(tar_path: &String) -> Result<Parser> {
        let file = File::open(tar_path)
            .with_context(|| format!("failed to open {}", tar_path))?;

        let len = file.metadata().unwrap().len();

        // TODO: Find better hints.
        // We may end up with slightly more states than the actual number of
        // pages. Therefore, use a factor (1.16).
        let hint_num_states = ((len as f64 * 1.16 + 4096.0) / 4096.0) as u32;

        // Starting out with 0 hint has been observed to use less memory than
        // various hint values.
        let hint_num_inodes = 0;

        Ok(Parser {
            reader: BufReader::new(file),
            // Use unsafe to zero-initialize since Default trait is not
            // automatically implemented for arrays longer than 32 elements.
            header: unsafe { std::mem::zeroed() },
            size: 0,
            rsize: 0,
            inode: Inode::default(),
            extra: Extra::default(),
            buf: vec![],
            index: Index::new(hint_num_inodes, hint_num_states)?,
            offset: 0,
        })
    }

    /// Parse the tar file and generate index.
    pub fn parse(&mut self) -> Result<Index> {
        let header_size = mem::size_of::<PosixHeader>();

        // Root node.
        let root = Inode {
            typeflag: FileType::Directory,
            name: String::from("/"),
            parent: String::from(""),
            mode: 0o755,
            links: 2,
            ..Inode::default()
        };

        // Add two root nodes so that inode indexes for items in tar start from 1.
        self.index.inodes.push(root.clone());
        self.index.inodes.push(root);

        loop {
            // Read and measure header.
            unsafe {
                let raw_ptr = &mut self.header as *mut _ as *mut u8;
                let slice = slice::from_raw_parts_mut(raw_ptr, header_size);
                match self.reader.read_exact(slice) {
                    // If read is successful, measure header.
                    Ok(_) => self.index.hasher.measure(slice)?,
                    _ => break,
                }
                // Update offset.
                self.offset += 512;
            }

            // Parse header size and round it up to multiple of 512 bytes.
            self.size = ascii_octal_to_u64(&self.header.size)?;
            self.rsize = ((self.size + 512 - 1) / 512) * 512;

            // Handle different file types.
            match self.header.typeflag {
                // Process PAX extensions.
                b'x' => {
                    self.parse_pax()?;
                }

                // Process GNU extensions.
                b'L' | b'K' => {
                    self.parse_gnu(self.header.typeflag == b'L')?;
                }

                // Process items that exist only in tar.
                b'0' | b'1' | b'2' | b'5' => self.parse_item()?,

                // End of tar marker
                0 => continue,

                // Unsupported.
                _ => {
                    return Err(anyhow!(
                        "unsupported typeflag {}",
                        char::from(self.header.typeflag)
                    ))
                }
            }

            // Update offset.
            self.offset += self.rsize as u32;
        }

        // Finalize the hash.
        self.index.hasher.finalize()?;

        // Transfer ownership to caller.
        Ok(std::mem::replace(&mut self.index, Index::default()))
    }

    /// Split a path into filename and directory.
    ///
    /// Removes any trailing '/' from the name component.
    /// The directory component will start and end with '/'.
    fn split_path(path: &[u8]) -> Result<(String, String)> {
        let mut path = str::from_utf8(path)?.to_string();
        // Remove trailing '/'.
        if path.ends_with("/") {
            path.pop();
        }

        // Split at right most '/' character.
        let (parent, name) = match path.rfind("/") {
            Some(p) => (path[0..p + 1].to_string(), path[p + 1..].to_string()),
            _ => (String::from("/"), path.to_string()),
        };

        if !parent.starts_with("/") {
            Ok(("/".to_owned() + &parent, name))
        } else {
            Ok((parent, name))
        }
    }

    /// Parse pax extensions.
    ///
    /// PAX Extended header records (typeflag 'x') are supported. These headers
    /// affect the following file in the archive.
    /// Supported tags: mtime, path, linkpath, uname, gname, size, uid, gid.
    /// Not supported: Character set definition tag, vendor specifi tags,
    ///                PAX Global extended header records (typeflag 'g').
    /// See [PAX extended header](https://www.ibm.com/docs/en/zos/2.1.0?topic=SSLTBW_2.1.0/com.ibm.zos.v2r1.bpxa500/paxex.htm#paxex)
    /// and [PAX Header Block](https://www.ibm.com/docs/en/zos/2.1.0?topic=SSLTBW_2.1.0/com.ibm.zos.v2r1.bpxa500/paxhead.htm).
    fn parse_pax(&mut self) -> Result<()> {
        // Read pax data and measure it.
        self.buf.resize(self.rsize as usize, 0);
        self.reader.read_exact(&mut self.buf)?;
        self.index.hasher.measure(&self.buf)?;

        // Skip past next occurence of given character.
        let mut p = 0;
        let mut skip_next = |buf: &Vec<u8>, ch| {
            while p < buf.len() && buf[p] != ch {
                p += 1;
            }
            p += 1;
            return p;
        };

        loop {
            // Skip size entry to obtain field name start.
            let name_start = skip_next(&self.buf, b' ');
            // Skip = to obtain field name end.
            let name_end = skip_next(&self.buf, b'=') - 1;

            let value_start = name_end + 1;
            // Skip \n to obtain value end.
            let value_end = skip_next(&self.buf, b'\n') - 1;

            // Check parse error.
            if value_end >= self.buf.len() {
                return Err(anyhow!(
                    "failed to parse pax entry\n{}",
                    str::from_utf8(&self.buf)?
                ));
            }

            let field = str::from_utf8(&self.buf[name_start..name_end])?;
            let value = &self.buf[value_start..value_end];
            match field {
                // See pax Extended Header File Times
                // https://pubs.opengroup.org/onlinepubs/9699919799/utilities/overrides.html#tag_20_92_13_05
                "path" => {
                    (self.inode.parent, self.inode.name) =
                        Parser::split_path(&value)?
                }
                "gid" => self.inode.gid = ascii_octal_to_u64(value)? as u32,
                "uid" => self.inode.uid = ascii_octal_to_u64(value)? as u32,
                "mtime" => self.inode.mtime = ascii_decimal_to_u64(value)?,
                "gname" => {
                    self.extra.gname = str::from_utf8(value)?.to_string()
                }
                "uname" => {
                    self.extra.uname = str::from_utf8(value)?.to_string()
                }
                "linkpath" => {
                    self.extra.link = str::from_utf8(value)?.to_string()
                }
                _ => {
                    return Err(anyhow!("unsupported pax field {}", field));
                }
            };

            // Break if all the fields have been parsed.
            if value_end + 1 == self.buf.len() || self.buf[value_end + 1] == 0 {
                break;
            }
        }

        Ok(())
    }

    /// Parse GNU LongLink and LongName headers.
    fn parse_gnu(&mut self, is_long_name: bool) -> Result<()> {
        // Resize buf, read and measure string.
        self.buf.resize(self.rsize as usize, 0u8);
        self.reader.read_exact(&mut self.buf)?;
        self.index.hasher.measure(&self.buf)?;

        if is_long_name {
            (self.inode.parent, self.inode.name) =
                Parser::split_path(&self.buf[0..self.size as usize])?;
        } else {
            self.extra.link =
                str::from_utf8(&self.buf[0..self.size as usize])?.to_string()
        }

        Ok(())
    }

    /// Parse tar entry header.
    /// PAX and GNU overrides are preferred over fields from header.
    fn parse_header(&mut self) -> Result<()> {
        // Read fields from header if not already populated by PAX/GNU
        // extensions.
        if self.inode.gid == 0 {
            self.inode.gid = ascii_octal_to_u64(&self.header.gid)? as u32;
        }

        if self.inode.uid == 0 {
            self.inode.uid = ascii_octal_to_u64(&self.header.uid)? as u32;
        }

        if self.inode.mtime == 0 {
            self.inode.mtime = ascii_octal_to_u64(&self.header.mtime)?;
        }

        if self.header.gname[0] != 0 && self.extra.gname.is_empty() {
            // gname is null terminated.
            self.extra.gname = String::from_utf8(self.header.gname.to_vec())?;
        }

        if self.header.uname[0] != 0 && self.extra.uname.is_empty() {
            // uname is null terminated.
            self.extra.uname = String::from_utf8(self.header.uname.to_vec())?;
        }

        // Set size of inode. The PAX size extension is not supported since we
        // don't expect a single large file in layers (for now).
        self.inode.size = self.size as u32;

        if self.inode.name.len() == 0 {
            self.buf.clear();
            // Add prefix
            if self.header.prefix[0] != 0 {
                extend(&mut self.buf, &self.header.prefix);
                self.buf.push(b'/');
            }

            extend(&mut self.buf, &self.header.name);
            (self.inode.parent, self.inode.name) =
                Parser::split_path(&self.buf)?;
        }

        // Figure out depth. `depth` is used for optimized binary search.
        self.inode.depth = (self.inode.parent.split("/").count() - 1) as u16;

        // Symbolic links or link to another archived file.
        if self.header.linkname[0] != 0 && self.extra.link.is_empty() {
            self.buf.clear();
            extend(&mut self.buf, &self.header.linkname);
            self.extra.link = str::from_utf8(&self.buf)?.to_string();
        }

        self.inode.mode = ascii_octal_to_u64(&self.header.mode)? as u32;

        if !self.extra.link.is_empty()
            || !self.extra.uname.is_empty()
            || !self.extra.gname.is_empty()
            || !self.extra.xattrs.is_empty()
        {
            self.inode.extra =
                Some(std::mem::replace(&mut self.extra, Extra::default()));
        }

        Ok(())
    }

    /// Parse a tar item.
    fn parse_item(&mut self) -> Result<()> {
        // Parse the header.
        self.parse_header()?;

        self.inode.typeflag = match self.header.typeflag {
            b'0' => FileType::RegularFile,
            b'1' => FileType::HardLink,
            b'2' => FileType::SymLink,
            b'5' => FileType::Directory,
            _ => {
                return Err(anyhow!(
                    "unsupported typeflag {}",
                    self.header.typeflag
                ))
            }
        };

        // Save the hash state prior to start of file.
        if self.header.typeflag == b'0' {
            self.inode.hash_index = self.index.hasher.save_state();
            self.inode.offset = self.offset / 512;
        }

        // Hash the contents in blocks.
        let mut buf = [0u8; 4096];
        for _i in 0..self.rsize as usize / buf.len() {
            self.reader.read_exact(&mut buf)?;
            self.index.hasher.measure(&buf)?;
            self.index.hasher.save_state();
        }

        // Round remaining bytes to 512 alignment.
        let remaining = ((self.rsize % 4096 + 511) / 512) * 512;
        if remaining > 0 {
            let buf = &mut buf[0..remaining as usize];
            self.reader.read_exact(buf)?;
            self.index.hasher.measure(&buf)?;
            self.index.hasher.save_state();
        }

        self.index
            .inodes
            .push(std::mem::replace(&mut self.inode, Inode::default()));

        Ok(())
    }
}

/// Create confidential container file-system index for given tar file/folder.
///
/// The tar file/folder is indexed and its digest is computed. If the computed
/// digest does not match the expected value failure is raised.
///
/// # Arguments
/// * `digest` - Expected digest value.
///    The digest should contain just the hex representation of the sha256
///    hash without any leading `sha256:` prefix.
/// * `path` - Path to tar file or folder.
pub fn index(digest: &Option<String>, path: &String) -> Result<()> {
    // Parse the tar file.
    let mut parser = Parser::new(path)?;
    let index = parser.parse()?;

    match &digest {
        Some(digest) if index.hasher.digest.ne(digest) => {
            return Err(anyhow!(
                "{}: Computed digest {} != supplied digest {}",
                path,
                index.hasher.digest,
                digest
            ));
        }
        _ => (),
    }

    // Write index to file.
    let index_file_name = &match path.split("/").last() {
        Some(f) => f.to_owned() + ".index",
        _ => return Err(anyhow!("invalid path {}", path)),
    };

    let bytes = index.to_file(&index_file_name)?;
    println!("wrote {}, size = {} bytes", index_file_name, bytes);

    Ok(())
}
