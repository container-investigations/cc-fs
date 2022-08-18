//! Provide sha256 digest computation using sha2 crate.
//!
//! The main rationale for the existence of this modules is to allow saving
//! intermediate states of sha256 computation. Intermediate states are useful
//! in implementing integrity enforced file-systems directly on top of OCI layer
//! tar files.
use std::slice;

use anyhow::{anyhow, Result};
use generic_array::{typenum::U64, GenericArray};
use serde::{Deserialize, Serialize};
use sha2::compress256;

/// Intermediate state of sha256 computation. 256 bits.
/// See [Comparison of SHA functions](https://en.wikipedia.org/wiki/SHA-2#Comparison_of_SHA_functions)
pub type State = [u32; 8];

/// Hasher computes the sha256 sum of a byte stream.
///
/// Intermediate states can be selectively saved before and after processing
/// a chunk of data (typically a page). Integrity can be later verified by
/// loading the `before` state, processing the chunk again and then checking that
/// the state matches the saved `after` state.
#[derive(Serialize, Deserialize, Debug, Default)]
pub struct Hasher {
    /// Set of saved intermediate states.
    states: Vec<State>,

    /// Current state.
    state: State,

    /// Length of processed data.
    len: u64,

    /// Computed sha256 sum.
    pub digest: String,
}

impl Hasher {
    /// Create a new Hasher instance.
    ///
    /// # Arguments
    /// * `hint_num_states` - Expected number of intermediate states.
    ///    A reasonable approximation is file-size divided by 4096.
    pub fn new(hint_num_states: u32) -> Result<Hasher> {
        Ok(Hasher {
            states: Vec::with_capacity(hint_num_states as usize),
            // Initialize state to sha256 initial values.
            state: [
                0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f,
                0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
            ],
            len: 0,
            digest: String::from(""),
        })
    }

    #[doc(hidden)]
    /// Process a given chunk of data.
    ///
    /// # Arguments
    /// * `buf` : Chunk of data. Length must be multiple of 64 bytes (512 bits).
    fn compress(state: &mut State, buf: &[u8]) -> Result<()> {
        // TODO: Can this be turned into a compile-time check?
        if buf.len() % 64 != 0 {
            return Err(anyhow!("buffer size must be multiple of 32"));
        }
        unsafe {
            // Cast the slice into a generic array.
            let raw_ptr = buf as *const _ as *const GenericArray<u8, U64>;
            let slice = slice::from_raw_parts(raw_ptr, buf.len() / 64);

            // Call sha2 crate's compress function.
            compress256(state, slice);
        }
        Ok(())
    }

    /// Save the current state.
    ///
    /// This function is expected to be called at the start of the file, before
    /// each page within the file, and after the end of the file.
    ///
    /// # Example
    /// ```
    /// hasher.save_state(); // Start of file.
    /// let mut buf = [0u8; 4096];
    /// for _i in file.len() / 4096 {
    ///   // Read page.
    ///   file.read_exact(&mut buf)?;
    ///   // Measure page and save hash state.
    ///   hasher.measure(&buf);
    ///   hasher.save_state();
    /// }
    /// // Read remaining bytes in file.
    /// let remaining = buf.len() % 4096;
    /// file.read_exact(&mut buf[0..remaining]);
    ///
    /// // Pad with zeros to page boundary.
    /// for i in remaining..4096 {
    ///   buf[i] = 0;  
    /// }
    ///
    /// // Measure last page and save state.
    /// hasher.measure(&buf);
    /// hasher.save_state();
    /// ```
    pub fn save_state(&mut self) -> u32 {
        self.states.push(self.state);
        self.states.len() as u32 - 1
    }

    /// Measure a given chunk of data.
    ///
    /// # Arguments
    /// * `buf` : Chunk of data. Length must be multiple of 64 bytes (512 bits).
    pub fn measure(&mut self, buf: &[u8]) -> Result<()> {
        // Measure slice and update length of processed data.
        Hasher::compress(&mut self.state, buf)?;
        self.len += buf.len() as u64;
        Ok(())
    }

    /// Finalize the sha256 computation.
    ///
    /// This involves appending a 1 bit, followed by padding 0 bits, followed by
    /// the length in bits of processed data as a u64 such that the total length
    /// of the bit stream is a multiple of 512.
    ///
    /// See [SHA-2](https://en.wikipedia.org/wiki/SHA-2#Pseudocode).
    ///
    /// TODO: Consume the hasher object after finalization.
    pub fn finalize(&mut self) -> Result<&String> {
        // The data processed so far is a multiple of 64 bytes.
        // Add another 64 bytes to the stream.
        let mut buf = [0u8; 64];

        // Add a 1 bit.
        buf[0] = 0x80;

        // Append length to the stream.
        let bits = self.len * 8 as u64;
        buf[56] = ((bits >> (8 * 7)) & 0xff) as u8;
        buf[57] = ((bits >> (8 * 6)) & 0xff) as u8;
        buf[58] = ((bits >> (8 * 5)) & 0xff) as u8;
        buf[59] = ((bits >> (8 * 4)) & 0xff) as u8;
        buf[60] = ((bits >> (8 * 3)) & 0xff) as u8;
        buf[61] = ((bits >> (8 * 2)) & 0xff) as u8;
        buf[62] = ((bits >> (8 * 1)) & 0xff) as u8;
        buf[63] = ((bits >> (8 * 0)) & 0xff) as u8;

        // Measure this chunk.
        self.measure(&buf)?;

        // Convert the state to hex representation to obtain the digest.
        let hash = self.state;
        self.digest = format!(
            "{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}",
            hash[0],
            hash[1],
            hash[2],
            hash[3],
            hash[4],
            hash[5],
            hash[6],
            hash[7]
        );

        Ok(&self.digest)
    }

    /// Verify the hash of a given chunk.
    ///
    /// Load the saved state at specified position, process the given chunk,
    /// and then check that the new state is equal to saves state at pos + 1.
    ///
    /// # Arguments
    /// * `pos` - The position of the `before` state for the chunk.
    /// * `buf` - Chunk of data. Length must be multiple of 64 bytes (512 bits).
    pub fn verify(&self, pos: u32, buf: &[u8]) -> Result<bool> {
        let mut state = self.states[pos as usize];
        Hasher::compress(&mut state, buf)?;
        Ok(state == self.states[pos as usize + 1])
    }
}
