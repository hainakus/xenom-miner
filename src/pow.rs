use log::info;
use std::sync::Arc;
use std::time::{Duration, UNIX_EPOCH};
use kaspa_hashes::{Hash, PowHash};

use time::{macros::format_description, OffsetDateTime};


use crate::{
    pow::{
        hasher::{Hasher},

    },

    target::{self, Uint256},
    Error,
};
use pyrin_miner::Worker;
use crate::pow::hasher::HeaderHasher;
use crate::pow::matrix::Matrix;
use crate::proto::{RpcBlock, RpcBlockHeader};

pub(crate) mod hasher;

mod keccak;
mod xoshiro;
mod matrix;


#[derive(Clone, Debug)]
pub enum BlockSeed {
    FullBlock(Box<RpcBlock>),
    PartialBlock {
        id: String,
        header_hash: [u64; 4],
        timestamp: u64,
        nonce: u64,
        target: Uint256,
        nonce_mask: u64,
        nonce_fixed: u64,
        hash: Option<String>,
    },
}

impl BlockSeed {
    pub fn report_block(&self) {
        match self {
            BlockSeed::FullBlock(block) => {
                let block_hash =
                    block.block_hash().expect("We just got it from the state, we should be able to hash it");
                let format = format_description!("[year]-[month]-[day] [hour]:[minute]:[second]");
                let block_time = OffsetDateTime::from(
                    UNIX_EPOCH + Duration::from_millis(block.header.as_ref().unwrap().timestamp as u64),
                );
                info!(
                    "Found a block: {} (Timestamp: {})",
                    block_hash,
                    block_time.format(format).unwrap_or_else(|_| "unknown".to_string())
                );
            }
            BlockSeed::PartialBlock { .. } => info!("Found a share!"),
        }
    }
}

#[derive(Clone)]
pub struct State {
    pub id: usize,
    matrix: Arc<Matrix>,
    pub target: Uint256,
    pub pow_hash_header: [u8; 72],
    block: Arc<BlockSeed>,
    // PRE_POW_HASH || TIME || 32 zero byte padding; without NONCE
    hasher: PowHash,

    pub nonce_mask: u64,
    pub nonce_fixed: u64,
}



impl State {
    #[inline]
    pub fn new(id: usize, block_seed: BlockSeed) -> Result<Self, Error> {
        let pre_pow_hash;
        let header_timestamp: u64;
        let header_target;
        let nonce_mask: u64;
        let nonce_fixed: u64;
        match block_seed {
            BlockSeed::FullBlock(ref block) => {
                let header = &block.header.as_ref().ok_or("Header is missing")?;

                header_target = target::u256_from_compact_target(header.bits);
                let mut hasher = HeaderHasher::new();
                serialize_header(&mut hasher, header, true);
                pre_pow_hash = hasher.finalize();
                header_timestamp = header.timestamp as u64;
                nonce_mask = 0xffffffffffffffffu64;
                nonce_fixed = 0;
            }
            BlockSeed::PartialBlock {
                ref header_hash,
                ref timestamp,
                ref target,
                nonce_fixed: fixed,
                nonce_mask: mask,
                ..
            } => {
                let mut pow_hash = [0u8; 32];
                for (i, chunk) in header_hash.iter().enumerate() {
                    pow_hash[i*8..(i+1)*8].copy_from_slice(&chunk.to_le_bytes());
                }
                pre_pow_hash = Hash::from_bytes(pow_hash);
                header_timestamp = *timestamp;
                header_target = *target;
                nonce_mask = mask;
                nonce_fixed = fixed
            }
        }

        // PRE_POW_HASH || TIME || 32 zero byte padding || NONCE
        let hasher = PowHash::new(pre_pow_hash, header_timestamp);
        let matrix = Arc::new(Matrix::generate(pre_pow_hash));
        let mut pow_hash_header = [0u8; 72];

        pow_hash_header.copy_from_slice(
            [pre_pow_hash.as_bytes().as_slice(), header_timestamp.to_le_bytes().as_slice(), [0u8; 32].as_slice()]
                .concat()
                .as_slice(),
        );
        Ok(Self {
            id,
            matrix,
            target: header_target,
            pow_hash_header,
            block: Arc::new(block_seed),
            hasher,
            nonce_mask,
            nonce_fixed,
        })
    }



    pub fn check_pow(&self, nonce: u64) -> (bool, Uint256) {
        let pow = self.calculate_pow(nonce);
        // The pow hash must be less or equal than the claimed target.
        (pow <= self.target, pow)
    }

    #[inline(always)]
    pub fn generate_block_if_pow(&self, nonce: u64) -> Option<BlockSeed> {
        let (pow_valid, pow_hash) = self.check_pow(nonce);

        // If pow is valid, proceed with block generation
        if pow_valid {
            let mut block_seed = (*self.block).clone();

            match block_seed {
                BlockSeed::FullBlock(ref mut block) => {
                    let header = &mut block.header.as_mut().expect("We checked that a header exists on creation");
                    header.nonce = nonce;
                }
                BlockSeed::PartialBlock { nonce: ref mut header_nonce, ref mut hash, .. } => {
                    *header_nonce = nonce;
                    *hash = Some(format!("{:x}", pow_hash));  // Using the calculated pow hash
                }
            }

            Some(block_seed)  // Return the generated block seed
        } else {
            None  // If pow is not valid, return None
        }
    }

    pub fn calculate_pow(&self, nonce: u64) -> Uint256 {
        // Hasher already contains PRE_POW_HASH || TIME || 32 zero byte padding; so only the NONCE is missing
        let hash = self.hasher.clone().finalize_with_nonce(nonce);
        let hash = self.matrix.heavy_hash(hash);
        Uint256::from_le_bytes(hash.as_bytes())
    }
    pub fn load_to_gpu(&self, gpu_work: &mut dyn Worker) {
        gpu_work.load_block_constants(&self.pow_hash_header, &self.matrix.0, &self.target.0);
    }

    #[inline(always)]
    pub fn pow_gpu(&self, gpu_work: &mut dyn Worker) {
        gpu_work.calculate_hash(None, self.nonce_mask, self.nonce_fixed);
    }
}

#[cfg(not(any(target_pointer_width = "64", target_pointer_width = "32")))]
compile_error!("Supporting only 32/64 bits");

#[inline(always)]
pub fn serialize_header<H: Hasher>(hasher: &mut H, header: &RpcBlockHeader, for_pre_pow: bool) {
    let (nonce, timestamp) = if for_pre_pow { (0, 0) } else { (header.nonce, header.timestamp) };
    let num_parents = header.parents.len();
    let version: u16 = header.version.try_into().unwrap();
    hasher.update(version.to_le_bytes()).update((num_parents as u64).to_le_bytes());

    let mut hash = [0u8; 32];
    for parent in &header.parents {
        hasher.update((parent.parent_hashes.len() as u64).to_le_bytes());
        for hash_string in &parent.parent_hashes {
            decode_to_slice(hash_string, &mut hash).unwrap();
            hasher.update(hash);
        }
    }
    decode_to_slice(&header.hash_merkle_root, &mut hash).unwrap();
    hasher.update(hash);

    decode_to_slice(&header.accepted_id_merkle_root, &mut hash).unwrap();
    hasher.update(hash);
    decode_to_slice(&header.utxo_commitment, &mut hash).unwrap();
    hasher.update(hash);

    hasher
        .update(timestamp.to_le_bytes())
        .update(header.bits.to_le_bytes())
        .update(nonce.to_le_bytes())
        .update(header.daa_score.to_le_bytes())
        .update(header.blue_score.to_le_bytes());

    // I'm assuming here BlueWork will never pass 256 bits.
    let blue_work_len = (header.blue_work.len() + 1) / 2;
    if header.blue_work.len() % 2 == 0 {
        decode_to_slice(&header.blue_work, &mut hash[..blue_work_len]).unwrap();
    } else {
        let mut blue_work = String::with_capacity(header.blue_work.len() + 1);
        blue_work.push('0');
        blue_work.push_str(&header.blue_work);
        decode_to_slice(&blue_work, &mut hash[..blue_work_len]).unwrap();
    }

    hasher.update((blue_work_len as u64).to_le_bytes()).update(&hash[..blue_work_len]);

    decode_to_slice(&header.pruning_point, &mut hash).unwrap();
    hasher.update(hash);

}

#[allow(dead_code)] // False Positive: https://github.com/rust-lang/rust/issues/88900
#[derive(Debug)]
enum FromHexError {
    OddLength,
    InvalidStringLength,
    InvalidHexCharacter { c: char, index: usize },
}

#[inline(always)]
fn decode_to_slice<T: AsRef<[u8]>>(data: T, out: &mut [u8]) -> Result<(), FromHexError> {
    let data = data.as_ref();
    if data.len() % 2 != 0 {
        return Err(FromHexError::OddLength);
    }
    if data.len() / 2 != out.len() {
        return Err(FromHexError::InvalidStringLength);
    }

    for (i, byte) in out.iter_mut().enumerate() {
        *byte = val(data[2 * i], 2 * i)? << 4 | val(data[2 * i + 1], 2 * i + 1)?;
    }

    #[inline(always)]
    fn val(c: u8, idx: usize) -> Result<u8, FromHexError> {
        match c {
            b'A'..=b'F' => Ok(c - b'A' + 10),
            b'a'..=b'f' => Ok(c - b'a' + 10),
            b'0'..=b'9' => Ok(c - b'0'),
            _ => Err(FromHexError::InvalidHexCharacter { c: c as char, index: idx }),
        }
    }

    Ok(())
}
