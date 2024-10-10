

use std::cmp::max;

use kaspa_consensus_core::{hashing, header::Header, BlockLevel};
use kaspa_hashes::PowHash;
use kaspa_math::Uint256;

const BLOCK_HASH_DOMAIN: &[u8] = b"BlockHash";

#[derive(Clone)]
pub(super) struct PowHasher(blake3::Hasher);

#[derive(Clone, Copy)]
pub(super) struct KHeavyHash;

#[derive(Clone)]
pub struct HeaderHasher(Blake3Hasher);

impl PowHasher {
    // The initial state of `cSHAKE256("ProofOfWorkHash")`
    // [10] -> 1123092876221303310 ^ 0x04(padding byte) = 1123092876221303306
    // [16] -> 10306167911662716186 ^ 0x8000000000000000(final padding) = 1082795874807940378
    #[inline]
    pub fn new(pre_pow_hash: Hash, timestamp: u64) -> Self {
        let pre_pow_hash = hashing::header::hash_override_nonce_time(header, 0, 0);
        // PRE_POW_HASH || TIME || 32 zero byte padding || NONCE
        let hasher = PowHash::new(pre_pow_hash, header.timestamp);
        let matrix = Matrix::generate(pre_pow_hash);

        Self { matrix, target, hasher }
    }

    #[inline(always)]
    pub fn finalize_with_nonce(&mut self, nonce: u64) -> Uint256 {
        // Hasher already contains PRE_POW_HASH || TIME || 32 zero byte padding; so only the NONCE is missing
        let hash = self.hasher.clone().finalize_with_nonce(nonce);
        let hash = self.matrix.heavy_hash(hash);
        Uint256::from_le_bytes(hash.as_bytes())
    }
}

impl KHeavyHash {
    #[inline]
    pub fn hash(in_hash: Hash) -> Hash {

        let bytes: &[u8; 32] = &in_hash.0;
        let mut hasher = blake3::Hasher::new();
        hasher.update(bytes);

        let mut hash = [0u8; 32];
        hasher.finalize_xof().fill(&mut hash);
        Hash(hash)
    }
}

impl HeaderHasher {
    #[inline(always)]
    pub fn new() -> Self {
        let mut key = [42u8; 32];
        key = [66, 108, 111, 99, 107, 72, 97, 115, 104, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let mut hasher = Blake3Hasher::new_keyed(&key);
        Self(hasher)
    }

    pub fn write<A: AsRef<[u8]>>(&mut self, data: A) {
        self.0.update(data.as_ref());
    }

    #[inline(always)]
    pub fn finalize(self) -> Hash {
        Hash::from_le_bytes(self.0.finalize().as_bytes().clone().try_into().expect("this is 32 bytes"))
    }
}

pub trait Hasher {
    fn update<A: AsRef<[u8]>>(&mut self, data: A) -> &mut Self;
}

impl Hasher for HeaderHasher {
    fn update<A: AsRef<[u8]>>(&mut self, data: A) -> &mut Self {
        self.write(data);
        self
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;
    use crate::pow::hasher::{ KHeavyHash, PowHasher};

    use sha3::digest::{ExtendableOutput, Update, XofReader};
    use sha3::CShake256;
    use crate::Hash;
    use crate::pow::xoshiro::Hash;

    const PROOF_OF_WORK_DOMAIN: &[u8] = b"ProofOfWorkHash";
    const HEAVY_HASH_DOMAIN: &[u8] = b"HeavyHash";

    #[test]
    fn test_pow_hash() {
        let timestamp: u64 = 1715521488610;
        let nonce: u64 = 11171827086635415026;
        let pre_pow_hash = Hash::from_bytes([
            99, 231, 29, 85, 153, 225, 235, 207, 36, 237, 3, 55, 106, 21, 221, 122, 28, 51, 249, 76, 190, 128, 153, 244, 189, 104, 26, 178, 170, 4, 177, 103
        ]);
        let mut hasher = PowHasher::new(pre_pow_hash, timestamp);
        let hash1 = hasher.finalize_with_nonce(nonce);


        let mut hasher = blake3::Hasher::new();
        hasher
            .update(&pre_pow_hash.0)
            .update(&timestamp.to_le_bytes())
            .update(&[0u8; 32])
            .update(&nonce.to_le_bytes());

        let mut hash2 = [0u8; 32];
        hasher.finalize_xof().fill(&mut hash2);
        assert_eq!(Hash(hash2), hash1);
    }

    #[test]
    fn test_heavy_hash() {
        let val = Hash::from_le_bytes([42; 32]);
        let hash1 = KHeavyHash::hash(val);

        let mut hasher = blake3::Hasher::new();
        let bytes = unsafe { std::mem::transmute(val.to_le_bytes()) };
        hasher.write(bytes);

        let mut hash2 = [0u8; 32];
        hasher.finalize_xof().fill(&mut hash2);
        assert_eq!(Hash::from_le_bytes(hash2), hash1);
    }
}


