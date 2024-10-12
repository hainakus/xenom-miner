use kaspa_hashes::Hash;




#[derive(Clone)]
pub struct HeaderHasher(blake3::Hasher);

impl HeaderHasher {
    #[inline(always)]
    pub fn new() -> Self {
        let mut key = [42u8; 32];
        key = [66, 108, 111, 99, 107, 72, 97, 115, 104, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let mut hasher = blake3::Hasher::new_keyed(&key);
        Self(hasher)
    }

    pub fn write<A: AsRef<[u8]>>(&mut self, data: A) {
        self.0.update(data.as_ref());
    }

    #[inline(always)]
    pub fn finalize(self) -> Hash {
        Hash::from_bytes(self.0.finalize().as_bytes().clone().try_into().expect("this is 32 bytes"))
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

