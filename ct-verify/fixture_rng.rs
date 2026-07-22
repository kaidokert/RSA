/// Deterministic, infallible RNG used only by verification fixtures.
///
/// The signing API requires a cryptographic RNG marker, but these fixtures
/// need a reproducible stream rather than production randomness. Keeping the
/// implementation local prevents this test double from being used by library
/// consumers. The byte-at-a-time fill also keeps slice-length panic machinery
/// out of archives inspected by the panic-free gate.
struct FixedRng(u64);

impl rand_core::TryRng for FixedRng {
    type Error = core::convert::Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        Ok(self.try_next_u64()? as u32)
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut value = self.0;
        value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        Ok(value ^ (value >> 31))
    }

    fn try_fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), Self::Error> {
        for chunk in destination.chunks_mut(8) {
            let bytes = self.try_next_u64()?.to_le_bytes();
            for (destination, source) in chunk.iter_mut().zip(bytes.iter()) {
                *destination = *source;
            }
        }
        Ok(())
    }
}

impl rand_core::TryCryptoRng for FixedRng {}
