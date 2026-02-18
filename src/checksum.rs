/// Fletcher-64 as used by APFS objects:
/// compute over object bytes excluding the first 8 bytes (checksum field).
/// Implemented over little-endian u32 words, mod 0xffffffff.
pub fn fletcher64(data_without_cksum_field: &[u8]) -> u64 {
    let mut sum1: u64 = 0;
    let mut sum2: u64 = 0;
    let mut i = 0;

    while i < data_without_cksum_field.len() {
        let mut word_bytes = [0u8; 4];
        let take = (data_without_cksum_field.len() - i).min(4);
        word_bytes[..take].copy_from_slice(&data_without_cksum_field[i..i + take]);
        let word = u32::from_le_bytes(word_bytes) as u64;

        sum1 = (sum1 + word) % 0xffff_ffff;
        sum2 = (sum2 + sum1) % 0xffff_ffff;

        i += 4;
    }

    (sum2 << 32) | sum1
}
