use std::convert::TryInto;

/// Decompress an LZ77-encoded sequence of bytes.
pub fn decompress(bytes: &[u8], output: &mut Vec<u8>) {
    let mut i = 0;
    while i < bytes.len() {
        let byte = bytes[i];
        i += 1;
        match byte {
            // Literal 0x00
            0x00 => output.push(0x00),
            // Copy the following 1-8 bytes to the decompressed stream as-is
            0x01..=0x08 => {
                let mut n = byte as usize;
                while n > 0 {
                    output.push(bytes[i]);
                    i += 1;
                    n -= 1;
                }
            },
            // Copy the byte as-is
            0x09..=0x7f => output.push(byte),
            // Decompress using (length, distance) encoding
            0x80..=0xbf => {
                i += 1;
                let llz = u16::from_be_bytes(bytes[i-2..i].try_into().unwrap());
                let llz = llz & 0x3fff; // Clear top two bits
                let length = (llz & 0x0007) + 3;
                let distance = llz >> 3;
                for _ in 0..(length as usize) {
                    let pos = output.len() - (distance as usize);
                    output.push(output[pos]);
                }
            },
            // A space char + another byte
            0xc0..=0xff => {
                output.push(0x20); // Space char
                output.push(byte ^ 0x80);
            },
        };
    }
}