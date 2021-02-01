use std::convert::TryInto;

/// Decompress a sequence of PalmDoc-LZ77-compressed blocks.
pub fn decompress_all(blocks: &Vec<Vec<u8>>) -> Vec<u8> {
    let mut output = vec!();
    for block in blocks {
        decompress(&block, &mut output);
    }
    output
}

/// Compress an arbitrary-length sequence of bytes using PalmDoc LZ77 compression.
///
/// Returns a sequence of compressed blocks where each block decompresses to
/// 4096 bytes, except for the last block which may decompress to fewer.
pub fn compress_all(input: &[u8]) -> Vec<Vec<u8>> {
    let mut output = vec!();
    for chunk in input.chunks(4096) {
        let mut compressed = vec!();
        compress(&chunk, &mut compressed);
        output.push(compressed);
    }
    output
}

/// Decompress a PalmDoc-LZ77-encoded sequence of bytes.
///
/// The input should decompress into 4096 bytes at most (the size of a PalmDoc LZ77 block). 
/// For arbitrary-length input, use `decompress_all`. 
pub fn decompress(input: &[u8], output: &mut Vec<u8>) {
    let mut i = 0;
    while i < input.len() {
        let byte = input[i];
        i += 1;
        match byte {
            // Literal 0x00
            0x00 => output.push(0x00),
            // Copy the following 1-8 bytes to the decompressed stream as-is
            0x01..=0x08 => {
                let n = byte as usize;
                for offset in 0..n {
                    output.push(input[i+offset])
                }
                i += n;
            },
            // Copy the byte as-is
            0x09..=0x7f => output.push(byte),
            // Decompress using (length, distance) encoding
            0x80..=0xbf => {
                i += 1;
                let llz = u16::from_be_bytes(input[i-2..i].try_into().unwrap());
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

/// Compress a sequence of bytes using PalmDoc LZ77 compression.
/// 
/// Handles only 4096 bytes of input (the size of a PalmDoc LZ77 block).
/// For arbitrary-length input, use `compress_all`.
pub fn compress(input: &[u8], output: &mut Vec<u8>) {
    assert!(input.len() <= 4096);

    // If we have several literals in a row, we want to encode them
    // <n> <lit_1> ... <lit_n>
    // So we'll store literals into this pool and dump them whenever
    // we hit a non-literal encoding (e.g. length-distance pair) or
    // when the pool hits size 8
    // This only applies to literals that can't be directly written to the
    // compressed output, i.e. not 0x00 or not in the range 0x40-0x7f.
    let mut literal_pool: Vec<u8> = vec!();

    let mut i = 0;
    while i < input.len() {
        match find_longest_match(&input, i) {
            Option::Some((distance, length)) => {
                dump_literal_pool(output, &mut literal_pool);
                // Encode 10dd dddd dddd dlll
                output.push(0b1000_0000 | (distance >> 5) as u8);
                output.push(
                    ((distance & 0b11111) << 3) as u8
                    | ((length - 3) & 0b111) as u8
                );
                i += length;
            },
            _ => {
                // Handle a space char + another char
                // The second char has to be between 0x40 and 0x7f, so that
                // XORing it with 0x80 will produce a value between 0xc0 and 0xff
                if input[i] == 0x20 && i+1 < input.len() 
                    && (input[i+1] >= 0x40 && input[i+1] <= 0x7f) 
                {
                    dump_literal_pool(output, &mut literal_pool);
                    output.push(input[i+1] ^ 0x80);
                    i += 2;
                    continue;
                }
                
                // If this byte falls into the literal range, just output it
                if input[i] == 0x00 || (input[i] >= 0x09 && input[i] <= 0x7f) {
                    dump_literal_pool(output, &mut literal_pool);
                    output.push(input[i]);
                    i += 1;
                    continue;
                }

                // Otherwise, this byte needs to be encoded via <n><byte_1>..<byte_n>
                // Since we can group a bunch of these together, just push into the 
                // literal pool
                literal_pool.push(input[i]);
                i += 1;
                if literal_pool.len() == 8 {
                    dump_literal_pool(output, &mut literal_pool);
                }
            }
        }
    }

    dump_literal_pool(output, &mut literal_pool);
}

fn dump_literal_pool(output: &mut Vec<u8>, literal_pool: &mut Vec<u8>) {
    if literal_pool.len() > 0 {
        output.push(literal_pool.len() as u8);
        for byte in literal_pool.iter() {
            output.push(*byte);
        }
        literal_pool.clear();
    } 
}

fn find_longest_match(input: &[u8], curr: usize) -> Option<(usize, usize)> {
    let mut best_match_distance = 0;
    let mut best_match_length = 0;

    // We need at least 3 bytes behind curr and
    // at least 3 bytes starting from curr
    // Otherwise, there won't be enough for a 3-byte-long match
    if curr < 3 || curr > input.len()-3 {
        return Option::None;
    }

    // Max distance is 0x7FF or 2047 (all 11 bits used)
    // That means we should take care not to start too far away!
    let mut i = if curr > 2047 { curr - 2047 } else { 0 };
    while i < curr - 2 {
        if input[i..i+3] != input[curr..curr+3] {
            i += 1;
            continue;
        }
        i += 3;
        
        let mut len = 3;
        while len < 10 && i < curr && curr+len < input.len() {
            if input[i] != input[curr+len] {
                break;
            }
            i += 1;
            len += 1;
        }

        if len > best_match_length {
            best_match_length = len;
            best_match_distance = (curr - i) + len;
        }

        i += 1;
    }
    
    if best_match_distance == 0 {
        Option::None
    } else {
        Option::Some((best_match_distance as usize, best_match_length as usize))
    }       
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str;

    #[test]
    fn test_compress() {
        let input = b"this text is text";
        let compressed = compress(input);
        let mut decompressed = vec!();
        decompress(&compressed, &mut decompressed);
        assert_eq!(input, &decompressed[..]);
        
        let input = b"Oooh faa laa ta da di doe. I say I say, faa laa ta, and da di doe!";
        let compressed = compress(input);
        let mut decompressed = vec!();
        decompress(&compressed, &mut decompressed);
        assert_eq!(input, &decompressed[..]);
    }
}
