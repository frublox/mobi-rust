use std::convert::TryInto;
use std::cmp;
use debug_print::{debug_print, debug_println};

/// Decompress a PalmDoc-LZ77-encoded sequence of bytes.
/// Handles only up to 4096 bytes (i.e. a single 'chunk').
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

/// Compress a sequence of bytes using PalmDoc LZ77 compression.
/// Handles only up to 4096 bytes (i.e. a single 'chunk').
fn compress(input: &[u8]) -> Vec<u8> {
    let mut i = 0;
    let mut output = Vec::with_capacity(input.len() / 2);
    // If we have several literals in a row, we want to encode them
    // <n> <lit_1> ... <lit_n>
    // So we'll store literals into this pool and dump them 
    // whenever we hit a non-literal encoding (e.g. length-distance pair)
    // or when the pool hits size 8
    let mut literal_pool: Vec<u8> = vec!();

    while i < input.len() {
        debug_print!("i={} ", i);
        match find_longest_match(&input, i) {
            Option::Some((distance, length)) => {
                debug_println!("Handling match distance={}, length={} \"{}\"", distance, length, std::str::from_utf8(&input[i - distance .. (i - distance)+length]).unwrap());
                dump_literal_pool(&mut output, &mut literal_pool);
                // Encode 10dd dddd dddd dlll
                output.push(0b1000_0000 | (distance >> 5) as u8);
                output.push(((distance & 0b11111) << 3) as u8 | ((length - 3) & 0b111) as u8);
                i += length;
            },
            _ => {
                // Handle a repeating byte
                // "aaaa" -> 0x04, 'a'
                let mut reps = 1;
                for j in i+1..cmp::min(i+8, input.len()) {
                    if input[j] == input[i] {
                        reps += 1;
                    } else {
                        break;
                    }
                }
                if reps > 2 { // Encoding takes 2, so only worth for > 2
                    debug_println!("Handling {} reps", reps);
                    dump_literal_pool(&mut output, &mut literal_pool);
                    output.push(reps as u8);
                    output.push(input[i]);
                    i += reps + 1;
                    continue;
                }

                // Handle a space char + another char
                // The second char has to be between 0x40 and 0x7f, so that
                // XORing it with 0x80 will produce a value between 0xc0 and 0xff
                if input[i] == 0x20 && i < input.len() - 1 
                    && (input[i+1] >= 0x40 && input[i+1] <= 0x7f) 
                {
                    debug_println!("Handling space+{} '{}'", input[i+1], input[i+1] as char);
                    dump_literal_pool(&mut output, &mut literal_pool);
                    output.push(input[i+1] ^ 0x80);
                    i += 2;
                    continue;
                }
                
                debug_println!("Adding literal {} '{}'", input[i], input[i] as char);
                // Handle this literal byte later
                literal_pool.push(input[i]);
                i += 1;
                if literal_pool.len() == 8 {
                    dump_literal_pool(&mut output, &mut literal_pool);
                }
            }
        }
    }

    dump_literal_pool(&mut output, &mut literal_pool);
    
    output
}

fn dump_literal_pool(output: &mut Vec<u8>, literal_pool: &mut Vec<u8>) {
    if literal_pool.len() > 1 {
        output.push(literal_pool.len() as u8);
        for byte in literal_pool.iter() {
            output.push(*byte);
        }
    } else if literal_pool.len() == 1 {
        // If the byte is between 0x09 and 0x7f, we can avoid using another byte
        // to encode the length
        let byte = literal_pool[0];
        if byte >= 0x09 && byte <= 0x7f {
            output.push(byte);
        } else {
            output.push(0x01);
            output.push(byte);
        }
    }

    literal_pool.clear();
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

    let mut i = 0;
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
