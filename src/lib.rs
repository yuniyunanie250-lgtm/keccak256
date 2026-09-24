//! Keccak-256, the hash Ethereum uses everywhere, in under 150 lines.
//!
//! Not SHA3-256. The two share a permutation but differ in padding: Keccak uses
//! `0x01`, SHA3 uses `0x06`. Using the wrong one produces a hash that is
//! perfectly valid and completely wrong, which is why the padding byte is
//! asserted against known vectors in the tests.

const RC: [u64; 24] = [
    0x0000000000000001,
    0x0000000000008082,
    0x800000000000808a,
    0x8000000080008000,
    0x000000000000808b,
    0x0000000080000001,
    0x8000000080008081,
    0x8000000000008009,
    0x000000000000008a,
    0x0000000000000088,
    0x0000000080008009,
    0x000000008000000a,
    0x000000008000808b,
    0x800000000000008b,
    0x8000000000008089,
    0x8000000000008003,
    0x8000000000008002,
    0x8000000000000080,
    0x000000000000800a,
    0x800000008000000a,
    0x8000000080008081,
    0x8000000000008080,
    0x0000000080000001,
    0x8000000080008008,
];

/// Rotation offsets, indexed [x][y].
const ROTC: [[u32; 5]; 5] = [
    [0, 36, 3, 41, 18],
    [1, 44, 10, 45, 2],
    [62, 6, 43, 15, 61],
    [28, 55, 25, 21, 56],
    [27, 20, 39, 8, 14],
];

const RATE: usize = 136; // 1088-bit rate for a 256-bit output

fn keccak_f(a: &mut [u64; 25]) {
    for round in 0..24 {
        // theta
        let mut c = [0u64; 5];
        for x in 0..5 {
            c[x] = a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20];
        }
        let mut d = [0u64; 5];
        for x in 0..5 {
            d[x] = c[(x + 4) % 5] ^ c[(x + 1) % 5].rotate_left(1);
        }
        for x in 0..5 {
            for y in 0..5 {
                a[x + 5 * y] ^= d[x];
            }
        }
        // rho and pi
        let mut b = [0u64; 25];
        for x in 0..5 {
            for y in 0..5 {
                b[y + 5 * ((2 * x + 3 * y) % 5)] = a[x + 5 * y].rotate_left(ROTC[x][y]);
            }
        }
        // chi
        for x in 0..5 {
            for y in 0..5 {
                a[x + 5 * y] = b[x + 5 * y] ^ ((!b[(x + 1) % 5 + 5 * y]) & b[(x + 2) % 5 + 5 * y]);
            }
        }
        // iota
        a[0] ^= RC[round];
    }
}

/// Keccak-256 of `data`.
pub fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut state = [0u64; 25];

    let mut padded = data.to_vec();
    padded.push(0x01); // Keccak padding, NOT SHA3's 0x06
    while padded.len() % RATE != 0 {
        padded.push(0x00);
    }
    let last = padded.len() - 1;
    padded[last] ^= 0x80;

    for block in padded.chunks_exact(RATE) {
        for (i, word) in block.chunks_exact(8).enumerate() {
            let mut buf = [0u8; 8];
            buf.copy_from_slice(word);
            state[i] ^= u64::from_le_bytes(buf);
        }
        keccak_f(&mut state);
    }

    let mut out = [0u8; 32];
    for i in 0..4 {
        out[i * 8..i * 8 + 8].copy_from_slice(&state[i].to_le_bytes());
    }
    out
}

/// Hex helper: `0x`-prefixed lowercase hash.
pub fn to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(2 + bytes.len() * 2);
    s.push_str("0x");
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

/// EIP-55 mixed-case checksum for a 20-byte address.
pub fn checksum_address(addr: &[u8; 20]) -> String {
    let lower = to_hex(addr)[2..].to_string();
    let hash = keccak256(lower.as_bytes());
    let mut out = String::from("0x");
    for (i, ch) in lower.chars().enumerate() {
        if ch.is_ascii_digit() {
            out.push(ch);
        } else {
            // nibble i of the hash decides the case
            let byte = hash[i / 2];
            let nibble = if i % 2 == 0 { byte >> 4 } else { byte & 0x0f };
            out.push(if nibble >= 8 {
                ch.to_ascii_uppercase()
            } else {
                ch
            });
        }
    }
    out
}

/// Parse a 20-byte hex address, with or without `0x`.
pub fn parse_address(s: &str) -> Result<[u8; 20], String> {
    let t = s
        .strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .unwrap_or(s);
    if t.len() != 40 {
        return Err(format!("expected 40 hex digits, got {}", t.len()));
    }
    let mut out = [0u8; 20];
    for i in 0..20 {
        out[i] = u8::from_str_radix(&t[i * 2..i * 2 + 2], 16)
            .map_err(|_| format!("non-hex at {}", i * 2))?;
    }
    Ok(out)
}
