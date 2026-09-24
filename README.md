# keccak256

Keccak-256 in pure Rust, no dependencies, plus the EIP-55 address checksum built
on top of it.

Keccak-256 is the hash Ethereum uses for everything: addresses, storage slots,
event topics, function selectors, the state trie. It is **not** SHA3-256 — the
two share the permutation but pad differently — so `sha3_256` from a standard
crypto crate gives you a different, wrong answer.

## Usage

```rust
use keccak256::{keccak256, checksum_address, parse_address};

let sel = keccak256(b"transfer(address,uint256)");
assert_eq!(&sel[..4], &[0xa9, 0x05, 0x9c, 0xbb]);

let addr = parse_address("0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed").unwrap();
assert_eq!(checksum_address(&addr), "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed");
```

## Verification

The tests pin the two published vectors for the empty string and `abc`, the four
selectors used by every ERC-20 tool, the multi-block path, and the two examples
from EIP-55. If the padding byte were `0x06` instead of `0x01` the hash output
changes completely and every vector fails, which is the point of pinning them.

## What it does not do

- **No SHA3-256 or SHAKE.** Different padding; add them as separate functions if
  needed rather than a mode flag.
- **Not constant time.** Fine for hashing public data, wrong for anything
  secret-dependent.
- **No streaming/incremental API.** One-shot over a byte slice.

## Development

```bash
cargo test
```

## License

MIT
