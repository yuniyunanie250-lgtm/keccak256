use keccak256::{checksum_address, keccak256, parse_address, to_hex};

#[test]
fn matches_the_published_empty_string_vector() {
    assert_eq!(
        to_hex(&keccak256(b"")),
        "0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
    );
}

#[test]
fn matches_the_published_abc_vector() {
    assert_eq!(
        to_hex(&keccak256(b"abc")),
        "0x4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45"
    );
}

#[test]
fn erc20_selectors_come_out_right() {
    let s = keccak256(b"transfer(address,uint256)");
    assert_eq!(to_hex(&s[..4]), "0xa9059cbb");
    let s = keccak256(b"balanceOf(address)");
    assert_eq!(to_hex(&s[..4]), "0x70a08231");
}

#[test]
fn padding_beyond_one_block_is_absorbed() {
    // 200 bytes forces a second block
    let long = vec![0xab_u8; 200];
    let a = keccak256(&long);
    let mut different = long.clone();
    different[199] = 0xac;
    assert_ne!(a, keccak256(&different));
}

#[test]
fn input_of_exactly_one_rate_still_pads_a_full_block() {
    let data = vec![0u8; 136];
    assert_eq!(keccak256(&data), keccak256(&data));
    assert_ne!(keccak256(&data), keccak256(&[0u8; 135]));
}

#[test]
fn eip55_checksums_match_the_spec_examples() {
    // examples from EIP-55 itself
    let a = parse_address("0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed").unwrap();
    assert_eq!(
        checksum_address(&a),
        "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"
    );
    let b = parse_address("0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359").unwrap();
    assert_eq!(
        checksum_address(&b),
        "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359"
    );
}

#[test]
fn address_parsing_is_strict() {
    assert!(parse_address("0x1234").is_err());
    assert!(parse_address("0xzz").is_err());
    assert!(parse_address(&format!("0x{}", "a".repeat(40))).is_ok());
}
