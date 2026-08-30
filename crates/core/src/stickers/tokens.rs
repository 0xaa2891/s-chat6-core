//! Inline custom-emoji tokens in MSG text:
//! `:e:<16 lowercase hex>` — the first 8 bytes of the item's content
//! hash. Old clients show the shortcode as text; CAP_STICKER peers
//! render the image inline and fetch misses with WANT_ITEM.

/// Distinct 8-byte hash prefixes in order of appearance.
pub fn extract(text: &str) -> Vec<[u8; 8]> {
    let mut out: Vec<[u8; 8]> = Vec::new();
    let bytes = text.as_bytes();
    let mut i = 0;
    while i + 20 <= bytes.len() {
        if &bytes[i..i + 3] == b":e:" {
            if let Some(hex) = text.get(i + 3..i + 19) {
                if bytes.get(i + 19) == Some(&b':')
                    && hex
                        .bytes()
                        .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
                {
                    if let Ok(decoded) = crate::store::hex_decode(hex) {
                        if decoded.len() == 8 {
                            let prefix: [u8; 8] = decoded.try_into().expect("len checked");
                            if !out.contains(&prefix) {
                                out.push(prefix);
                            }
                        }
                    }
                    i += 20;
                    continue;
                }
            }
        }
        i += 1;
    }
    out
}

/// The token for an item hash (first 8 bytes, lowercase hex).
pub fn token_for(sha256: &[u8; 32]) -> String {
    format!(":e:{}:", crate::store::hex_encode(&sha256[..8]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_distinct_in_order() {
        let a = token_for(&[0xAA; 32]);
        let b = token_for(&[0xBB; 32]);
        let text = format!("hi {a} and {b} and {a} again");
        let got = extract(&text);
        assert_eq!(got, vec![[0xAA; 8], [0xBB; 8]]);
        assert!(extract("no tokens here").is_empty());
        assert!(
            extract(":e:ZZZZZZZZZZZZZZZZ:").is_empty(),
            "uppercase rejected"
        );
        assert!(extract(":e:aabb:").is_empty(), "short rejected");
    }
}
