//! Onion module tests: address codec roundtrips and tamper rejection,
//! keygen verified against a captured tor 0.4.9.11 blob, client-auth file
//! format, file keystore, and the torrc template's exact tuning values.

use super::address::base32_decode;
use super::*;

#[test]
fn key_blob_matches_tor() {
    // Captured from tor 0.4.9.11 ADD_ONION on the Chutney testnet:
    // the blob is the 64-byte expanded secret key; the hostname is
    // derived from (clamped scalar)·B.
    let blob =
        "QNFkroFuDkJ0RCXXllBHv8aGU3n/dXgwvuSAEuiP0GhG0JMWlgvbtKalstewI93onbbb80VgQuf+3Rq7iI5GJw==";
    let hostname = hostname_from_key_blob(blob).unwrap();
    assert_eq!(
        hostname,
        "gxnsylx52dbp6hdnsojruqm2rrclndcbawkb6u2eotpkvjwqtv62moqd"
    );
}

#[test]
fn generated_blob_roundtrips() {
    let (blob, hostname) = generate_v3_key_blob();
    assert_eq!(hostname_from_key_blob(&blob).unwrap(), hostname);
    assert_eq!(hostname.len(), ONION_HOSTNAME_LEN);
    let (blob2, hostname2) = key_blob_from_seed(&[42u8; 32]);
    assert_eq!(hostname_from_key_blob(&blob2).unwrap(), hostname2);
    // Deterministic per seed.
    assert_eq!(key_blob_from_seed(&[42u8; 32]).1, hostname2);
}

#[test]
fn onion_address_roundtrip() {
    let pubkey = [7u8; 32];
    let host = hostname_from_pubkey(&pubkey);
    assert_eq!(host.len(), ONION_HOSTNAME_LEN);
    let decoded = pubkey_from_hostname(&host).unwrap();
    assert_eq!(decoded, pubkey);
    // with suffix and mixed case
    let upper = format!("{}.ONION", host.to_ascii_uppercase());
    assert_eq!(pubkey_from_hostname(&upper).unwrap(), pubkey);
}

#[test]
fn onion_address_tamper_fails() {
    let pubkey = [1u8; 32];
    let host = hostname_from_pubkey(&pubkey);
    let mut chars: Vec<char> = host.chars().collect();
    chars[0] = if chars[0] == 'a' { 'b' } else { 'a' };
    let tampered: String = chars.into_iter().collect();
    assert!(pubkey_from_hostname(&tampered).is_err());
    assert!(pubkey_from_hostname("short").is_err());
}

#[test]
fn client_auth_keys_are_base32_32_bytes() {
    let keys = ClientAuthKeys::generate();
    assert_eq!(base32_decode(&keys.public_b32).unwrap().len(), 32);
    assert_eq!(base32_decode(&keys.private_b32).unwrap().len(), 32);
}

#[test]
fn client_auth_file_format() {
    let tmp = tempfile::tempdir().unwrap();
    let host = hostname_from_pubkey(&[3u8; 32]);
    let path = write_client_auth_file(tmp.path(), &host, "abcd").unwrap();
    assert_eq!(
        path.file_name().unwrap().to_string_lossy(),
        format!("{host}.auth_private")
    );
    assert_eq!(
        std::fs::read_to_string(&path).unwrap(),
        format!("{host}:descriptor:x25519:abcd\n")
    );
}

#[tokio::test]
async fn file_keystore_roundtrip() {
    let tmp = tempfile::tempdir().unwrap();
    let ks = FileKeyStore::new(tmp.path().to_path_buf());
    assert_eq!(ks.get("onion-key/inbox").await.unwrap(), None);
    ks.put("onion-key/inbox", "BLOB").await.unwrap();
    assert_eq!(
        ks.get("onion-key/inbox").await.unwrap(),
        Some("BLOB".to_string())
    );
    assert_eq!(
        ks.keys_with_prefix(ONION_KEY_PREFIX).await.unwrap(),
        vec!["onion-key/inbox".to_string()]
    );
    ks.delete("onion-key/inbox").await.unwrap();
    assert_eq!(ks.get("onion-key/inbox").await.unwrap(), None);
    assert!(ks.put("bad key!", "x").await.is_err());
}

#[test]
fn torrc_has_exact_tuning_values() {
    let tmp = tempfile::tempdir().unwrap();
    let torrc = base_torrc(&TorrcParams {
        data_dir: tmp.path().join("data"),
        control_port: 19051,
        socks_port: 19050,
        client_auth_dir: tmp.path().join("client_auth"),
        log_file: None,
        extra: vec!["TestingTorNetwork 1".into()],
    });
    for line in [
        "SocksPort 127.0.0.1:19050 IsolateSOCKSAuth IsolateDestAddr IsolateClientProtocol",
        "KeepalivePeriod 60",
        "MaxClientCircuitsPending 48",
        "VanguardsLiteEnabled 1",
        "CookieAuthentication 1",
        "TestingTorNetwork 1",
    ] {
        assert!(torrc.contains(line), "torrc missing {line:?}:\n{torrc}");
    }
    assert!(
        !torrc.contains("HiddenServiceDir"),
        "no torrc HS dirs anymore"
    );
    assert!(
        !torrc.lines().any(|l| l.starts_with("HiddenService")),
        "tor rejects HiddenService* options without a HiddenServiceDir"
    );
}
