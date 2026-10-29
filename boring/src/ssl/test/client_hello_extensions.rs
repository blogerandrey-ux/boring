use std::sync::{Arc, Mutex};

use super::server::{ClientSslBuilder, Server};
use crate::ssl::{SslContext, SslMethod, SslRef, SslSignatureAlgorithm};

/// Connects with `configure` applied to the client and returns the ClientHello
/// body the server received.
fn client_hello_with(configure: impl FnOnce(&mut SslRef)) -> Vec<u8> {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let mut server = Server::builder();
    server.ctx().set_select_certificate_callback({
        let seen = seen.clone();
        move |client_hello| {
            *seen.lock().unwrap() = client_hello.as_bytes().to_vec();
            Ok(())
        }
    });
    let server = server.build();
    let client = server.client().build();
    let mut builder: ClientSslBuilder = client.builder();
    configure(builder.ssl());
    builder.connect();
    let hello = seen.lock().unwrap().clone();
    hello
}

/// Splits a ClientHello body into (extension type, extension data).
fn extensions(body: &[u8]) -> Vec<(u16, Vec<u8>)> {
    fn u16_at(b: &[u8], i: usize) -> usize {
        usize::from(u16::from_be_bytes([b[i], b[i + 1]]))
    }
    let mut i = 2 + 32; // legacy_version, random
    i += 1 + usize::from(body[i]); // session_id
    i += 2 + u16_at(body, i); // cipher_suites
    i += 1 + usize::from(body[i]); // compression_methods
    let end = i + 2 + u16_at(body, i);
    i += 2;
    let mut out = Vec::new();
    while i < end {
        let ty = u16_at(body, i) as u16;
        let len = u16_at(body, i + 2);
        out.push((ty, body[i + 4..i + 4 + len].to_vec()));
        i += 4 + len;
    }
    out
}

fn types(body: &[u8]) -> Vec<u16> {
    extensions(body).into_iter().map(|(t, _)| t).collect()
}

fn new_ssl() -> crate::ssl::Ssl {
    let ctx = SslContext::builder(SslMethod::tls()).unwrap().build();
    crate::ssl::Ssl::new(&ctx).unwrap()
}

#[test]
fn extension_order_is_followed() {
    let default = types(&client_hello_with(|_| {}));
    // Reverse the default order: every sent extension is listed.
    let reversed: Vec<u16> = default.iter().rev().copied().collect();
    let hello = client_hello_with(|ssl| ssl.set_extension_order(&reversed).unwrap());
    assert_eq!(types(&hello), reversed);
}

#[test]
fn extension_order_appends_unlisted_in_default_order() {
    let default = types(&client_hello_with(|_| {}));
    let first = [default[default.len() - 1], default[0]];
    let hello = client_hello_with(|ssl| ssl.set_extension_order(&first).unwrap());
    let mut expected = first.to_vec();
    expected.extend(default.iter().copied().filter(|t| !first.contains(t)));
    assert_eq!(types(&hello), expected);
}

#[test]
fn extension_order_takes_precedence_over_permutation() {
    let default = types(&client_hello_with(|_| {}));
    let reversed: Vec<u16> = default.iter().rev().copied().collect();
    for _ in 0..4 {
        let hello = client_hello_with(|ssl| {
            ssl.set_permute_extensions(true);
            ssl.set_extension_order(&reversed).unwrap();
        });
        assert_eq!(types(&hello), reversed);
    }
}

#[test]
fn extension_order_rejects_unknown_and_duplicate_codepoints() {
    let mut ssl = new_ssl();
    assert!(ssl.set_extension_order(&[0x1234]).is_err());
    assert!(ssl.set_extension_order(&[0, 16, 0]).is_err());
    assert!(ssl.set_extension_order(&[0, 16]).is_ok());
    assert!(ssl.set_extension_order(&[]).is_ok());
}

#[test]
fn record_size_limit_is_offered() {
    assert!(!types(&client_hello_with(|_| {})).contains(&28));
    let hello = client_hello_with(|ssl| ssl.set_record_size_limit(0x4001).unwrap());
    let ext = extensions(&hello).into_iter().find(|(t, _)| *t == 28);
    assert_eq!(ext.map(|(_, d)| d), Some(vec![0x40, 0x01]));
}

#[test]
fn record_size_limit_rejects_out_of_range_values() {
    let mut ssl = new_ssl();
    assert!(ssl.set_record_size_limit(63).is_err());
    assert!(ssl.set_record_size_limit(16386).is_err());
    assert!(ssl.set_record_size_limit(64).is_ok());
    assert!(ssl.set_record_size_limit(0).is_ok());
}

#[test]
fn delegated_credential_sigalgs_are_offered() {
    assert!(!types(&client_hello_with(|_| {})).contains(&34));
    let sigalgs = [
        SslSignatureAlgorithm::ECDSA_SECP256R1_SHA256,
        SslSignatureAlgorithm::ECDSA_SECP384R1_SHA384,
    ];
    let hello = client_hello_with(|ssl| ssl.set_delegated_credential_sigalgs(&sigalgs).unwrap());
    let ext = extensions(&hello).into_iter().find(|(t, _)| *t == 34);
    assert_eq!(
        ext.map(|(_, d)| d),
        Some(vec![0x00, 0x04, 0x04, 0x03, 0x05, 0x03])
    );
}

#[test]
fn client_hello_padding_pads_to_512_bytes() {
    let restrict = |ssl: &mut SslRef| {
        // Without a post-quantum key share and with a long server name, the
        // ClientHello falls in the padded range.
        ssl.set_curves_list("X25519:P-256").unwrap();
        ssl.set_hostname("a-rather-long-host-name-to-push-the-hello-over-256.example")
            .unwrap();
    };
    let unpadded = client_hello_with(restrict);
    assert!(!types(&unpadded).contains(&21));
    let len = unpadded.len() + 4;
    assert!(len > 0xff && len < 0x200, "ClientHello is {len} bytes");

    let padded = client_hello_with(|ssl| {
        restrict(ssl);
        ssl.set_client_hello_padding(true);
    });
    assert_eq!(types(&padded).last(), Some(&21));
    // The handshake message, including its 4-byte header, is 512 bytes.
    assert_eq!(padded.len() + 4, 0x200);
}

#[test]
fn client_hello_padding_leaves_large_hellos_alone() {
    // The default ClientHello carries a post-quantum key share and is larger
    // than 512 bytes.
    let default = client_hello_with(|_| {});
    assert!(default.len() + 4 >= 0x200);
    let padded = client_hello_with(|ssl| ssl.set_client_hello_padding(true));
    assert_eq!(types(&padded), types(&default));
}
