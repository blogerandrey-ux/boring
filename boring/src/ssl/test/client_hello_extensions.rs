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

/// Returns (aead id, payload length) of the GREASE ECH extension.
fn ech_grease(body: &[u8]) -> Option<(u16, usize)> {
    let (_, d) = extensions(body).into_iter().find(|(t, _)| *t == 0xfe0d)?;
    // type(1) kdf(2) aead(2) config_id(1) enc<2> payload<2>
    assert_eq!(d[0], 0, "outer ECH");
    let aead = u16::from_be_bytes([d[3], d[4]]);
    let enc_len = usize::from(u16::from_be_bytes([d[6], d[7]]));
    let p = 8 + enc_len;
    let payload_len = usize::from(u16::from_be_bytes([d[p], d[p + 1]]));
    assert_eq!(d.len(), p + 2 + payload_len);
    Some((aead, payload_len))
}

#[test]
fn ech_grease_shape_is_configurable() {
    let mut aeads = std::collections::BTreeSet::new();
    for _ in 0..32 {
        let hello = client_hello_with(|ssl| {
            ssl.set_enable_ech_grease(true);
            ssl.set_ech_grease_aeads(&[0x0001, 0x0003]).unwrap();
            ssl.set_ech_grease_payload_len(240).unwrap();
        });
        let (aead, len) = ech_grease(&hello).unwrap();
        assert_eq!(len, 240);
        aeads.insert(aead);
    }
    // Both AEADs show up; the chance of missing one in 32 tries is 2^-31.
    assert_eq!(aeads.into_iter().collect::<Vec<_>>(), vec![0x0001, 0x0003]);
}

#[test]
fn ech_grease_shape_rejects_bad_values() {
    let mut ssl = new_ssl();
    assert!(ssl.set_ech_grease_aeads(&[0x0004]).is_err());
    assert!(ssl.set_ech_grease_aeads(&[]).is_ok());
    assert!(ssl.set_ech_grease_payload_len(15).is_err());
    assert!(ssl.set_ech_grease_payload_len(0).is_ok());
}

/// The handshake message of a ClientHello body as the session ID callback sees
/// it: header added, session ID zeroed.
fn zeroed_message(body: &[u8]) -> Vec<u8> {
    let len = body.len();
    let mut msg = vec![1, (len >> 16) as u8, (len >> 8) as u8, len as u8];
    msg.extend_from_slice(body);
    let sid_len = usize::from(msg[38]);
    msg[39..39 + sid_len].fill(0);
    msg
}

#[test]
fn session_id_callback_sets_the_echoed_session_id() {
    let hello = client_hello_with(|ssl| {
        ssl.set_client_hello_session_id_callback(|_, session_id, msg| {
            assert_eq!(usize::from(msg[38]), session_id.len());
            assert!(msg[39..39 + session_id.len()].iter().all(|&b| b == 0));
            let digest = crate::sha::sha256(msg);
            session_id.copy_from_slice(&digest[..session_id.len()]);
            true
        });
    });
    // The server got the derived session ID, and `connect` succeeded, so the
    // client accepted the ServerHello echoing it.
    let sid_len = usize::from(hello[34]);
    assert_eq!(sid_len, 32);
    let digest = crate::sha::sha256(&zeroed_message(&hello));
    assert_eq!(&hello[35..35 + sid_len], &digest[..sid_len]);
}

#[test]
fn session_id_callback_can_fail_the_handshake() {
    let mut server = Server::builder();
    server.should_error();
    let server = server.build();
    let client = server.client().build();
    let mut builder = client.builder();
    builder
        .ssl()
        .set_client_hello_session_id_callback(|_, _, _| false);
    builder.connect_err();
}

#[test]
fn client_key_share_x25519_matches_the_key_share() {
    const X25519: u16 = 0x001d;
    const X25519_MLKEM768: u16 = 0x11ec;
    let keys = Arc::new(Mutex::new(Vec::new()));
    let hello = client_hello_with({
        let keys = keys.clone();
        |ssl| {
            ssl.set_curves_list("X25519MLKEM768:X25519").unwrap();
            ssl.set_client_hello_session_id_callback(move |ssl, _, _| {
                let mut keys = keys.lock().unwrap();
                for group in [X25519_MLKEM768, X25519, 0x0017] {
                    keys.push((group, ssl.client_key_share_x25519(group)));
                }
                true
            });
        }
    });
    let shares = extensions(&hello)
        .into_iter()
        .find(|(t, _)| *t == 51)
        .expect("key_share")
        .1;
    let mut public = std::collections::HashMap::new();
    let mut i = 2;
    while i < shares.len() {
        let group = u16::from_be_bytes([shares[i], shares[i + 1]]);
        let len = usize::from(u16::from_be_bytes([shares[i + 2], shares[i + 3]]));
        let data = &shares[i + 4..i + 4 + len];
        // X25519MLKEM768: ML-KEM-768 encapsulation key, then the X25519 key.
        public.insert(group, data[data.len() - 32..].to_vec());
        i += 4 + len;
    }
    let keys = keys.lock().unwrap();
    assert_eq!(keys.len(), 3);
    for (group, private) in keys.iter() {
        match public.get(group) {
            Some(expected) => {
                let private = private.expect("x25519 private key");
                let mut derived = [0u8; 32];
                unsafe {
                    crate::ffi::X25519_public_from_private(derived.as_mut_ptr(), private.as_ptr())
                };
                assert_eq!(&derived[..], &expected[..], "group {group:#06x}");
            }
            None => assert!(private.is_none(), "group {group:#06x}"),
        }
    }
    // Outside a handshake there is nothing to export.
    assert!(new_ssl().client_key_share_x25519(X25519).is_none());
}
