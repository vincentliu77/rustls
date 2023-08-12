#[cfg(feature = "logging")]
use log::debug;

use crate::{
    conn::ConnectionRandoms,
    jls::server::JlsForwardConn,
    msgs::{
        codec::Codec,
        handshake::{
            ClientHelloPayload, ConvertServerNameList, HandshakeMessagePayload, HandshakePayload,
            Random,
        },
        message::{Message, MessagePayload, PlainMessage},
    },
    vecbuf::ChunkVecBuffer,
    HandshakeType, JlsServerConfig, common_state::State,
};

use super::{hs::{ServerContext, self}, ServerConnectionData};

/// Return true if jls authentication passed
pub(super) fn handle_client_hello_tls13(
    config: &JlsServerConfig,
    cx: &mut ServerContext<'_>,
    client_hello: &ClientHelloPayload,
    chm: &Message,
    randoms: &mut ConnectionRandoms,
) -> bool {
    let mut client_hello_clone = ClientHelloPayload {
        client_version: client_hello.client_version.clone(),
        random: Random([0u8; 32]),
        session_id: client_hello.session_id.clone(),
        cipher_suites: client_hello.cipher_suites.clone(),
        compression_methods: client_hello.compression_methods.clone(),
        extensions: client_hello.extensions.clone(),
    };
    // PSK binders involves the calucaltion of hash of clienthello contradicting
    // with fake random generaton. Must be set zero before checking.
    crate::jls::set_zero_psk_binders(&mut client_hello_clone);
    let mut ch_hs = HandshakeMessagePayload {
        typ: HandshakeType::ClientHello,
        payload: HandshakePayload::ClientHello(client_hello_clone),
    };
    let mut buf = Vec::<u8>::new();
    ch_hs.encode(&mut buf);

    let server_name = client_hello
        .get_sni_extension()
        .map_or(None, |x| x.get_single_hostname());
    let server_name = server_name.map(|x| x.as_ref().to_string());
    let valid_name = if let Some(name) = &server_name {
        config.check_server_name(name)
    } else {
        false
    };

    if config.check_fake_random(&randoms.client, &buf) && valid_name {
        debug!("JLS client authenticated");
        cx.common.jls_authed = Some(true);
        return true;
    } else {
        if valid_name {
            debug!("JLS client authentication failed: wrong pwd/iv");
        } else {
            debug!("JLS client authentication failed: wrong server name");
        }

        cx.common.jls_authed = Some(false);
        if let HandshakePayload::ClientHello(ch_ref) = &mut ch_hs.payload {
            ch_ref.random = Random(randoms.client);
            ch_ref.extensions = client_hello.extensions.clone();
        }
        let msg = Message {
            version: chm.version,
            payload: MessagePayload::handshake(ch_hs),
        };
        let plain_msg = PlainMessage::from(msg);
        let opa_msg = plain_msg
            .into_unencrypted_opaque()
            .encode();

        let upstream_addr = server_name.map_or(config.get_jls_upstream().ok(), |x| {
            config.find_upstream(x.as_ref()).ok()
        });
        let mut chunk = ChunkVecBuffer::new(None);
        chunk.append(opa_msg);
        if let Some(addr) = upstream_addr {
            cx.data.jls_conn = Some(JlsForwardConn {
                from_upstream: [0u8; 4096],
                to_upstream: chunk,
                upstream_addr: addr,
            });
        } else {
            panic!("Jls autentication failed but no upstream url available");
        }
        // End handshaking, start forward traffic
        cx.common.may_send_application_data = true;
        cx.common.may_receive_application_data = true;

        return false;
    }
}

// JLS Forward
pub(super) struct ExpectForward {}
impl ExpectForward {}

impl State<ServerConnectionData> for ExpectForward {
    fn handle(self: Box<Self>, _cx: &mut ServerContext<'_>, m: Message) -> hs::NextStateOrError {
        Err(crate::check::inappropriate_message(&m.payload, &[]))
    }
}