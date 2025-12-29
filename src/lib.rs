use hkdf::Hkdf;
use obfstr::obfstr;
use sha2::Sha256;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use x25519_dalek::{PublicKey, StaticSecret};

pub type ReadKey = [u8; 32];
pub type WriteKey = [u8; 32];

#[derive(Clone)]
pub enum HandshakeRole {
    Client { server_public_key: PublicKey },
    Server { my_static_secret: StaticSecret },
}

pub async fn do_handshake<S>(
    stream: &mut S,
    role: HandshakeRole,
) -> std::io::Result<(ReadKey, WriteKey)>
where
    S: AsyncRead + AsyncWrite + Unpin, // This combination of traits describes a bidirectional async stream,
{
    //let my_secret = EphemeralSecret::random_from_rng(rand_core::OsRng));
    // We are using a key ephemerally here but due to x25519_dalek's design we are forced to
    // use StaticSecret to implement 2DH
    let my_secret = StaticSecret::random_from_rng(rand_core::OsRng);
    let my_public = PublicKey::from(&my_secret);
    stream.write_all(my_public.as_bytes()).await?;

    let mut peer_public_bytes = [0u8; 32];
    stream.read_exact(&mut peer_public_bytes).await?;
    let peer_public = PublicKey::from(peer_public_bytes);

    let shared_secret = my_secret.diffie_hellman(&peer_public);

    let secret_auth = match role {
        HandshakeRole::Client { server_public_key } => my_secret.diffie_hellman(&server_public_key),
        HandshakeRole::Server { my_static_secret } => my_static_secret.diffie_hellman(&peer_public),
    };

    let hkdf = Hkdf::<Sha256>::new(None, shared_secret.as_bytes());
    let mut okm = [0u8; 64];
    let mut info = Vec::from(obfstr!("hkdfrsh"));
    info.extend_from_slice(secret_auth.as_bytes());
    hkdf.expand(&info, &mut okm)
        .map_err(|_| std::io::Error::other("hkdf errror"))?;
    let (key_tx, key_rx) = okm.split_at(32);

    Ok((key_tx.try_into().unwrap(), key_rx.try_into().unwrap()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt}; // Import the extension traits!

    #[tokio::test]
    async fn test_handshake_success() {
        const SERVER_PUBKEY: [u8; 32] = [
            65, 176, 115, 118, 36, 147, 145, 126, 126, 120, 230, 223, 55, 244, 230, 112, 179, 181,
            93, 11, 193, 222, 118, 29, 222, 26, 110, 228, 193, 155, 107, 124,
        ];

        let (mut client_socket, mut server_socket) = tokio::io::duplex(64);

        tokio::spawn(async move {
            let mut client_key_buf = [0u8; 32];
            server_socket
                .read_exact(&mut client_key_buf)
                .await
                .expect("server failed to read client key");

            server_socket
                .write_all(&SERVER_PUBKEY)
                .await
                .expect("server failed to write key");
        });

        let role = HandshakeRole::Client {
            server_public_key: PublicKey::from(SERVER_PUBKEY),
        };

        let result = do_handshake(&mut client_socket, role).await;

        assert!(result.is_ok(), "handshake should succeed");
        let (rx_key, tx_key) = result.unwrap();

        assert_ne!(tx_key, [0u8; 32]);
        assert_ne!(rx_key, [0u8; 32]);
        assert_ne!(rx_key, tx_key, "rx and tx keys should differ");
    }
}
