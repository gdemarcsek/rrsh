use hkdf::Hkdf;
use sha2::Sha256;
use x25519_dalek::{EphemeralSecret, PublicKey};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub type ReadKey = [u8; 32];
pub type WriteKey = [u8; 32];

pub async fn do_handshake<S>(stream: &mut S) -> std::io::Result<(ReadKey, WriteKey)>
where
    S: AsyncRead + AsyncWrite + Unpin // This combination of traits describes a bidirectional async stream,
{
    let my_secret = EphemeralSecret::random_from_rng(rand_core::OsRng);
    let my_public = PublicKey::from(&my_secret);

    stream.write_all(my_public.as_bytes()).await?;

    let mut peer_public_bytes = [0u8; 32];
    stream.read_exact(&mut peer_public_bytes).await?;
    let peer_public = PublicKey::from(peer_public_bytes);

    let shared_secret = my_secret.diffie_hellman(&peer_public);

    let hkdf = Hkdf::<Sha256>::new(None, shared_secret.as_bytes());

    let mut okm = [0u8; 64];
    
    hkdf.expand(b"hkdfrsh", &mut okm)
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::Other, "hkdf errror"))?;

    let (key_tx, key_rx) = okm.split_at(32);

    Ok((
        key_tx.try_into().unwrap(), 
        key_rx.try_into().unwrap()
    ))
}