use bytes::{Buf, BufMut, BytesMut};
use chacha20poly1305::aead::Aead;
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use tokio_util::codec::{Decoder, Encoder};

pub struct EncryptedCodec {
    pub cipher: ChaCha20Poly1305,
    pub nonce_counter: u64,
}

impl EncryptedCodec {
    pub fn new(cipher: ChaCha20Poly1305) -> Self {
        Self {
            cipher,
            nonce_counter: 0,
        }
    }
}

// Helper: Convert u64 counter -> 12-byte Nonce (96-bit)
fn make_nonce(counter: u64) -> Nonce {
    let mut nonce_bytes = [0u8; 12];
    // Copy the counter into the first 8 bytes (Little Endian)
    nonce_bytes[..8].copy_from_slice(&counter.to_le_bytes());
    // Return standard generic array wrapper
    nonce_bytes.into()
}

impl Encoder<Vec<u8>> for EncryptedCodec {
    type Error = std::io::Error;
    // WARNING: We are using repeatable nonces so the protocol needs two distinct keys for each direction of comms!
    fn encode(&mut self, item: Vec<u8>, dst: &mut BytesMut) -> Result<(), Self::Error> {
        let nonce = make_nonce(self.nonce_counter);
        self.nonce_counter += 1;

        let ciphertext = self
            .cipher
            .encrypt(&nonce, item.as_ref())
            .map_err(|_| std::io::Error::other("enc failed"))?;

        // Write Length (u16) + Ciphertext
        dst.put_u16(ciphertext.len() as u16);
        dst.put_slice(&ciphertext);
        Ok(())
    }
}

impl Decoder for EncryptedCodec {
    type Item = Vec<u8>;
    type Error = std::io::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        if src.len() < 2 {
            return Ok(None);
        }

        let len = u16::from_be_bytes([src[0], src[1]]) as usize;

        if src.len() < 2 + len {
            src.reserve(2 + len - src.len());
            return Ok(None);
        }

        src.advance(2);
        let data = src.split_to(len);

        let nonce = make_nonce(self.nonce_counter);
        self.nonce_counter += 1;

        let plaintext = self.cipher.decrypt(&nonce, data.as_ref()).map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "auth tag failed")
        })?;

        Ok(Some(plaintext))
    }
}
