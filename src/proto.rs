use crate::codec::EncryptedCodec;
use bytes::{Buf, BytesMut};
use std::io;
use tokio_util::codec::{Decoder, Encoder};

#[derive(Debug, Clone, PartialEq)]
pub enum Message {
    PtyData(Vec<u8>),
    Resize { rows: u16, cols: u16 },
    Heartbeat,
    Exit,
}

pub struct ProtocolCodec {
    encrypted_codec: EncryptedCodec,
}

impl ProtocolCodec {
    pub fn new(encrypted_codec: EncryptedCodec) -> Self {
        Self { encrypted_codec }
    }
}

impl Encoder<Message> for ProtocolCodec {
    type Error = std::io::Error;

    fn encode(&mut self, item: Message, dst: &mut BytesMut) -> Result<(), Self::Error> {
        // Optimization: Pre-allocate capacity to avoid re-allocations for small headers
        let mut payload = match &item {
            Message::PtyData(d) => Vec::with_capacity(1 + d.len()),
            _ => Vec::with_capacity(5),
        };

        match item {
            Message::PtyData(data) => {
                payload.push(0x01);
                payload.extend_from_slice(&data);
            }
            Message::Resize { rows, cols } => {
                payload.push(0x02);
                payload.extend_from_slice(&rows.to_be_bytes());
                payload.extend_from_slice(&cols.to_be_bytes());
            }
            Message::Heartbeat => payload.push(0x03),
            Message::Exit => payload.push(0x04),
        }

        self.encrypted_codec.encode(payload, dst)
    }
}

impl Decoder for ProtocolCodec {
    type Item = Message;
    type Error = std::io::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        let decrypted_frame = match self.encrypted_codec.decode(src)? {
            Some(data) => data,
            None => return Ok(None),
        };

        if decrypted_frame.is_empty() {
            return Ok(None);
        }

        let mut cursor = io::Cursor::new(decrypted_frame);

        let tag = cursor.get_u8();

        match tag {
            0x01 => {
                let pos = cursor.position() as usize;
                let data = cursor.into_inner();
                Ok(Some(Message::PtyData(data[pos..].to_vec())))
            }
            0x02 => {
                if cursor.remaining() < 4 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "Short resize frame",
                    ));
                }
                let rows = cursor.get_u16();
                let cols = cursor.get_u16();
                Ok(Some(Message::Resize { rows, cols }))
            }
            0x03 => Ok(Some(Message::Heartbeat)),
            0x04 => Ok(Some(Message::Exit)),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Unknown protocol tag",
            )),
        }
    }
}
