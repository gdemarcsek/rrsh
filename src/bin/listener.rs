use chacha20poly1305::{ChaCha20Poly1305, KeyInit};
use crossterm::terminal::{disable_raw_mode, enable_raw_mode};
use futures::{SinkExt, StreamExt};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::signal::unix::{SignalKind, signal};
use tokio_util::codec::{FramedRead, FramedWrite};

use rrsh::{
    HandshakeRole, codec::EncryptedCodec, do_handshake, proto::Message, proto::ProtocolCodec,
};

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

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let listener = TcpListener::bind("0.0.0.0:4444").await?;
    let server_role = rrsh::HandshakeRole::Server {
        my_static_secret: x25519_dalek::StaticSecret::from([
            154, 28, 197, 146, 162, 193, 220, 27, 149, 212, 221, 50, 238, 237, 119, 104, 137, 101,
            199, 180, 99, 33, 61, 7, 158, 188, 197, 71, 96, 155, 89, 199,
        ]),
    };
    println!("[*] Listening on 0.0.0.0:4444 (Encrypted, Framed, Interactive)...");

    loop {
        let (mut socket, addr) = listener.accept().await?;
        println!("[+] New connection from: {}", addr);

        match handle_session(&mut socket, server_role.clone()).await {
            Ok(_) => println!("[*] Waiting for next client..."),
            Err(e) => eprintln!("[-] Session Error: {}", e),
        }
    }
}

async fn handle_session(
    socket: &mut tokio::net::TcpStream,
    role: HandshakeRole,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("[*] Starting Handshake...");

    let (key_rx, key_tx) = do_handshake(socket, role).await?;

    let cipher_tx = ChaCha20Poly1305::new_from_slice(&key_rx).unwrap();
    let cipher_rx = ChaCha20Poly1305::new_from_slice(&key_tx).unwrap();

    println!("[+] Handshake Complete. Entering Raw Mode.");

    let _guard = RawModeGuard::new()?;

    let (raw_reader, raw_writer) = socket.split();
    let mut frame_reader = FramedRead::new(
        raw_reader,
        ProtocolCodec::new(EncryptedCodec::new(cipher_rx)),
    );
    let mut frame_writer = FramedWrite::new(
        raw_writer,
        ProtocolCodec::new(EncryptedCodec::new(cipher_tx)),
    );

    let mut stdin = tokio::io::stdin();
    let mut stdout = tokio::io::stdout();
    let mut stdin_buf = [0u8; 4096];

    let mut window_change_events = signal(SignalKind::window_change())?;

    frame_writer
        .send(Message::Resize {
            rows: crossterm::terminal::size()?.1,
            cols: crossterm::terminal::size()?.0,
        })
        .await?;

    loop {
        tokio::select! {
            Some(result) = frame_reader.next() => {
                match result {
                    Ok(Message::PtyData(data)) => {
                        stdout.write_all(&data).await?;
                        stdout.flush().await?;
                    }
                    Ok(Message::Exit) => {
                        println!("\r\n[!] Remote side exited the session.");
                        break;
                    }
                    Ok(Message::Heartbeat) => {
                        frame_writer.send(Message::Heartbeat).await?;
                    }
                    Ok(_) => {}
                    Err(e) => return Err(format!("network error: {}", e).into()),
                }
            }

            Ok(n) = stdin.read(&mut stdin_buf) => {
                if n == 0 { break; }
                let data = stdin_buf[..n].to_vec();
                frame_writer.send(Message::PtyData(data)).await?;
            }

            _ = window_change_events.recv() => {
                frame_writer.send(Message::Resize {
                    rows: crossterm::terminal::size()?.1,
                    cols: crossterm::terminal::size()?.0,
                }).await?;
            }

            else => break
        }
    }

    Ok(())
}
