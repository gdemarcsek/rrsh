# rrsh - a simple Rust reverse shell

A Rust learning project.

WARNING: This is my learning project to learn and practice Rust. While it ships some "production" features to give more space to practice, it is _just_ a learning project with no intention to be yet another "C2 framework" or anything remotely similar.

DISCLAIMER: This project is for educational purposes and authorized security testing only. The author is not responsible for any misuse. The code is provided "as is" with safety interlocks enabled by default.

Features implemented:

- [*] "Upgraded" (pty) shell (NOTE: some features are lacking, for example proper support for window resize)
- [*] Minimalistic, custom encrypted channel (modified ChaCha20Poly1305 with 2DH handshake protocol over ECDH)
- [*] Async networking using Tokio
- [*] Some super basic stealth for its Rust practice value, nothing more

NOTE: Windows and Linux support are not tested.

## Architecture

rrsh uses a custom encrypted transport layer to evade standard network signatures:

1. **Handshake:** ECDH (X25519) key exchange to derive a shared secret.
2. **KDF:** HKDF-SHA256 to derive distinct Tx/Rx keys.
3. **Transport:** ChaCha20Poly1305 with stateful nonces (preventing replay attacks).
4. **Encoding:** Custom length-prefixed framing (Big Endian u16).
5. **I/O**: Tokio-based async I/O and cross-platform PTY management for interactive shell support.

## Building

Build instructions for building on macOS for various platforms:

### Linux

```
cargo install cargo-zigbuild # brew install zig
rustup target add x86_64-unknown-linux-musl
cargo zigbuild --target x86_64-unknown-linux-musl --release --bins
```

### Windows

```
cargo install cargo-xwinbuild
rustup target add x86_64-pc-windows-msvc
cargo xwin build --target x86_64-pc-windows-msvc --release --bins
```

### Mac

```
cargo build --release --bins
```

## Running

Victim: `cargo run --bin rrsh --release`

Listener: `cargo run --bin listener --release`


## Detection

This is a personal learning project but indeed, someone might misuse it since it's public so I also publish a Yara rule with it to detect naive uses:

```
rule Rust_Reverse_Shell {
    strings:
        $sigma = { 
            65 78 70 61 [0-16]
            6E 64 20 33 [0-16]
            AD DE 62 79 [0-16]
            EF BE 20 6B
        }

        // might be found in the linux build
        $pubkey_section = {
            98 f3 d4 36 [0-16] 88 be 80 1c [0-16] 18 ca ca b0
        }

        $goodbye_string = "[*] Goodbye"
        $spawn_string = "failed to spawn:"
        $aead_string = "auth tag failed"

    condition:
        (uint16(0) == 0x5A4D or uint32(0) == 0xFEEDFACF or uint32(0) == 0x464C457F) and
        4 of them and filesize > 200KB
}
```

Also submitted to VT:

 - https://www.virustotal.com/gui/file/78407d5f91f824972d26bc371b522b5a1527135a964411ee65df8aeee5ed8adb
 - https://www.virustotal.com/gui/file/65f8e7637d2c2ef79ba861d9a650f7f40d514b103aa16019d7aca5147c366b82
 - https://www.virustotal.com/gui/file/b950b6ce403ceb7ebd12b6a6aea5382b7d63a0696ebb155d8471ea39f95f593a

