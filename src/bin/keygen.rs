use x25519_dalek::{StaticSecret, PublicKey};
use rand_core::OsRng;

fn main() {
    let server_secret = StaticSecret::random_from_rng(OsRng);
    let server_public = PublicKey::from(&server_secret);

    println!("Server Private: {:?}", server_secret.to_bytes());
    println!("Server Public: {:?}", server_public.as_bytes());
}

