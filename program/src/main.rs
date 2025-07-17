#![no_main]

use elgamal_lib::*;

sp1_zkvm::entrypoint!(main);

pub fn main() {
    let exec_mode = sp1_zkvm::io::read::<ExecMode>();
    let mode = sp1_zkvm::io::read::<Mode>();

    match mode {
        Mode::Encrypt => encrypt(exec_mode),
        Mode::Decrypt => decrypt(exec_mode),
    }
}

fn encrypt(exec_mode: ExecMode) {
    let pk = sp1_zkvm::io::read::<PublicKey>();
    let nonce = sp1_zkvm::io::read::<Scalar>();
    let message = sp1_zkvm::io::read::<RistrettoPoint>();

    let mut ciphertext = Ciphertext::default();

    if exec_mode == ExecMode::All {
        ciphertext = pk.encrypt(nonce, &message);
    }

    sp1_zkvm::io::commit(&ciphertext);
}

fn decrypt(exec_mode: ExecMode) {
    let sk = sp1_zkvm::io::read::<SecretKey>();
    let ciphertext = sp1_zkvm::io::read::<Ciphertext>();

    let mut decrypted_message = RistrettoPoint::default();

    if exec_mode == ExecMode::All {
        decrypted_message = sk.decrypt(&ciphertext);
    }

    sp1_zkvm::io::commit(&decrypted_message);
}

