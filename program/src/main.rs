#![no_main]

use std::hint::black_box;
use elgamal_lib::*;

sp1_zkvm::entrypoint!(main);

pub fn main() {
    let repetitions = sp1_zkvm::io::read::<u32>();
    let exec_mode = sp1_zkvm::io::read::<ExecMode>();
    let mode = sp1_zkvm::io::read::<Mode>();

    match mode {
        Mode::Encrypt => encrypt(exec_mode, repetitions),
        Mode::Decrypt => decrypt(exec_mode, repetitions),
    }
}

fn encrypt(exec_mode: ExecMode, repetitions: u32) {
    let pk = sp1_zkvm::io::read::<PublicKey>();
    let nonce = sp1_zkvm::io::read::<Scalar>();
    let message = sp1_zkvm::io::read::<RistrettoPoint>();

    if exec_mode == ExecMode::All {
        for _ in 0..repetitions {
            black_box(black_box(pk).encrypt(black_box(nonce), black_box(&message)));
        }
    }
}

fn decrypt(exec_mode: ExecMode, repetitions: u32) {
    let sk = sp1_zkvm::io::read::<SecretKey>();
    let ciphertext = sp1_zkvm::io::read::<Ciphertext>();

    if exec_mode == ExecMode::All {
        for _ in 0..repetitions {
            black_box(black_box(&sk).decrypt(black_box(&ciphertext)));
        }
    }
}

