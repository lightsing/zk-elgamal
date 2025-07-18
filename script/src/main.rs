use std::env;
use rand::thread_rng;
use sp1_sdk::{SP1Stdin, include_elf, CpuProver, Prover, SP1ProvingKey, SP1VerifyingKey};
use elgamal_lib::*;

pub const ELF: &[u8] = include_elf!("elgamal-program");

struct Case {
    secret_key: SecretKey,
    public_key: PublicKey,
    nonce: Scalar,
    message: RistrettoPoint,
    ciphertext: Ciphertext,
}

fn main() {
    sp1_sdk::utils::setup_logger();

    let client = CpuProver::new();
    let (proving_key, verifying_key) = client.setup(ELF);

    let mut rng = thread_rng();

    let secret_key = SecretKey::new(Scalar::random(&mut rng));
    let public_key = PublicKey::from(&secret_key);
    let nonce = Scalar::random(&mut rng);
    let message = RistrettoPoint::random(&mut rng);
    let ciphertext = public_key.encrypt(nonce, &message);

    let case = Case {
        secret_key,
        public_key,
        nonce,
        message,
        ciphertext,
    };

    run(
        &client,
        &proving_key,
        &verifying_key,
        &case,
        1000, // number of repetitions
        Mode::Encrypt,
    );

    run(
        &client,
        &proving_key,
        &verifying_key,
        &case,
        1000, // number of repetitions
        Mode::Decrypt,
    );
}

fn run(
    client: &CpuProver,
    proving_key: &SP1ProvingKey,
    verifying_key: &SP1VerifyingKey,
    case: &Case,
    repetitions: u32,
    mode: Mode,
){
    match mode {
        Mode::Encrypt => println!("[+] Running encrypt:"),
        Mode::Decrypt => println!("[+] Running decrypt:"),
    }

    if cfg!(feature = "profiling") {
        env::set_var("TRACE_FILE", match mode {
            Mode::Encrypt => format!("encrypt-{repetitions}.json"),
            Mode::Decrypt => format!("decrypt-{repetitions}.json"),
        });
    }

    let mut stdin = SP1Stdin::new();
    stdin.write(&repetitions);
    stdin.write(&ExecMode::All);
    match mode {
        Mode::Encrypt => write_encrypt_stdin(case, &mut stdin),
        Mode::Decrypt => write_decrypt_stdin(case, &mut stdin),
    }

    let (_, report) = client.execute(&ELF, &stdin).run().unwrap();
    let total_instruction_count = report.total_instruction_count();
    println!("- Total Instructions: {total_instruction_count}");

    if !cfg!(feature = "profiling") {
        let now = std::time::Instant::now();
        let proof = client.prove(&proving_key, &stdin).compressed().run().unwrap();
        let total_proving_time = now.elapsed();
        // sanity check
        client.verify(&proof, &verifying_key).unwrap();

        // run baseline
        let mut stdin = SP1Stdin::new();
        stdin.write(&repetitions);
        stdin.write(&ExecMode::Baseline);
        match mode {
            Mode::Encrypt => write_encrypt_stdin(case, &mut stdin),
            Mode::Decrypt => write_decrypt_stdin(case, &mut stdin),
        }
        let (_, report) = client.execute(&ELF, &stdin).run().unwrap();
        let baseline_instruction_count = report.total_instruction_count();
        let net_instruction_count = total_instruction_count - baseline_instruction_count;
        let net_instruction_per_operation = net_instruction_count as f64 / repetitions as f64;

        let now = std::time::Instant::now();
        let proof = client.prove(&proving_key, &stdin).compressed().run().unwrap();
        let baseline_proving_time = now.elapsed();
        let net_proving_time = total_proving_time - baseline_proving_time;
        let net_proving_time_per_operation = net_proving_time / repetitions;

        // sanity check
        client.verify(&proof, &verifying_key).unwrap();


        println!("- Total Proving Time: {total_proving_time:?}");
        println!("- Baseline Instructions: {baseline_instruction_count}");
        println!("- Baseline Proving Time: {baseline_proving_time:?}");
        println!("- Net Instructions: {net_instruction_count}");
        println!("- Net Proving Time: {net_proving_time:?}");
        println!("- Net Instructions per operation: {net_instruction_per_operation:.2}");
        println!("- Net Proving Time per operation: {net_proving_time_per_operation:?}");
    }
}

fn write_encrypt_stdin(
    case: &Case,
    stdin: &mut SP1Stdin,
) {
    stdin.write(&Mode::Encrypt);
    stdin.write(&case.public_key);
    stdin.write(&case.nonce);
    stdin.write(&case.message);
}

fn write_decrypt_stdin(
    case: &Case,
    stdin: &mut SP1Stdin,
) {
    stdin.write(&Mode::Decrypt);
    stdin.write(&case.secret_key);
    stdin.write(&case.ciphertext);
}
