use std::env;
use rand::thread_rng;
use sp1_sdk::{SP1Stdin, include_elf, CpuProver, Prover};
use elgamal_lib::*;

pub const ELF: &[u8] = include_elf!("elgamal-program");

fn main() {
    sp1_sdk::utils::setup_logger();

    let client = CpuProver::new();
    let (proving_key, verifying_key) = client.setup(ELF);

    let mut rng = thread_rng();

    // let mut results = vec![];
    //
    // for _ in 0..1000 {
    let secret_key = SecretKey::new(Scalar::random(&mut rng));
    let public_key = PublicKey::from(&secret_key);
    let nonce = Scalar::random(&mut rng);
    let message = RistrettoPoint::random(&mut rng);
    let ciphertext = public_key.encrypt(nonce, &message);

    println!("[+] Running encrypt:");

    #[cfg(feature = "profiling")]
    unsafe {
        env::set_var("TRACE_FILE", "encrypt.json");
    }

    let mut stdin = SP1Stdin::new();
    stdin.write(&ExecMode::All);
    stdin.write(&Mode::Encrypt);
    stdin.write(&public_key);
    stdin.write(&nonce);
    stdin.write(&message);
    let (mut public_values, report) = client.execute(&ELF, &stdin).run().unwrap();
    let enc_total_instruction_count = report.total_instruction_count();
    println!("- Total Instructions: {enc_total_instruction_count}");
    let ct_vm: Ciphertext = public_values.read();
    assert_eq!(ct_vm, ciphertext);

    #[cfg(not(feature = "profiling"))]
    {
        let now = std::time::Instant::now();
        let proof = client.prove(&proving_key, &stdin).compressed().run().unwrap();
        let enc_total_proving_time = now.elapsed();
        println!("- Total Proving Time: {enc_total_proving_time:?}");
        client.verify(&proof, &verifying_key).unwrap();

        let mut stdin = SP1Stdin::new();
        stdin.write(&ExecMode::Baseline);
        stdin.write(&Mode::Encrypt);
        stdin.write(&public_key);
        stdin.write(&nonce);
        stdin.write(&message);
        let (_, report) = client.execute(&ELF, &stdin).run().unwrap();
        let enc_net_instruction_count = enc_total_instruction_count - report.total_instruction_count();
        println!("- Net Instructions: {enc_net_instruction_count}", );

        let now = std::time::Instant::now();
        let proof = client.prove(&proving_key, &stdin).compressed().run().unwrap();
        let enc_net_proving_time = now.elapsed() - enc_total_proving_time;
        println!("- Net Proving Time: {enc_net_proving_time:?}");
        client.verify(&proof, &verifying_key).unwrap();
    }


    println!("[+] Running decrypt:");

    #[cfg(feature = "profiling")]
    unsafe {
        env::set_var("TRACE_FILE", "decrypt.json");
    }

    let mut stdin = SP1Stdin::new();
    stdin.write(&ExecMode::All);
    stdin.write(&Mode::Decrypt);
    stdin.write(&secret_key);
    stdin.write(&ciphertext);
    let (mut public_values, report) = client.execute(&ELF, &stdin).run().unwrap();
    let dec_total_instruction_count = report.total_instruction_count();
    println!("- Total Instructions: {dec_total_instruction_count}");
    let decrypted_message_vm: RistrettoPoint = public_values.read();
    assert_eq!(decrypted_message_vm, secret_key.decrypt(&ciphertext));

    #[cfg(not(feature = "profiling"))]
    {
        let now = std::time::Instant::now();
        let proof = client.prove(&proving_key, &stdin).compressed().run().unwrap();
        let dec_total_proving_time = now.elapsed();
        println!("- Total Proving Time: {dec_total_proving_time:?}");
        client.verify(&proof, &verifying_key).unwrap();

        let mut stdin = SP1Stdin::new();
        stdin.write(&ExecMode::Baseline);
        stdin.write(&Mode::Decrypt);
        stdin.write(&secret_key);
        stdin.write(&ciphertext);
        let (_, report) = client.execute(&ELF, &stdin).run().unwrap();
        let dec_net_instruction_count = dec_total_instruction_count - report.total_instruction_count();
        println!("- Net Instructions: {dec_net_instruction_count}");

        let now = std::time::Instant::now();
        let proof = client.prove(&proving_key, &stdin).compressed().run().unwrap();
        let dec_net_proving_time = now.elapsed() - dec_total_proving_time;
        println!("- Net Proving Time: {dec_net_proving_time:?}");
        client.verify(&proof, &verifying_key).unwrap();
    }
    //     results.push((
    //         enc_total_instruction_count,
    //         enc_net_instruction_count,
    //         enc_total_proving_time,
    //         dec_total_instruction_count,
    //         dec_net_instruction_count,
    //         dec_total_proving_time,
    //     ));
    // }
    //

    // // Print avg
    //
    // let len = results.len() as u64;
    //
    // let (
    //     enc_total_instruction_count,
    //     enc_net_instruction_count,
    //     enc_total_proving_time,
    //     dec_total_instruction_count,
    //     dec_net_instruction_count,
    //     dec_total_proving_time,
    // ) = results
    //     .into_iter()
    //     .reduce(
    //         |acc, item| (
    //             acc.0 + item.0,
    //             acc.1 + item.1,
    //             acc.2 + item.2,
    //             acc.3 + item.3,
    //             acc.4 + item.4,
    //             acc.5 + item.5,
    //         )
    //     ).unwrap();
    //
    // println!("[+] Results:");
    // println!("- Avg Encrypt Total Instructions: {}", enc_total_instruction_count / len);
    // println!("- Avg Encrypt Net Instructions: {}", enc_net_instruction_count / len);
    // println!("- Avg Encrypt Total Proving Time: {} s", enc_total_proving_time.as_secs() / len);
    // println!("- Avg Decrypt Total Instructions: {}", dec_total_instruction_count / len);
    // println!("- Avg Decrypt Net Instructions: {}", dec_net_instruction_count / len);
    // println!("- Avg Decrypt Total Proving Time: {} s", dec_total_proving_time.as_secs() / len);
}
