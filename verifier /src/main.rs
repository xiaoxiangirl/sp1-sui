use ark_bn254::Bn254;
use ark_groth16::{prepare_verifying_key, Groth16};
use ark_serialize::CanonicalSerialize;
use ark_snark::SNARK;
use clap::Parser;
use num_bigint::BigUint;
use num_traits::Num;
use sp1_sdk::SP1ProofWithPublicValues;

use sui_sp1::ark_converter::{
    load_ark_groth16_verifying_key_from_bytes, load_ark_proof_from_bytes,
    load_ark_public_inputs_from_bytes,
};
use sui_sp1::{convert_sp1_gnark_to_ark, GROTH16_VK_3_0_0_BYTES};

/// CLI arguments
#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Path to the SP1 proof file
    #[arg(short, long, default_value = "../proofs/fibonacci_proof.bin")]
    proof_path: String,
}

fn main() {
    // Parse command line arguments
    let args = Args::parse();

    // Read the serialized SP1ProofWithPublicValues from the file.
    let sp1_proof_with_public_values = SP1ProofWithPublicValues::load(&args.proof_path).unwrap();

    let (ark_groth16_serialized_hex, ark_public_inputs_serialized_hex, ark_proof_serialized_hex) =
        convert_sp1_gnark_to_ark(sp1_proof_with_public_values);

    println!("\n=== Ark Groth16 Verification Components ===\n");

    println!("1. Verifying Key bytes:");
    println!("---------------------------");
    println!("{}\n", ark_groth16_serialized_hex);

    println!("2. Public Inputs bytes:");
    println!("---------------------------");
    println!("{}\n", ark_public_inputs_serialized_hex);

    println!("3. Proof bytes:");
    println!("---------------------------");
    println!("{}\n", ark_proof_serialized_hex);

}
