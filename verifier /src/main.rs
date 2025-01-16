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
use sui_sp1::GROTH16_VK_3_0_0_BYTES;

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

    let (ark_groth16_serialized_hex, ark_proof_serialized_hex, ark_public_inputs_serialized_hex) =
        convert_sp1_gnark_to_ark_format(sp1_proof_with_public_values);

    println!("\n=== Ark Groth16 Verification Components ===\n");
    
    println!("1. Verifying Key bytes:");
    println!("---------------------------");
    println!("{}\n", ark_groth16_serialized_hex);
    
    println!("2. Proof bytes:");
    println!("---------------------------");
    println!("{}\n", ark_proof_serialized_hex);
    
    println!("3. Public Inputs bytes:");
    println!("---------------------------");
    println!("{}\n", ark_public_inputs_serialized_hex);
}

fn convert_sp1_gnark_to_ark_format(
    sp1_proof_with_public_values: SP1ProofWithPublicValues,
) -> (String, String, String) {
    let proof_bytes = sp1_proof_with_public_values.bytes();

    let proof = sp1_proof_with_public_values
        .proof
        .try_as_groth_16()
        .expect("Failed to convert proof to Groth16 proof");

    // Convert vkey hash to bytes.
    let vkey_hash = BigUint::from_str_radix(&proof.public_inputs[0], 10)
        .unwrap()
        .to_bytes_be();

    // To match the standard format, the 31 byte vkey hash is left padded with a 0 byte.
    let mut padded_vkey_hash = vec![0];
    padded_vkey_hash.extend_from_slice(&vkey_hash);
    let vkey_hash = padded_vkey_hash;

    // Ark Proof
    let ark_proof = load_ark_proof_from_bytes(&proof_bytes[4..]).unwrap();
    let mut ark_proof_serialized = Vec::new();
    ark_proof
        .serialize_compressed(&mut ark_proof_serialized)
        .unwrap();

    // Ark Public Inputs
    let mut ark_padded_vkey_hash: [u8; 32] = [0u8; 32];
    ark_padded_vkey_hash[..vkey_hash.len()].copy_from_slice(&vkey_hash);

    let committed_values_digest = BigUint::from_str_radix(&proof.public_inputs[1], 10)
        .unwrap()
        .to_bytes_be();
    let mut padded_committed_values_digest = [0u8; 32];
    padded_committed_values_digest[..committed_values_digest.len()]
        .copy_from_slice(&committed_values_digest);

    let ark_public_inputs =
        load_ark_public_inputs_from_bytes(&ark_padded_vkey_hash, &padded_committed_values_digest);
    let mut ark_public_inputs_serialized = Vec::new();
    ark_public_inputs.iter().for_each(|input| {
        input
            .serialize_compressed(&mut ark_public_inputs_serialized)
            .unwrap();
    });

    // Ark Groth16
    let ark_groth16_vk = load_ark_groth16_verifying_key_from_bytes(GROTH16_VK_3_0_0_BYTES).unwrap();
    let ark_pvk = prepare_verifying_key(&ark_groth16_vk);

    // Verify Ark proof
    let ark_verified =
        Groth16::<Bn254>::verify_with_processed_vk(&ark_pvk, &ark_public_inputs, &ark_proof)
            .unwrap();
    assert!(ark_verified);

    // Print Bytes to pass it on the Sui verifier
    let mut ark_groth16_serialized = Vec::new();
    ark_groth16_vk
        .serialize_compressed(&mut ark_groth16_serialized)
        .unwrap();
    let ark_groth16_serialized_hex: String = hex::encode(ark_groth16_serialized);
    let ark_proof_serialized_hex: String = hex::encode(ark_proof_serialized);
    let ark_public_inputs_serialized_hex: String = hex::encode(ark_public_inputs_serialized);

    (
        ark_groth16_serialized_hex,
        ark_proof_serialized_hex,
        ark_public_inputs_serialized_hex,
    )
}
