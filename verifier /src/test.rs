use ark_bn254::Bn254;
use ark_groth16::{prepare_verifying_key, Groth16};
use ark_serialize::CanonicalSerialize;
use ark_snark::SNARK;
use num_bigint::BigUint;
use num_traits::Num;
use sp1_sdk::SP1ProofWithPublicValues;
use sp1_verifier::Groth16Verifier;

#[test]
fn test_convert_gnark_to_ark() {
    use crate::ark_converter::{
        load_ark_groth16_verifying_key_from_bytes, load_ark_proof_from_bytes,
        load_ark_public_inputs_from_bytes,
    };
    use crate::GROTH16_VK_3_0_0_BYTES;

    // Read the serialized SP1ProofWithPublicValues from the file.
    let sp1_proof_with_public_values_file = "../proofs/fibonacci_proof.bin";
    let sp1_proof_with_public_values =
        SP1ProofWithPublicValues::load(&sp1_proof_with_public_values_file).unwrap();

    let proof_bytes = sp1_proof_with_public_values.bytes();
    let sp1_public_inputs = sp1_proof_with_public_values.public_values.to_vec();

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

    let sp1_vkey_hash = format!("0x{}", hex::encode(&vkey_hash));

    let sp1_verified = Groth16Verifier::verify(
        &proof_bytes,
        &sp1_public_inputs,
        &sp1_vkey_hash,
        &GROTH16_VK_3_0_0_BYTES,
    );
    // Check that SP1 test proof is correct before converting
    assert!(sp1_verified.is_ok());

    // Convert SP1 proof to Ark format
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
    // Serialize public inputs
    ark_public_inputs.iter().for_each(|input| {
        input
            .serialize_compressed(&mut ark_public_inputs_serialized)
            .unwrap();
    });

    // Construct Ark Groth16 Verifying Key
    let ark_groth16_vk = load_ark_groth16_verifying_key_from_bytes(GROTH16_VK_3_0_0_BYTES).unwrap();
    let ark_pvk = prepare_verifying_key(&ark_groth16_vk);

    // Verify Ark Groth16 proof
    let ark_verified =
        Groth16::<Bn254>::verify_with_processed_vk(&ark_pvk, &ark_public_inputs, &ark_proof)
            .unwrap();
    assert!(ark_verified);

    // Print Bytes to pass it on the Sui verifier
    let mut ark_groth16_serialized = Vec::new();
    ark_groth16_vk
        .serialize_compressed(&mut ark_groth16_serialized)
        .unwrap();

    println!("Ark Groth16 VK: {}", hex::encode(ark_groth16_serialized));
    println!("Ark Proof: {}", hex::encode(ark_proof_serialized));
    println!(
        "Ark Public Inputs: {}",
        hex::encode(ark_public_inputs_serialized)
    );
}
