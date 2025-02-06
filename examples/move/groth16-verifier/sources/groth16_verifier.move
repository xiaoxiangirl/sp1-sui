/// Module: groth16_verifier
module groth16_verifier::groth16_verifier;

use sui::groth16::{
    prepare_verifying_key,
    proof_points_from_bytes,
    public_proof_inputs_from_bytes,
    bn254,
    verify_groth16_proof
};

public fun verify_groth16_bn254_proof(
    groth16_vk: vector<u8>,
    public_inputs: vector<u8>,
    proof: vector<u8>,
) {
    let pvk = prepare_verifying_key(&bn254(), &groth16_vk);
    let public_inputs = public_proof_inputs_from_bytes(public_inputs);
    let proof_points = proof_points_from_bytes(proof);

    assert!(verify_groth16_proof(&bn254(), &pvk, &public_inputs, &proof_points));
}
