use std::{fs, io::BufReader, marker::PhantomData, time::Instant};

use batch_verify_circuit::{circuits::batchverify::IntegratedCircuit, generator::{gen_pk, gen_proof, gen_sol_verifier, gen_srs}};
use halo2_wrong_ecc::halo2::{halo2curves::{bn256::{Bn256, Fr as BnScalar}, CurveAffine}, poly::{commitment::Params, kzg::commitment::ParamsKZG}};
use halo2_wrong_ecc::halo2::halo2curves::secp256k1::Secp256k1Affine as Secp256k1;
use rand::thread_rng;
use snark_verifier::{loader::evm::{self, encode_calldata}, util::arithmetic::Curve};
use snark_verifier::util::arithmetic::Group;

fn main() {
    println!("hello");
    // let params_hex = "";
    let params_raw = fs::read("/Volumes/HIKVISION/project_rust/halo2-evm-verifier/output/params.bin").expect("read params file error");
    // let params_raw = hex::decode(params_hex).unwrap();

    let params = ParamsKZG::<Bn256>::read(&mut BufReader::new(params_raw.as_slice()))
        .expect("restore params error");

    // let params = gen_srs(20);

    // The input data is length-fixed only
    let mut rng = thread_rng();
    let aux_generator = <Secp256k1 as CurveAffine>::CurveExt::random(&mut rng).to_affine();

    let empty_circuit = IntegratedCircuit::<Secp256k1, BnScalar> {
        aux_generator: aux_generator,
        window_size: 4,
        batch_size: 2,
        _marker: PhantomData,
    };

    println!("gen_pk start");
    let start = Instant::now();
    let pk = gen_pk(&params, &empty_circuit);
    println!("gen_pk end");
    let duration = start.elapsed();

    println!("Time elapsed in expensive_function() is: {:?}", duration);

    // TODO instance circuit
    // let mut rng = thread_rng();
    // let aux_generator = <Secp256k1 as CurveAffine>::CurveExt::random(&mut rng).to_affine();
    // let circuit = IntegratedCircuit::<Secp256k1, BnScalar> {
    //     aux_generator,
    //     window_size: 4,
    //     batch_size: 4,
    //     _marker: PhantomData,
    // };

    // TODO public info
    // let instances = vec![vec![difficulty]];
    let instances = vec![vec![]];

    println!("gen_proof start");
    let start = Instant::now();
    let proof = gen_proof(&params, &pk, empty_circuit.clone(), &instances);
    println!("gen_proof end");
    let duration = start.elapsed();

    println!("Time elapsed in expensive_function() is: {:?}", duration);

    let calldata = encode_calldata(&instances, &proof);

    println!(
        r#"{{
    "proof": "0x{}",
    "calldata": "0x{}"
    }}"#,
        hex::encode(&proof),
        hex::encode(calldata),
    );

    // let sol_code = gen_sol_verifier(&params, empty_circuit, vec![])
    //             .expect("generate solidity file error");
    // println!(
    //    "Generated verifier contract size: {}",
    //     evm::compile_solidity(sol_code.as_str()).len()
    // );
    // fs::write("Verifier.sol", sol_code).expect("write verifier solidity error");
}
