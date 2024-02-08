use std::{fs, io::BufReader, marker::PhantomData};

use halo2_wrong_ecc::halo2::{halo2curves::{bn256::{Bn256, Fr as BnScalar}, CurveAffine}, poly::{commitment::Params, kzg::commitment::ParamsKZG}};
use halo2_wrong_ecc::halo2::halo2curves::secp256k1::Secp256k1Affine as Secp256k1;
use rand::thread_rng;
use snark_verifier::{loader::evm::encode_calldata, util::arithmetic::Curve};
use snark_verifier::util::arithmetic::Group;
use wasm_bindgen::prelude::wasm_bindgen;
use serde_json::Value as JsonValue;

use crate::{circuits::batchverify::IntegratedCircuit, generator::{gen_pk, gen_proof, gen_srs}};

pub mod generator;
pub mod circuits;


#[wasm_bindgen]
pub fn prove(input: &str) -> std::string::String {

    // TODO parse input json, like {"private_a": 3, "private_b": 4}
    let input_v: JsonValue = serde_json::from_str(&input).unwrap();
    let item_str = input_v.as_array().unwrap()[0].as_str().unwrap();
    let v: JsonValue = serde_json::from_str(&item_str).unwrap();



    // TODO replace your params
    // invoke gen_srs() to get your params
    // let params_hex = "";
    // let params_raw = hex::decode(params_hex).unwrap();
    // let params = ParamsKZG::<Bn256>::read(&mut BufReader::new(params_raw.as_slice()))
    //     .expect("restore params error");
    
    let params = gen_srs(20);

    // The input data is length-fixed only
    let mut rng = thread_rng();
    let aux_generator = <Secp256k1 as CurveAffine>::CurveExt::random(&mut rng).to_affine();

    let empty_circuit = IntegratedCircuit::<Secp256k1, BnScalar> {
        aux_generator: aux_generator,
        window_size: 4,
        batch_size: 2,
        _marker: PhantomData,
    };

    let pk = gen_pk(&params, &empty_circuit);

    // TODO public info
    let instances = vec![vec![]];

    let proof = gen_proof(&params, &pk, empty_circuit.clone(), &instances);
    let calldata = encode_calldata(&instances, &proof);

    format!(
        r#"{}"#,
        hex::encode(&proof),
    )
}
