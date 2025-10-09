// SPDX-License-Identifier: Apache-2.0

use std::{
    io,
    sync::{Mutex, RwLock},
};

use actix_web::{cookie::Cookie, get, post, web, App, HttpRequest, HttpResponse, HttpServer};
use aes::cipher::KeyInit;
use aes_gcm::{
    aead::{generic_array::GenericArray, AeadMutInPlace},
    Aes256Gcm, Nonce,
};
use aes_kw::{Kek, KekAes256};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, prelude::BASE64_STANDARD, Engine};
use clap::Parser;
use kbs_types::{Challenge, ProtectedHeader, Request, Response, TeePubKey};
use lazy_static::lazy_static;
use p256::{
    ecdh::EphemeralSecret, elliptic_curve::sec1::FromEncodedPoint, EncodedPoint, PublicKey,
};
use rand::Rng;
use serde_json::{json, Value};
use sev::firmware::guest::AttestationReport;
use uuid::Uuid;

const AES_GCM_256_ALGORITHM: &str = "A256GCM";
const AES_GCM_256_KEY_BITS: u32 = 256;
const ECDH_ES_A256KW: &str = "ECDH-ES+A256KW";
const P256_CURVE: &str = "P-256";
const EC_KTY: &str = "EC";

lazy_static! {
    pub static ref KEY: RwLock<Vec<(String, String)>> = RwLock::new(Vec::new());
    pub static ref MEASUREMENT: RwLock<Vec<u8>> = RwLock::new(Vec::new());
    pub static ref SECRET: RwLock<Vec<u8>> = RwLock::new(Vec::new());
    pub static ref ATTESTED: Mutex<bool> = Mutex::new(false);
}

#[derive(Debug, Parser)]
struct Args {
    #[arg(long, short)]
    pub measurement: Option<String>,
    #[arg(long, short)]
    pub secret: Option<String>,
}

fn launch_measurement() -> Vec<u8> {
    MEASUREMENT.read().unwrap().clone()
}

fn secret() -> Vec<u8> {
    SECRET.read().unwrap().clone()
}

#[actix_web::main]
async fn main() -> io::Result<()> {
    let args = Args::parse();

    if args.measurement.is_some() {
        let measurement = args.measurement.clone().unwrap();

        let mut bytes = hex::decode(measurement).unwrap();
        let mut m = MEASUREMENT.write().unwrap();
        m.append(&mut bytes);
    }

    if args.secret.is_some() {
        let secret = args.secret.clone().unwrap();

        let mut bytes = hex::decode(secret).unwrap();
        let mut s = SECRET.write().unwrap();
        s.append(&mut bytes);
    }

    HttpServer::new(|| {
        App::new().service(
            web::scope("/kbs/v0")
                .service(auth)
                .service(attest)
                .service(resource),
        )
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}

#[post("/auth")]
pub async fn auth(req: web::Json<Request>) -> HttpResponse {
    let cookie = Cookie::build("kbs-session-id", Uuid::new_v4().to_string()).finish();

    let req = req.into_inner();
    if req.version != "0.4.0" {
        return HttpResponse::ExpectationFailed().into();
    }

    let c = Challenge {
        nonce: BASE64_STANDARD.encode(Uuid::new_v4().as_bytes()),
        extra_params: Value::String(String::new()),
    };

    HttpResponse::Ok().cookie(cookie).json(c)
}

/// Placeholder for attesting a client's TEE evidence.
#[post("/attest")]
pub async fn attest(req: HttpRequest, attest: web::Json<kbs_types::Attestation>) -> HttpResponse {
    let _cookie = req.cookie("kbs-session-id").unwrap();

    let attest = attest.into_inner();

    let serde_json::Value::Object(tee_evidence) = attest.tee_evidence.primary_evidence else {
        panic!("evidence not a base64 string");
    };

    let evidence = {
        let report = tee_evidence.get("snp-report").unwrap();

        let Value::String(s) = report else {
            panic!("SNP attestation report is not represented as a base64-encoded JSON string");
        };

        BASE64_STANDARD.decode(s).unwrap()
    };

    let report: AttestationReport = unsafe { std::ptr::read(evidence.as_ptr() as *const _) };

    if report.measurement.as_ref() == launch_measurement() {
        let mut val = ATTESTED.lock().unwrap();
        *val = true;
    } else {
        println!(
            "\nlaunch measurement not as expected\nexpected:{:?}\nfound:{:?}",
            hex::encode(launch_measurement()),
            hex::encode(report.measurement.as_ref())
        );

        return HttpResponse::ExpectationFailed().into();
    }

    let tee_pubkey = attest.runtime_data.tee_pubkey;
    let TeePubKey::EC {
        crv: _,
        alg: _,
        x,
        y,
    } = tee_pubkey
    else {
        return HttpResponse::ExpectationFailed().into();
    };

    let mut key = KEY.write().unwrap();

    key.push((x, y));

    let json = json!({
        "token": "test-token".to_string(),
    });

    HttpResponse::Ok().json(json)
}

#[get("/resource/default/sample/test")]
pub async fn resource(_req: HttpRequest) -> HttpResponse {
    let attested = ATTESTED.lock().unwrap();
    if !*attested {
        println!("client is unattested, not releasing secret");
        return HttpResponse::ExpectationFailed().into();
    }

    let mut payload = secret();

    let mut rng = rand::thread_rng();

    // 1. Generate a random CEK
    let cek = Aes256Gcm::generate_key(&mut rng);

    let mut key = KEY.write().unwrap();

    let (x, y) = key.pop().unwrap();

    let x: [u8; 32] = URL_SAFE_NO_PAD.decode(x).unwrap().try_into().unwrap();
    let y: [u8; 32] = URL_SAFE_NO_PAD.decode(y).unwrap().try_into().unwrap();
    let client_point = EncodedPoint::from_affine_coordinates(
        &GenericArray::from(x),
        &GenericArray::from(y),
        false,
    );
    let public_key = PublicKey::from_encoded_point(&client_point)
        .into_option()
        .unwrap();
    let encrypter_secret = EphemeralSecret::random(&mut rng);
    let z = encrypter_secret
        .diffie_hellman(&public_key)
        .raw_secret_bytes()
        .to_vec();
    let mut key_derivation_materials = Vec::new();
    key_derivation_materials.extend_from_slice(&(ECDH_ES_A256KW.len() as u32).to_be_bytes());
    key_derivation_materials.extend_from_slice(ECDH_ES_A256KW.as_bytes());
    key_derivation_materials.extend_from_slice(&(0_u32).to_be_bytes());
    key_derivation_materials.extend_from_slice(&(0_u32).to_be_bytes());
    key_derivation_materials.extend_from_slice(&AES_GCM_256_KEY_BITS.to_be_bytes());
    let mut wrapping_key = vec![0; 32];
    concat_kdf::derive_key_into::<sha2::Sha256>(&z, &key_derivation_materials, &mut wrapping_key)
        .unwrap();
    let wrapping_key: [u8; 32] = wrapping_key.try_into().unwrap();
    let wrapping_key: KekAes256 = Kek::new(&GenericArray::from(wrapping_key));
    let mut encrypted_key = vec![0; 40];
    encrypted_key.resize(40, 0);
    let cek = cek.to_vec();
    wrapping_key.wrap(&cek, &mut encrypted_key).unwrap();

    let point = EncodedPoint::from(encrypter_secret.public_key());
    let epk_x = point.x().unwrap();
    let epk_y = point.y().unwrap();
    let epk_x = URL_SAFE_NO_PAD.encode(epk_x);
    let epk_y = URL_SAFE_NO_PAD.encode(epk_y);
    let protected = ProtectedHeader {
        alg: ECDH_ES_A256KW.to_string(),
        enc: AES_GCM_256_ALGORITHM.to_string(),
        other_fields: json!({
            "epk": {
                "crv": P256_CURVE,
                "kty": EC_KTY,
                "x": epk_x,
                "y": epk_y
            }
        })
        .as_object()
        .unwrap()
        .clone(),
    };

    // 3. Encrypt content with CEK
    let mut cek_cipher = Aes256Gcm::new(GenericArray::from_slice(&cek));

    let iv = rand::thread_rng().gen::<[u8; 12]>();
    let nonce = Nonce::from_slice(&iv);
    let aad = protected.generate_aad().unwrap();

    let tag = cek_cipher
        .encrypt_in_place_detached(nonce, &aad, &mut payload)
        .unwrap();

    let resp = Response {
        protected,
        encrypted_key,
        iv: iv.into(),
        ciphertext: payload,
        aad: None,
        tag: tag.to_vec(),
    };

    HttpResponse::Ok().json(resp)
}
