// SPDX-License-Identifier: Apache-2.0

use std::{cmp::min, collections::BTreeMap, io, sync::RwLock};

use actix_web::{cookie::Cookie, post, web, App, HttpRequest, HttpResponse, HttpServer};
use aes::{
    cipher::{BlockEncrypt, KeyInit},
    Aes128,
};
use base64::prelude::*;
use elliptic_curve::JwkEcKey;
use kbs_types::{Challenge, ProtectedHeader, Request, Response, TeePubKey};
use lazy_static::lazy_static;
use p384::{ecdh::EphemeralSecret, EncodedPoint, NistP384};
use rand_core::OsRng;
use serde_json::Value;
use sha2::Sha256;
use uuid::Uuid;

lazy_static! {
    pub static ref KEY: RwLock<Vec<(JwkEcKey, EphemeralSecret)>> = RwLock::new(Vec::new());
}

#[actix_web::main]
async fn main() -> io::Result<()> {
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
pub async fn auth(_req: web::Json<Request>) -> HttpResponse {
    let cookie = Cookie::build("kbs-session-id", Uuid::new_v4().to_string()).finish();

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

    let ec = match attest.tee_pubkey {
        TeePubKey::EC {
            crv: _,
            alg: _,
            x,
            y,
        } => {
            let x = BASE64_URL_SAFE.decode(x).unwrap();
            let y = BASE64_URL_SAFE.decode(y).unwrap();

            let epoint = EncodedPoint::from_affine_coordinates(
                x.as_slice().into(),
                y.as_slice().into(),
                false,
            );
            let jwk = JwkEcKey::from_encoded_point::<NistP384>(&epoint).unwrap();
            let private = EphemeralSecret::random(&mut OsRng);

            (jwk, private)
        }
        _ => panic!("invalid RSA key"),
    };

    let mut key = KEY.write().unwrap();
    key.push(ec);

    HttpResponse::Ok().into()
}

#[post("/{resouce_id}")]
pub async fn resource(_req: HttpRequest, resource_id: web::Path<String>) -> HttpResponse {
    let id = resource_id.into_inner();
    if id != "svsm_secret" {
        panic!("invalid resource id");
    }

    let (jwk, private) = {
        let mut vec = KEY.write().unwrap();
        vec.pop().unwrap()
    };

    let public = jwk.to_public_key().unwrap();
    let shared = private.diffie_hellman(&public);
    let hkdf = shared.extract::<Sha256>(None);

    let mut out = [0u8; 16];
    let empty: [u8; 0] = [];

    hkdf.expand(&empty, &mut out).unwrap();
    let aes = Aes128::new_from_slice(&out).unwrap();

    let plaintext = String::from("hello, SVSM! This message is from the attestation server");

    let mut bytes: Vec<u8> = Vec::new();
    let mut ptr = 0;
    let pt_bytes = plaintext.as_bytes();
    let len = pt_bytes.len();

    while ptr < len {
        let mut enc = [0u8; 16];
        let remain = min(16, len - ptr);
        enc[..remain].copy_from_slice(&pt_bytes[ptr..ptr + remain]);

        aes.encrypt_block((&mut enc).into());
        bytes.append(&mut enc.to_vec());
        ptr += 16;
    }

    let protected = ProtectedHeader {
        alg: "ECDHP384".to_string(),
        enc: "AES128".to_string(),
        other_fields: BTreeMap::new(),
    };

    let resp = Response {
        protected,
        encrypted_key: private.public_key().to_sec1_bytes().to_vec(),
        aad: None,
        iv: "".to_string().into(),
        ciphertext: bytes,
        tag: "".to_string().into(),
    };

    HttpResponse::Ok().json(resp)
}
