//#![crate_name = "microsalt"]
//#![crate_type = "lib"]

///High Level Crypto library for your trusty rusty programs
///"TweetNaCl is the world's first auditable high-security cryptographic library."
//https://github.com/erik/knuckle/blob/master/src/lib.rs
// Primitives
//
// The following cryptographic primitives are used with this library.
//
//  Module        | Primitive
//  ------------- | -------------
//  cryptobox     | Curve25519/Salsa20/Poly1305
//  hash          | SHA-512
//  secretbox     | Salsa20/Poly1305
//  sign          | Ed25519
//  stream        | Salsa20

extern crate libc;
extern crate rand;
#[macro_use]
extern crate index_fixed;

#[macro_use]
extern crate unwrap;

extern crate rustc_serialize;

/// Interface to strong cryptographic hash function.
pub mod hash;
///  Interface to 
pub mod onetimeauth;
mod shared;
pub mod stream;
pub mod sign;
pub mod secretbox;
pub mod boxy;



use rand::Rng;
//random byte generator
pub fn randombytes(x: &mut [u8]){
    let mut rng = rand::OsRng::new().unwrap();
    rng.fill_bytes(x);
}






