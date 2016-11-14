/////////////
//Signatures
/////////////
mod ed25519;
use std;
use shared;
//https://github.com/maidsafe/rust_sodium/blob/master/src/crypto/sign/mod.rs
// ----------------------------------------------------------------------------------
// |`crypto_sign`                         | PUBLICKEYBYTES | SECRETKEYBYTES | BYTES |
// |--------------------------------------|----------------|----------------|-------|
// |`crypto_sign_ed25519`                 | 32             | 64             | 64    |
// ----------------------------------------------------------------------------------

//https://github.com/erik/knuckle/blob/master/src/sign.rs
//https://github.com/jedisct1/libsodium/blob/master/src/libsodium/include/sodium/crypto_sign_ed25519.h
/// Number of bytes in the sign public key
pub const PUBLIC_KEY_BYTES: usize = 32;
/// Number of bytes in the sign private key
//#define crypto_sign_ed25519_SECRETKEYBYTES (32U + 32U)
//TODO:A tuple of two 32 bit for 64 bit is used like above i think thats for 32 bit arch so that the secret key is undercontrol
pub const SECRET_KEY_BYTES: usize = 64;
/// Bytes of padding used in each signed message
pub const SIGN_BYTES: usize = 64;
/// Number of bytes a signature is 
pub const SIGNATURE_LENGTH: usize = 64;

//https://github.com/erik/knuckle/blob/master/src/cryptobox.rs
//Key Generation
///A Pubic key for crypto box
pub type PublicKey = [u8; PUBLIC_KEY_BYTES];
///A secret key for crypto box
pub type SecretKey = [u8; SECRET_KEY_BYTES];


/// A asymmetric keypair containing matching public and private keys.
pub struct Keypair {
    /// Public key
    pub public: PublicKey,
    /// Private key
    pub secret: SecretKey
}

//For Secret key we must implement the drop trait to zero out the used memory
impl Drop for Keypair {
    fn drop(&mut self) {
        println!("Dropping Secret KEY, but must ZERO OUT MEMORY!!!!!");
        //use utils::memzero;
        //let &mut $name(ref mut v) = self;
        //memzero(v);
    }
}

impl Keypair {
    /// Generate a random matching public and private key.
    pub fn new() -> Keypair {
        let mut pk = [0u8; PUBLIC_KEY_BYTES];
        let mut sk = [0u8; SECRET_KEY_BYTES];

        ed25519::crypto_sign_keypair(&mut pk, &mut sk);
        //Return New Key Pair
        Keypair { public: pk, secret: sk }
    }

    /// Sign a given data 
    pub fn sign(&self, data: &[u8]) -> SignedData {
        let mut signed = std::iter::repeat(0).take(data.len() + SIGN_BYTES).collect::<Vec<_>>();

        let secret_key : SecretKey = self.secret;
        let public_key : PublicKey = self.public;

        ed25519::crypto_sign(&mut signed, data, &secret_key);

        SignedData {public_key: public_key, signed: signed}
    }

}


/// Encapsulates the verification key and signed message.
pub struct SignedData {
    /// Public key matching the key used to sign this message.
    pub public_key: PublicKey,
    /// Cryptographically signed message, containing both signature and message.
    pub signed: Vec<u8>
}

impl SignedData {
    ///Verify a signed message
    pub fn verify(&self) -> Option<Vec<u8>>  {
        let public_key : PublicKey = self.public_key;

        //LOOK INTO MORE SECURE MEMEORY ALLOCATION AND ZERO OUT
        let mut msg = std::iter::repeat(0).take(self.signed.len()).collect::<Vec<_>>();

        match ed25519::crypto_sign_open(&mut msg, &self.signed, &public_key) {
            Some(msg_len) => {
                println!("msg_len: {}", msg_len);
                unsafe {msg.set_len(msg_len as usize);}
                Some(msg)
            },
            None => None,
        }

    }
}



//this method is for detached signatures 
pub fn signature(data: &[u8], key: &SecretKey) -> Vec<u8> {
    //allocte vector to hold signature + data construct 
    //let mut signed = Vec::with_capacity(data.len() + SIGNATURE_LENGTH);
    let mut signed = std::iter::repeat(0).take(data.len() + SIGN_BYTES).collect::<Vec<_>>();
    ed25519::crypto_sign(&mut signed, data, &key);
    //signature is 64 bytes so we must fiind the difference 
    //let len = data.len() - SIGNATURE_LENGTH as usize;
    //Shortens the vector, keeping the first len elements and dropping the rest.
    let mut tmp = signed.as_slice();
    tmp = &tmp[..SIGNATURE_LENGTH];
    let tmp1 = tmp.to_vec();
    tmp1
}


pub fn verify_signature(data: &[u8], signature: &[u8], key: &PublicKey) -> bool {
    //allocate new vector that will combine the signature and data for the use of crypto open
    let mut signed  = Vec::new(); 
    signed.extend(signature.iter().cloned());
    signed.extend(data.iter().cloned());
    //LOOK INTO MORE SECURE MEMEORY ALLOCATION AND ZERO OUT
    let mut msg = std::iter::repeat(0).take(signed.len()).collect::<Vec<_>>();

    match ed25519::crypto_sign_open(&mut msg, &signed, &key) {
        Some(_) => true, 
        None => false
    }
}


#[test]
fn test_sign_sanity() {
    use std::iter::repeat;

    for i in 1..2 {
        let keypair = Keypair::new();
        let msg: Vec<u8> = repeat(i as u8).take(i * 4).collect();

        let sig = keypair.sign(&msg);
        //println!("signedMSG: {:?}", &sig);
        let desig = sig.verify();
        println!("msg:\t{:?}\nsig:\t{:?}\ndesig:\t{:?}", msg, sig.signed, desig);
        //assert!(desig.is_some());
        assert!(desig.unwrap() == msg);
    }
}

#[test]
fn test_sign_fail_sanity() {
    let key1 = Keypair::new();
    let key2 = Keypair::new();

    let msg = b"some message";

    let sig = key1.sign(msg);
    //change the keys used
    let altered_sig = SignedData { public_key: key2.public, signed: sig.signed.clone() };
    let desig = altered_sig.verify();

    println!("msg:\t{:?}\nsig:\t{:?}\ndesig:\t{:?}", msg, sig.signed, desig);

    assert!(desig.is_none());
}

//the tests are not long for dev purposes but for better test increase loop count to 32 ir 256

#[test]
fn test_sign_verify() { 
    for i in 0..2usize {
        let key = Keypair::new();
        let message = shared::random_data_test_helper(i);
        let sig = key.sign(&message);
        let desig = sig.verify();
        assert!(desig.unwrap() == message);
    }
}

#[test]  
fn test_sign_verify_tamper() {
    for i in 0..2usize {
        let key = Keypair::new();
        let message = shared::random_data_test_helper(i);
        let mut sig = key.sign(&message);
        let len = sig.signed.len();
        for j in 0..len {
            sig.signed[j] ^= 0x20;
            let desig = sig.verify();
            assert!(desig.is_none());
            sig.signed[j] ^= 0x20;
        }
    }
}

#[test]
fn test_sign_verify_detached() {
    for i in 10..20usize {
        let key = Keypair::new();
        let message = shared::random_data_test_helper(i);
        let sig = signature(&message, &key.secret);
        let b = verify_signature(&message, &sig, &key.public);
        assert!(b);  
    }
}


#[test]  
fn test_sign_verify_detached_tamper() {
    for i in 0..2usize {
        let key = Keypair::new();
        let message = shared::random_data_test_helper(i);
        let mut sig = signature(&message, &key.secret);
        let len = sig.len();
        for j in 0..len {
            sig[j] ^= 0x20;
            let b = verify_signature(&message, &sig, &key.public);
            println!("{:?}", b);
            assert!(!b);
            sig[j] ^= 0x20;
        }
    }
}

#[test]
fn test_sign_verify_seed() {
    for i in 0..2usize {
        let mut seedbuf = [0; 32];
        super::randombytes(&mut seedbuf);
            
        let seed = seedbuf;
        let mut pk = [0u8; PUBLIC_KEY_BYTES];
        let mut sk = [0u8; SECRET_KEY_BYTES];
        ed25519::crypto_sign_keypair_seed(&mut pk, &mut sk, &seed);
        let pk : PublicKey = pk;
        let sk : SecretKey = sk;
        let key = Keypair{
            public: pk,
            secret: sk,
        };

        let message = shared::random_data_test_helper(i);
        let mut sig = key.sign(&message);
        let desig = sig.verify();
        assert!(desig.unwrap() == message);
    }
}

#[test]
fn test_sign_verify_tamper_seed() {
    for i in 0..2usize {
         let mut seedbuf = [0; 32];
        super::randombytes(&mut seedbuf);
            
        let seed = seedbuf;
        let mut pk = [0u8; PUBLIC_KEY_BYTES];
        let mut sk = [0u8; SECRET_KEY_BYTES];
        ed25519::crypto_sign_keypair_seed(&mut pk, &mut sk, &seed);
        let pk : PublicKey = pk;
        let sk : SecretKey = sk;
        let key = Keypair{
            public: pk,
            secret: sk,
        };

        let message = shared::random_data_test_helper(i);
        let mut sig = key.sign(&message);
        let len = sig.signed.len();
        for j in 0..len {
            sig.signed[j] ^= 0x20;
            let desig = sig.verify();
            assert!(desig.is_none());
            sig.signed[j] ^= 0x20;
        }
    }
}

//https://github.com/maidsafe/rust_sodium/blob/master/src/crypto/sign/ed25519.rs
//use low level api for this test versus higher level as before fore direct bytes access
#[test]
fn test_sign_vectors() {
    // test vectors from the Python implementation
    // from the [Ed25519 Homepage](http://ed25519.cr.yp.to/software.html)
    use rustc_serialize::hex::{FromHex, ToHex};
    use std::fs::File;
    use std::io::{BufRead, BufReader};

    let r = BufReader::new(unwrap!(File::open("testvectors/ed25519.input")));

    for mline in r.lines() {
        let line = unwrap!(mline);
        let mut x = line.split(':');
        let x0 = unwrap!(x.next());
        let x1 = unwrap!(x.next());
        let x2 = unwrap!(x.next());
        let x3 = unwrap!(x.next());
        let seed_bytes = unwrap!(x0[..64].from_hex());

        assert!(seed_bytes.len() == 32);

        let mut seedbuf = [0u8; 32];
        for (s, b) in seedbuf.iter_mut().zip(seed_bytes.iter()) {
            *s = *b
        }

        let seed = seedbuf;
        let mut pk = [0u8; PUBLIC_KEY_BYTES];
        let mut sk = [0u8; SECRET_KEY_BYTES];
        ed25519::crypto_sign_keypair_seed(&mut pk, &mut sk, &seed);
        
        let m = unwrap!(x2.from_hex());
        
        let mut sm = std::iter::repeat(0).take(m.len() + SIGN_BYTES).collect::<Vec<_>>();
        ed25519::crypto_sign(&mut sm, &m, &sk);
        let smp = sm.clone();
        let sg = SignedData {public_key: pk, signed: smp};
        
        assert!(unwrap!(sg.verify()) == m);

        //println!("{:?}", pk.to_hex());
        //println!("{:?}", x1);
        assert!(x1 == pk.to_hex());

        //println!("{:?}", sk.to_hex());
        //println!("{:?}", x3);
        assert!(x3 == sm.to_hex());
    }
}

fn test_sign_vectors_detached() {
    // test vectors from the Python implementation
    // from the [Ed25519 Homepage](http://ed25519.cr.yp.to/software.html)
    use rustc_serialize::hex::{FromHex, ToHex};
    use std::fs::File;
    use std::io::{BufRead, BufReader};

    let r = BufReader::new(unwrap!(File::open("testvectors/ed25519.input")));

    for mline in r.lines() {
        let line = unwrap!(mline);
        let mut x = line.split(':');
        let x0 = unwrap!(x.next());
        let x1 = unwrap!(x.next());
        let x2 = unwrap!(x.next());
        let x3 = unwrap!(x.next());
        let seed_bytes = unwrap!(x0[..64].from_hex());

        assert!(seed_bytes.len() == 32);

        let mut seedbuf = [0u8; 32];
        for (s, b) in seedbuf.iter_mut().zip(seed_bytes.iter()) {
            *s = *b
        }

        let seed = seedbuf;
        let mut pk = [0u8; PUBLIC_KEY_BYTES];
        let mut sk = [0u8; SECRET_KEY_BYTES];
        ed25519::crypto_sign_keypair_seed(&mut pk, &mut sk, &seed);
        
        let m = unwrap!(x2.from_hex());
        
        let sk : SecretKey = sk;
        let sig = signature(&m, &sk);
        let pk : PublicKey = pk;
        let b = verify_signature(&m, &sig, &pk);

        assert!(b);
        assert!(x1 == pk.to_hex());
        //println!("{:?}", sk.to_hex());
        //println!("{:?}", x3);
        //let mut sm = std::iter::repeat(0).take(m.len() + SIGN_BYTES).collect::<Vec<_>>();
        let mut sm  = Vec::new(); 
        sm.extend(sig.iter().cloned());
        sm.extend(m.iter().cloned());
        assert!(x3 == sm.to_hex());
    }
}