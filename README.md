# WIP 
This is still in active development use with caution. Documentation and Examples will soon be available once public api has become stable 

***

# microsalt
High Level Pure Rust Crypto library for your trusty rusty programs

### Tests
There is test coverage for each module but more is needed 

#### The following cryptographic primitives are used with this library.

|  Module       | Primitive                   |
| ------------- | ----------------------------|
| boxy          | Curve25519/Salsa20/Poly1305 |
| hash          | SHA-512                     |
| secretbox     | Salsa20/Poly1305            |
| sign          | Ed25519                     |
| stream        | Salsa20                     |
| onetimeauth   | Poly1305                    |
***

# Examples
## Hash 
Currently the hasher function takes data as &[u8] 
```rust
extern crate microsalt;

fn main() {
  // microsalt::hash::LENGTH is also available for hash length 
  let x = b"hello world";
  let hash = microsalt::hash::hasher(x);
  println!("{:?}", hash.to_vec()); //converts to vector for easy printing   
}
```

## boxy -> Public Key Box Construct

## secretbox -> Secret key Box Construct

## Sign
```rust
//Available types
microsalt::sign::PublicKey 
microsalt::sign::SecretKey 
microsalt::sign::Keypair
microsalt::sign::SignedData

fn main() {
  let keypair = microsalt::sign::Keypair::new();
  let msg = b"Hello World";
  //sign our msg, returns SignedData type that encapsulates the public key and signed data
  //Please note that this contruct will attach the signature to the begining of the given data
  let signature = keypair.sign(&msg); //sign(data: &[u8]) so must pass data as [u8]
  
  //the signature variable can be used to acces its fields as seen bellow
  //signature.public_key --> the public key used to verify this data
  //signature.signed --> A vector (Vec<u8>) that holds the signature + data
  
  //verigy our signature
  let verify_signature = signature.verify(); //returns an Option<Vec<u8>> so can be Some() or None

  //compare
  assert!(verify_signature.unwrap() == msg);
}
```
### Detached signatures
```rust

fn main() {
  //generate keypair
  let key = microsalt::sign::Keypair::new();
  let message = b"Hello World";
  //the signtaure function may be used when you just need the signature
  let signature = microsalt::sign::signature(&message, &key.secret);
  //this is the verify function for signature generated using the function above
  let verified_signature = microslat::sign::verify_signature(&message, &signature, &key.public);
  //the verify_signature function returns a boolean, true for verified and false for not
  assert!(verified_signature);  
}
```

## onetimeauth

## stream
***

### https://tweetnacl.cr.yp.to/
"TweetNaCl is the world's first auditable high-security cryptographic library. TweetNaCl fits into just 100 tweets while supporting all 25 of the C NaCl functions used by applications. TweetNaCl is a self-contained public-domain C library, so it can easily be integrated into applications."

#### Thanks for these previous work
* https://github.com/maidsafe/rust_sodium/
* https://github.com/jmesmon/sodalite
* https://github.com/erik/knuckle/

