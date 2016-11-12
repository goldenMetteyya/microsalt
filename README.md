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

## sign
```rust
//Available types
microsalt::sign::PublicKey 
microsalt::sign::SecretKey


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

