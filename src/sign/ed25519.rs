//https://github.com/maidsafe/rust_sodium/blob/master/src/crypto/sign/ed25519.rs
//! `ed25519`, a signature scheme specified in
//! [Ed25519](http://ed25519.cr.yp.to/). This function is conjectured to meet the
//! standard notion of unforgeability for a public-key signature scheme under
//! chosen-message attacks.

use hash;
use shared;

use super::super::randombytes as randombytes;
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

//Key Generation
///A Pubic key for signatures
pub type PublicKey = [u8; PUBLIC_KEY_BYTES];
///A secret key for signature
pub type SecretKey = [u8; SECRET_KEY_BYTES];

///Typedef: Gf -> i64 [16], representing 256-bit integer in radix 2^16
type Gf = [i64;16];
//const gf0 = {0}
const GF0 : Gf = [0; 16];
//const gf1 = {1}
const GF1 : Gf = [1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0];



//const gf Edwards curve parameter
const D : Gf = [0x78a3, 0x1359, 0x4dca, 0x75eb, 0xd8ab, 0x4141, 0x0a4d, 0x0070, 0xe898, 0x7779, 0x4079, 0x8cc7, 0xfe73, 0x2b6f, 0x6cee, 0x5203];
//const gf Edwards curve parameter, doubled
const D2 : Gf = [0xf159, 0x26b2, 0x9b94, 0xebd6, 0xb156, 0x8283, 0x149a, 0x00e0, 0xd130, 0xeef3, 0x80f2, 0x198e, 0xfce7, 0x56df, 0xd9dc, 0x2406];
//x-coordinate of base point
const X : Gf = [0xd51a, 0x8f25, 0x2d60, 0xc956, 0xa7b2, 0x9525, 0xc760, 0x692c, 0xdc5c, 0xfdd6, 0xe231, 0xc0a4, 0x53fe, 0xcd6e, 0x36d3, 0x2169];
//y-coordinate of base point
const Y : Gf = [0x6658, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666];
const I : Gf = [0xa0b0, 0x4a0e, 0x1b27, 0xc4ee, 0xe478, 0xad2f, 0x1806, 0x2f43, 0xd7a7, 0x3dfb, 0x0099, 0x2b4d, 0xdf0b, 0x4fc1, 0x2480, 0x2b83];



//Copy 256-bit integer
fn set25519(r: &mut Gf, a: Gf) {
    for i in 0..16 {
        r[i]=a[i];
    }
}

//Conditionally swap curve points
fn cswap(p: &mut [Gf;4], q: &mut [Gf;4], b: u8) {
    for i in 0..4 {
        /* FIXME: check b cast to isize */
        shared::sel25519(&mut p[i], &mut q[i], b as isize);
    }
}

//Add points on Edwards curve
fn add(p: &mut [Gf;4],q: &[Gf;4]) {
    let mut a = GF0;
    let mut b = a;
    let mut c = a;
    let mut d = a;
    let mut t = a;
    let mut e = a;
    let mut f = a;
    let mut g = a;
    let mut h = a;

    /* XXX: avoid aliasing with extra copy */
    let mut tmp = GF0;
    shared::gf_subtract(&mut a, p[1], p[0]);
    shared::gf_subtract(&mut t, q[1], q[0]);
    shared::gf_multiply(&mut tmp, a, t);
    a = tmp;
    shared::gf_add(&mut b, p[0], p[1]);
    shared::gf_add(&mut t, q[0], q[1]);
    shared::gf_multiply(&mut tmp, b, t);
    b = tmp;
    shared::gf_multiply(&mut c, p[3], q[3]);
    shared::gf_multiply(&mut tmp, c, D2);
    c = tmp;
    shared::gf_multiply(&mut d, p[2], q[2]);
    shared::gf_add(&mut tmp, d, d);
    d = tmp;
    shared::gf_subtract(&mut e, b, a);
    shared::gf_subtract(&mut f, d, c);
    shared::gf_add(&mut g, d, c);
    shared::gf_add(&mut h, b, a);

    shared::gf_multiply(&mut p[0], e, f);
    shared::gf_multiply(&mut p[1], h, g);
    shared::gf_multiply(&mut p[2], g, f);
    shared::gf_multiply(&mut p[3], e, h);
}


//Parity of integer mod 2^255 - 19
fn par25519(a: Gf) -> u8 {
    let mut d = [0u8;32];
    shared::pack25519(&mut d, a);
    return d[0]&1;
}


//Freeze and store curve point
fn pack(r: &mut [u8;32], p: &[Gf;4]) {
    let mut tx = GF0;
    let mut ty = GF0;
    let mut zi = GF0;

    shared::inv25519(&mut zi, p[2]);
    shared::gf_multiply(&mut tx, p[0], zi);
    shared::gf_multiply(&mut ty, p[1], zi);
    shared::pack25519(r, ty);
    r[31] ^= par25519(tx) << 7;
}

//Scalar multiplication on Edwards curve
fn scalarmult(p: &mut [Gf;4], q: &mut [Gf;4], s: &[u8;32]) {
    set25519(&mut p[0],GF0);
    set25519(&mut p[1],GF1);
    set25519(&mut p[2],GF1);
    set25519(&mut p[3],GF0);

    for i in (0..256).rev() {
        let b : u8 = (s[i/8]>>(i&7))&1;
        /* XXX: avoid aliasing with extra copy */
        cswap(p,q,b);
        add(q,p);
        let mut tmp = *p;
        add(&mut tmp,p);
        *p = tmp;
        cswap(p,q,b);
    }
}

//Scalar multiplication by base point on Edwards curve
fn scalarbase(p: &mut [Gf;4], s: &[u8;32]){
    /* XXX: uninit */
    let mut q = [GF0; 4];
    set25519(&mut q[0],X);
    set25519(&mut q[1],Y);
    set25519(&mut q[2],GF1);
    shared::gf_multiply(&mut q[3],X,Y);
    scalarmult(p, &mut q,s);
}

pub fn crypto_sign_keypair_seed(public_key: &mut PublicKey, secret_key: &mut SecretKey, seed: &[u8;32]){
    /* FIXME: uninit in tweet-nacl */
    let mut d = [0u8; 64];
    let mut p = [GF0;4];
    
    *index_fixed!(&mut secret_key;..32) = *seed;
    hash::raw_sha512(&mut d, &secret_key[..32]);
    d[0] &= 248;
    d[31] &= 127; //63 
    d[31] |= 64;

    scalarbase(&mut p, index_fixed!(&d;..32));
    pack(public_key, &p);

    for i in 0..32 {
        secret_key[32 + i] = public_key[i];
    }
}

//Generate key pair for signature
pub fn crypto_sign_keypair(public_key: &mut PublicKey, secret_key: &mut SecretKey){
    let mut seed = [0u8;32];
    randombytes(&mut seed);
    crypto_sign_keypair_seed(public_key, secret_key, &seed);
}

//const u64[32] -> prime order of base point
const L: [u64; 32] = [0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10];

//freeze mod order of base point, radix 2^8
fn mod_l(r: &mut [u8;32], x: &mut [i64;64]) {
    /*
       i64 carry,i,j;
       */
    for i in (32..64).rev() {
        let mut carry = 0;
        for j in (i - 32)..(i - 12) {
            /* FIXME: check cast to i64 */
            x[j] += carry - 16 * x[i] * L[j - (i - 32)] as i64;
            carry = (x[j] + 128) >> 8;
            x[j] -= carry << 8;
        }
        /* index is last value of @j */
        x[i - 12] += carry;
        x[i] = 0;
    }

    let mut carry = 0;
    for j in 0..32 {
        /* FIXME: check cast to i64 */
        x[j] += carry - (x[31] >> 4) * L[j] as i64;
        carry = x[j] >> 8;
        x[j] &= 255;
    }

    for j in 0..32 {
        /* FIXME: check cast to i64 */
        x[j] -= carry * L[j] as i64;
    }
    for i in 0..32 {
        x[i+1] += x[i] >> 8;
        r[i] = x[i] as u8;
    }
}

//Freeze 512-bit string mod order of base point
fn reduce(r: &mut [u8;64]) {
    /* TODO: uninitialized in tweet-nacl */
    let mut x = [0i64;64];
    for i in 0..64 {
        /* FIXME: this cast needs to be verified */
        x[i] = (r[i] as u64) as i64; // FOR(i,64) x[i] = (u64) r[i];
    }
    for i in 0..64 {
        r[i] = 0;
    }
    mod_l(index_fixed!(&mut r;..32), &mut x);
}

/**
 * Generate an attached (ie: joined) signature for a message
 *
 * The signature is stored at the beginning of @sm (signed message). @sm must be at exactly
 * @m.len() + SIGN_LEN bytes long.
 *
 * @sm is not read from, it is only used as an output parameter.
 *
 * Panics:
 *
 * - @sm is not the right size.
 */
pub fn crypto_sign(sm: &mut [u8], m: &[u8], sk: &SecretKey) {
    //HANDLE ERROR BETTER
    assert_eq!(sm.len(), m.len() + SIGNATURE_LENGTH);

    /* XXX: uninit in tweet nacl { */
    let mut d = [0u8; 64];
    let mut h = [0u8; 64];
    let mut r = [0u8;64];
    let mut p = [GF0; 4];
    /* } */

    hash::raw_sha512(&mut d, &sk[..32]);
    d[0] &= 248;
    d[31] &= 127;
    d[31] |= 64;

    for i in 0..m.len() {
        sm[64 + i] = m[i];
    }
    for i in 0..32 {
        sm[32 + i] = d[32 + i];
    }

    hash::raw_sha512(&mut r, &sm[32..][..m.len()+32]);
    reduce(&mut r);
    scalarbase(&mut p, index_fixed!(&r;..32));
    pack(index_fixed!(&mut sm;..32), &p);

    for i in 0..32 {
        sm[i+32] = sk[i+32];
    }

    hash::raw_sha512(&mut h,&sm[..m.len() + 64]);
    reduce(&mut h);

    let mut x = [0i64; 64];
    for i in 0..32 {
      /* FIXME: check this cast */
      x[i] = r[i] as u64 as i64; //FOR(i,32) x[i] = (u64) r[i];
    }

    for i in 0..32 {
        for j in 0..32 {
          /* FIXME: check this cast */
          x[i+j] += ((h[i] as u64) * (d[j] as u64)) as i64; //FOR(i,32) FOR(j,32) x[i+j] += h[i] * (u64) d[j];
        }
    }

    mod_l(index_fixed!(&mut sm[32..];..32), &mut x);
}

//power 2^252 - 3 mod 2^255 - 19
fn pow2523(o: &mut Gf, i: Gf) {
    let mut c = GF0;
    for a in 0..16 {
        c[a]=i[a];
    }
    for a in (0..251).rev() {
        /* XXX: avoid aliasing with a copy */
        let mut tmp = GF0;
        shared::gf_square(&mut tmp,c);
        if a != 1 {
            shared::gf_multiply(&mut c,tmp,i);
        } else {
            c = tmp;
        }
    }
    for a in 0..16 {
        o[a]=c[a];
    }
}

//Compare mod 2^255 - 19
fn neq25519(a: Gf, b: Gf) -> bool {
    /* TODO: uninit in tweet-nacl */
    let mut c = [0u8; 32];

    /* TODO: uninit in tweet-nacl */
    let mut d = [0u8; 32];

    shared::pack25519(&mut c,a);
    shared::pack25519(&mut d,b);
    shared::verify_32(&c, &d) != 0
}


//Load curve point
fn unpackneg(r: &mut [Gf;4], p: &[u8; 32]) -> isize { /* int */
    let mut t = GF0;
    let mut chk = t;
    let mut num = t;
    let mut den = t;
    let mut den2 = t;
    let mut den4 = t;
    let mut den6 = t;

    /* XXX: add extra copy to avoid aliasing */
    let mut tmp = GF0;

    set25519(&mut r[2],GF1);
    shared::unpack25519(&mut r[1],p);
    shared::gf_square(&mut num,r[1]);
    shared::gf_multiply(&mut den,num,D);
    shared::gf_subtract(&mut tmp,num,r[2]);
    num = tmp;
    shared::gf_add(&mut tmp,r[2],den);
    den = tmp;

    shared::gf_square(&mut den2,den);
    shared::gf_square(&mut den4,den2);
    shared::gf_multiply(&mut den6,den4,den2);
    shared::gf_multiply(&mut t,den6,num);
    shared::gf_multiply(&mut tmp,t,den);
    t = tmp;

    pow2523(&mut tmp,t);
    t = tmp;
    shared::gf_multiply(&mut tmp,t,num);
    t = tmp;
    shared::gf_multiply(&mut tmp,t,den);
    t = tmp;
    shared::gf_multiply(&mut tmp,t,den);
    t = tmp;
    shared::gf_multiply(&mut r[0],t,den);

    shared::gf_square(&mut chk,r[0]);
    shared::gf_multiply(&mut tmp,chk,den);
    chk = tmp;
    if neq25519(chk, num) {
        shared::gf_multiply(&mut tmp,r[0],I);
        r[0] = tmp;
    }

    shared::gf_square(&mut chk,r[0]);
    shared::gf_multiply(&mut tmp,chk,den);
    chk = tmp;
    if neq25519(chk, num) {
        return -1;
    }

    if par25519(r[0]) == (p[31]>>7) {
        shared::gf_subtract(&mut tmp,GF0,r[0]);
        r[0] = tmp;
    }

    let (init, mut rest) = r.split_at_mut(3);
    shared::gf_multiply(&mut rest[0],init[0],init[1]);
    return 0;
}


/**
 * verify an attached signature
 *
 * @m must have the same length as @sm.
 *
 * If verification failed, returns Err(()).
 * Otherwise, returns the number of bytes in message & copies the message into @m
 *
 * Panics:
 *
 * - If m.len() != sm.len()
 *
 */
pub fn crypto_sign_open(m: &mut [u8], sm : &[u8], pk: &PublicKey) -> Option<usize> {
    //HANDLE THIS ERROR CASE BETTER
    assert_eq!(m.len(), sm.len());
    let mut t = [0u8;32];
    let mut h = [0u8;64];

    let mut p = [GF0;4];
    let mut q = p;

    if sm.len() < 64 {
        return None;
    }

    /* TODO: check if upackneg should return a bool */
    if unpackneg(&mut q,pk) != 0 {
        return None;
    }

    for i in 0..sm.len() {
        m[i] = sm[i];
    }
    for i in 0..32 {
        m[i+32] = pk[i];
    }
    hash::raw_sha512(&mut h, &m[..sm.len()]);
    reduce(&mut h);
    scalarmult(&mut p, &mut q, index_fixed!(&h;..32));

    scalarbase(&mut q, index_fixed!(&sm[32..];..32));
    add(&mut p, &q);
    pack(&mut t, &p);


    let n = sm.len() - 64;
    /* TODO: check if verify_32 should return a bool */
    if shared::verify_32(index_fixed!(&sm;..32), &t) != 0 {
        for i in 0..n {
            m[i] = 0;
        }
        return None;
    }

    for i in 0..n {
        m[i] = sm[i + 64];
    }
    Some(n)
}

