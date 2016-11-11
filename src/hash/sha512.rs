//SHA512
//https://github.com/jmesmon/sodalite/
use std::num::Wrapping as W;

/// Byte size of the hashed output.
pub const HASH_LENGTH: usize = 64;
pub type Hash = [u8; HASH_LENGTH];

fn r(x: W<u64>, c: usize) -> W<u64> { (x >> c) | (x << (64 - c)) }
fn ch(x: W<u64>, y: W<u64>, z: W<u64>) -> W<u64> { (x & y) ^ (!x & z) }
fn maj(x: W<u64>, y: W<u64>, z: W<u64>) -> W<u64> { (x & y) ^ (x & z) ^ (y & z) }
fn upper_sigma0(x: W<u64>) -> W<u64> { r(x,28) ^ r(x,34) ^ r(x,39) }
fn upper_sigma1(x: W<u64>) -> W<u64> { r(x,14) ^ r(x,18) ^ r(x,41) }
fn sigma0(x: W<u64>) -> W<u64> { r(x, 1) ^ r(x, 8) ^ (x >> 7) }
fn sigma1(x: W<u64>) -> W<u64> { r(x,19) ^ r(x,61) ^ (x >> 6) }

const K : [u64;80] = [
    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
    0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
    0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
    0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
    0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
    0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
    0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
    0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
    0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
    0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
    0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
    0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
    0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
    0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817
];

fn dl64(x: &[u8;8]) -> W<u64>{
    let mut u = 0u64;
    for v in x {
        u = u << 8 | (*v as u64);
    }
    W(u)
}

fn ts64(x: &mut [u8;8], mut u: u64){
    for v in x.iter_mut().rev() {
        *v = u as u8;
        u >>= 8;
    }
}

fn hashblocks(x: &mut [u8], mut m: &[u8]) -> usize {
    /* XXX: all uninit in tweet-nacl */
    let mut z = [W(0u64);8];
    let mut b = [W(0u64);8];
    let mut a = [W(0u64);8];
    let mut w = [W(0u64);16];

    for i in 0..8 {
        let v = dl64(index_fixed!(&x[8 * i..];..8));
        z[i] = v;
        a[i] = v;
    }

    while m.len() >= 128 {
        for i in 0..16 {
            w[i] = dl64(index_fixed!(&m[8 * i..];..8));
        }

        for i in 0..80 {
            for j in 0..8 {
                b[j] = a[j];
            }
            let t = a[7] + upper_sigma1(a[4]) + ch(a[4],a[5],a[6]) + W(K[i]) + w[i%16];
            b[7] = t + upper_sigma0(a[0]) + maj(a[0],a[1],a[2]);
            b[3] = b[3] + t;
            for j in 0..8 {
                a[(j+1)%8] = b[j];
            }
            if i%16 == 15 {
                for j in 0..16 {
                    w[j] = w[j] + w[(j+9)%16] + sigma0(w[(j+1)%16]) + sigma1(w[(j+14)%16]);
                }
            }
        }

        for i in 0..8 {
            a[i] = a[i] + z[i];
            z[i] = a[i];
        }

        m = &m[128..];
    }

    for i in 0..8 {
        ts64(index_fixed!(&mut x[8*i..];..8),z[i].0);
    }

    m.len()
}

const IV:[u8; 64] = [
    0x6a,0x09,0xe6,0x67,0xf3,0xbc,0xc9,0x08,
    0xbb,0x67,0xae,0x85,0x84,0xca,0xa7,0x3b,
    0x3c,0x6e,0xf3,0x72,0xfe,0x94,0xf8,0x2b,
    0xa5,0x4f,0xf5,0x3a,0x5f,0x1d,0x36,0xf1,
    0x51,0x0e,0x52,0x7f,0xad,0xe6,0x82,0xd1,
    0x9b,0x05,0x68,0x8c,0x2b,0x3e,0x6c,0x1f,
    0x1f,0x83,0xd9,0xab,0xfb,0x41,0xbd,0x6b,
    0x5b,0xe0,0xcd,0x19,0x13,0x7e,0x21,0x79
];

//SHA512
pub fn hash(out: &mut Hash, mut m: &[u8]){
    let mut h = IV;

    /* XXX: idealy, we'd either cast (if usize < u64) or keep the existing type (if usize >= u64)
     * */
    let b = m.len() as u64;

    hashblocks(&mut h, m);
    // slice m to the last 'new_len' bytes
    let new_len = m.len() & 127;
    let s = m.len() - new_len;
    m = &m[s..][..new_len];

    let mut x = [0u8;256];
    for i in 0..m.len() {
        x[i] = m[i];
    }
    x[m.len()] = 128;

    let new_len = 256-(if m.len()<112 {128} else {0});
    let mut x = &mut x[..new_len];
    let l = x.len() - 9;
    x[l] = (b >> 61) as u8;
    /* FIXME: check cast to u64 */
    let l = x.len() - 8;
    ts64(index_fixed!(&mut x[l..];..8), (b<<3) as u64);
    hashblocks(&mut h, &x);

    for i in 0..64 {
        out[i] = h[i];
    }
}







