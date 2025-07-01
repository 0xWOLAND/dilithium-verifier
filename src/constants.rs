pub const Q: u32 = 8380417;
pub const D: usize = 13;
pub const GAMMA1: u32 = 1 << 17;
pub const GAMMA2: u32 = (Q - 1) / 88;
pub const TAU: usize = 4;
pub const BETA: u32 = TAU as u32 * GAMMA2;
pub const OMEGA: usize = 80;

pub const K: usize = 4;
pub const L: usize = 4;
pub const ETA: u32 = 2;

pub const POLYT0_PACKEDBYTES: usize = 416;
pub const POLYT1_PACKEDBYTES: usize = 320;
pub const POLYZ_PACKEDBYTES: usize = 576;
pub const POLYW1_PACKEDBYTES: usize = 192;
pub const POLYETA_PACKEDBYTES: usize = 96;

pub const CRYPTO_PUBLICKEYBYTES: usize = 1312;
pub const CRYPTO_SECRETKEYBYTES: usize = 2528;
pub const CRYPTO_BYTES: usize = 2420;

pub const N: usize = 256;
pub const SEEDBYTES: usize = 32;
pub const CRHBYTES: usize = 64;
pub const TRBYTES: usize = 64;

pub const ROOT_OF_UNITY: u32 = 1753;
pub const ROOT_OF_UNITY_INV: u32 = 731434;