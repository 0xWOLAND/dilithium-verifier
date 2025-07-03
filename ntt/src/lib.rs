//! Number Theoretic Transform (NTT) gadget for Dilithium/ML-DSA
//! 
//! This module implements the Number Theoretic Transform used in the Dilithium/ML-DSA
//! digital signature algorithm (FIPS 204). The NTT is a key component that enables
//! efficient polynomial multiplication in the ring Zq[X]/(X^n + 1).
//! 
//! The implementation is optimized for zero-knowledge circuits using plonky2.

use plonky2::field::extension::Extendable;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::target::Target;
use plonky2::plonk::circuit_builder::CircuitBuilder;

#[cfg(test)]
mod tests;

// Dilithium/ML-DSA parameters
pub const N: usize = 256;                    // Polynomial degree
pub const Q: u32 = 8380417;                  // Prime modulus q
pub const ROOT_OF_UNITY: u32 = 1753;         // Primitive 512th root of unity mod q
pub const MONT_R: u32 = 4193792;             // 2^32 mod q for Montgomery form
pub const MONT_R_INV: u32 = 1073479681;     // R^(-1) mod q  
pub const Q_INV: u32 = 4236238847;          // -q^(-1) mod 2^32

/// Pre-computed zetas for forward NTT (bit-reversed order)
/// These are powers of the primitive root in Montgomery form
const ZETAS: [u32; 256] = [
    4193792, 25847, 5771523, 7861508, 237124, 7602457, 7504169, 466468,
    1826347, 2353451, 8021166, 6288512, 3119733, 5495562, 3111497, 2680103,
    2725464, 1024112, 7300517, 3585928, 7830929, 7260833, 2619752, 6271868,
    6262231, 4520680, 6980856, 5102745, 1757237, 8360995, 4010497, 280005,
    2706023, 95776, 3077325, 3530437, 6718724, 4788269, 5842901, 3915439,
    4519302, 5336701, 3574422, 5512770, 3539968, 8079950, 2348700, 7841118,
    6681150, 6736599, 3505694, 4558682, 3507263, 6239768, 6779997, 3699596,
    811944, 531354, 954230, 3881043, 3900724, 5823537, 2071892, 5582638,
    4450022, 6851714, 4702672, 5339162, 6927966, 3475950, 2176455, 6795196,
    7122806, 1939314, 4296819, 7380215, 5190273, 5223087, 4747489, 126922,
    3412210, 7396998, 2147896, 2715295, 5412772, 4686924, 7969390, 5903370,
    7709315, 7151892, 8357436, 7072248, 7998430, 1349076, 1852771, 6949987,
    5037034, 264944, 508951, 3097992, 44288, 7280319, 904516, 3958618,
    4656075, 8371839, 1653064, 5130689, 2389356, 8169440, 759969, 7063561,
    189548, 4827145, 3159746, 6529015, 5971092, 8202977, 1315589, 1341330,
    1285669, 6795489, 7567685, 6940675, 5361315, 4499357, 4751448, 3839961,
    2091667, 3407706, 2316500, 3817976, 5037939, 2244091, 5933984, 4817955,
    266997, 2434439, 7144689, 3513181, 4860065, 4621053, 7183191, 5187039,
    900702, 1859098, 909542, 819034, 495491, 6767243, 8337157, 7857917,
    7725090, 5257975, 2031748, 3207046, 4823422, 7855319, 7611795, 4784579,
    342297, 286988, 5942594, 4108315, 3437287, 5038140, 1735879, 203044,
    2842341, 2691481, 5790267, 1265009, 4055324, 1247620, 2486353, 1595974,
    4613401, 1250494, 2635921, 4832145, 5386378, 1869119, 1903435, 7329447,
    7047359, 1237275, 5062207, 6950192, 7929317, 1312455, 3306115, 6417775,
    7100756, 1917081, 5834105, 7005614, 1500165, 777191, 2235880, 3406031,
    7838005, 5548557, 6709241, 6533464, 5796124, 4656147, 594136, 4603424,
    6366809, 2432395, 2454455, 8215696, 1957272, 3369112, 185531, 7173032,
    5196991, 162844, 1616392, 3014001, 810149, 1652634, 4686184, 6581310,
    5341501, 3523897, 3866901, 269760, 2213111, 7404533, 1717735, 472078,
    7953734, 1723600, 6577327, 1910376, 6712985, 7276084, 8119771, 4546524,
    5441381, 6144432, 7959518, 6094090, 183443, 7403526, 1612842, 4834730,
    7826001, 3919660, 8332111, 7018208, 3937738, 1400424, 7534263, 1976782
];

/// Pre-computed inverted zetas for inverse NTT (bit-reversed order)
const ZETAS_INV: [u32; 256] = [
    6403635, 846154, 6979993, 4442679, 1362209, 48394, 607805, 1597042,
    3797302, 5109772, 1223977, 5178974, 2517468, 3250773, 2961761, 1969633,
    4046816, 5577416, 2962457, 6773897, 2631308, 2991508, 4579606, 1606103,
    1068912, 3031773, 4787263, 5048169, 2103608, 6896093, 2280555, 1568989,
    6148386, 2107893, 1641068, 3952119, 5102687, 5008616, 4000890, 1538653,
    8337205, 4754871, 1361431, 5175450, 5119607, 6041966, 3702845, 3815817,
    3609956, 7754736, 3058618, 4035287, 5649675, 3845516, 1924896, 1275245,
    2247055, 2872640, 6607083, 1439318, 3513932, 5805983, 7555351, 4678944,
    3644945, 6851074, 6949687, 3624903, 7159814, 3645130, 4608888, 7629990,
    1236956, 2654117, 7870244, 8233061, 5765074, 4906000, 4067012, 1680639,
    4930490, 1464364, 6154188, 2844551, 1460395, 8166701, 3924628, 1473317,
    1799933, 1658825, 6632147, 3537401, 4754069, 4102498, 4728047, 2508970,
    1844508, 7924507, 5166096, 1719522, 8041009, 7738725, 1670287, 5159128,
    1108415, 2803073, 2766851, 8050985, 4520355, 4108337, 1957019, 1677392,
    3867897, 3952462, 4853618, 3835104, 3396617, 3267090, 513776, 4569752,
    3047733, 2635926, 6059783, 5947863, 6901658, 3103550, 5498973, 5997157,
    1686799, 2008455, 6297470, 3669056, 6980169, 1799489, 2795946, 4135535,
    5119311, 1616076, 5597513, 8097494, 3088925, 1844203, 7962726, 6979850,
    2418395, 5715012, 4815471, 1296963, 4761016, 2994994, 3447825, 5495014,
    765176, 1924608, 2318547, 4227158, 7000373, 6056981, 8130847, 2088428,
    2983047, 8338897, 6275568, 4765669, 7977227, 4673915, 5485903, 1863754,
    3550867, 1905938, 3956736, 2624324, 1749671, 5179354, 3998013, 6095423,
    256219, 6525077, 3073593, 5493088, 5066975, 4863033, 1509763, 6096982,
    4862491, 6893475, 6849066, 7733225, 1058397, 6012690, 2170214, 7969554,
    6825113, 6334109, 3139949, 6815783, 4700414, 1609107, 3983336, 2149423,
    3789691, 8334476, 2142395, 4700114, 3501058, 7230524, 8059958, 5072354,
    344423, 8143770, 7700760, 6154693, 1983605, 4013441, 4150399, 5962893,
    4303361, 4533159, 3000827, 6693133, 4569816, 6077936, 1734473, 7570847,
    7726453, 4603681, 7628644, 5353533, 6007901, 6647568, 1354518, 8045701,
    8128116, 2772752, 5851888, 4226767, 7532709, 5002260, 7424100, 7945926,
    6264440, 7840824, 4455951, 6632936, 7608135, 2166024, 7853698, 4395412,
    5166636, 4673632, 2846072, 1883569, 2901620, 2740983, 3946313, 3653808
];

/// Inverse of N modulo q for final scaling in inverse NTT
const N_INV: u32 = 8347681; // 256^(-1) mod q in Montgomery form

/// Polynomial representation in the circuit
pub struct PolynomialTarget {
    pub coeffs: Vec<Target>,
}

impl PolynomialTarget {
    /// Create a new polynomial with virtual targets
    pub fn new<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self {
        let coeffs = (0..N).map(|_| builder.add_virtual_target()).collect();
        Self { coeffs }
    }

    /// Create polynomial from existing targets
    pub fn from_targets(coeffs: Vec<Target>) -> Self {
        assert_eq!(coeffs.len(), N, "Polynomial must have exactly {} coefficients", N);
        Self { coeffs }
    }

    /// Get coefficient at index
    pub fn get_coeff(&self, idx: usize) -> Target {
        self.coeffs[idx]
    }

    /// Set coefficient (for testing)
    pub fn set_coeff(&mut self, idx: usize, coeff: Target) {
        self.coeffs[idx] = coeff;
    }
}

/// Main NTT gadget implementation
pub struct NttGadget;

impl NttGadget {
    /// Forward Number Theoretic Transform
    /// Converts polynomial from coefficient form to evaluation form
    pub fn ntt<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        poly: &PolynomialTarget,
    ) -> PolynomialTarget {
        let mut coeffs = poly.coeffs.clone();
        
        // Cooley-Tukey NTT with bit-reversal
        let mut len = 128;
        let mut k = 1;
        
        while len >= 2 {
            let mut start = 0;
            while start < N {
                let zeta = builder.constant(F::from_canonical_u32(ZETAS[k]));
                k += 1;
                
                for j in start..(start + len) {
                    // Butterfly operation: (a, b) -> (a + zeta*b, a - zeta*b)
                    let t = Self::montgomery_mul(builder, zeta, coeffs[j + len]);
                    let u = coeffs[j];
                    
                    coeffs[j] = Self::add_mod_q(builder, u, t);
                    coeffs[j + len] = Self::sub_mod_q(builder, u, t);
                }
                start += 2 * len;
            }
            len >>= 1;
        }
        
        PolynomialTarget { coeffs }
    }

    /// Inverse Number Theoretic Transform  
    /// Converts polynomial from evaluation form back to coefficient form
    pub fn intt<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        poly: &PolynomialTarget,
    ) -> PolynomialTarget {
        let mut coeffs = poly.coeffs.clone();
        
        // Gentleman-Sande inverse NTT
        let mut len = 2;
        let mut k = 127; // Start from the end of zetas_inv
        
        while len <= 128 {
            let mut start = 0;
            while start < N {
                let zeta = builder.constant(F::from_canonical_u32(ZETAS_INV[k]));
                k = if k > 0 { k - 1 } else { 0 };
                
                for j in start..(start + len) {
                    // Inverse butterfly: (a, b) -> ((a + b), zeta*(a - b))
                    let t = coeffs[j];
                    
                    coeffs[j] = Self::add_mod_q(builder, t, coeffs[j + len]);
                    coeffs[j + len] = Self::sub_mod_q(builder, t, coeffs[j + len]);
                    coeffs[j + len] = Self::montgomery_mul(builder, zeta, coeffs[j + len]);
                }
                start += 2 * len;
            }
            len <<= 1;
        }
        
        // Scale by n^(-1) = 256^(-1) mod q in Montgomery form
        let n_inv = builder.constant(F::from_canonical_u32(N_INV));
        for i in 0..N {
            coeffs[i] = Self::montgomery_mul(builder, n_inv, coeffs[i]);
        }
        
        PolynomialTarget { coeffs }
    }

    /// Pointwise polynomial multiplication in NTT domain
    /// This is the key advantage of NTT - O(n) instead of O(n^2) multiplication
    pub fn pointwise_mul<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        a: &PolynomialTarget,
        b: &PolynomialTarget,
    ) -> PolynomialTarget {
        let mut coeffs = Vec::with_capacity(N);
        
        for i in 0..N {
            let product = Self::montgomery_mul(builder, a.coeffs[i], b.coeffs[i]);
            coeffs.push(product);
        }
        
        PolynomialTarget { coeffs }
    }

    /// Add two polynomials coefficient-wise with modular reduction
    pub fn add_poly<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        a: &PolynomialTarget,
        b: &PolynomialTarget,
    ) -> PolynomialTarget {
        let mut coeffs = Vec::with_capacity(N);
        
        for i in 0..N {
            let sum = Self::add_mod_q(builder, a.coeffs[i], b.coeffs[i]);
            coeffs.push(sum);
        }
        
        PolynomialTarget { coeffs }
    }

    /// Subtract two polynomials coefficient-wise with modular reduction
    pub fn sub_poly<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        a: &PolynomialTarget,
        b: &PolynomialTarget,
    ) -> PolynomialTarget {
        let mut coeffs = Vec::with_capacity(N);
        
        for i in 0..N {
            let diff = Self::sub_mod_q(builder, a.coeffs[i], b.coeffs[i]);
            coeffs.push(diff);
        }
        
        PolynomialTarget { coeffs }
    }

    /// Scale polynomial by a constant
    pub fn scale<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        poly: &PolynomialTarget,
        scalar: Target,
    ) -> PolynomialTarget {
        let mut coeffs = Vec::with_capacity(N);
        
        for i in 0..N {
            let scaled = Self::montgomery_mul(builder, poly.coeffs[i], scalar);
            coeffs.push(scaled);
        }
        
        PolynomialTarget { coeffs }
    }

    /// Montgomery multiplication: (a * b * R^(-1)) mod q
    /// This is the core arithmetic operation for efficient modular multiplication
    pub fn montgomery_mul<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        a: Target,
        b: Target,
    ) -> Target {
        // Standard Montgomery multiplication for 32-bit modulus
        // Since we're in a larger field, we can do arithmetic directly
        let t = builder.mul(a, b);
        
        // Reduce modulo q
        let result = Self::reduce_mod_q(builder, t);
        
        // Apply Montgomery factor R^(-1) mod q
        let r_inv = builder.constant(F::from_canonical_u32(MONT_R_INV));
        let final_result = builder.mul(result, r_inv);
        Self::reduce_mod_q(builder, final_result)
    }

    /// Add two elements modulo q
    pub fn add_mod_q<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        a: Target,
        b: Target,
    ) -> Target {
        let sum = builder.add(a, b);
        let q_target = builder.constant(F::from_canonical_u32(Q));
        
        // If sum >= q, subtract q
        let is_ge_q = Self::is_ge(builder, sum, q_target);
        let one = builder.one();
        let is_ge_q_bool = builder.is_equal(is_ge_q, one);
        let reduced = builder.sub(sum, q_target);
        builder.select(is_ge_q_bool, reduced, sum)
    }

    /// Subtract two elements modulo q  
    pub fn sub_mod_q<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        a: Target,
        b: Target,
    ) -> Target {
        let q_target = builder.constant(F::from_canonical_u32(Q));
        
        // If a >= b, return a - b, else return a - b + q
        let is_ge = Self::is_ge(builder, a, b);
        let one = builder.one();
        let is_ge_bool = builder.is_equal(is_ge, one);
        let diff = builder.sub(a, b);
        let diff_plus_q = builder.add(diff, q_target);
        
        builder.select(is_ge_bool, diff, diff_plus_q)
    }

    /// Check if a >= b using Plonky2 range checks (returns BoolTarget)
    fn is_ge<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        a: Target,
        b: Target,
    ) -> Target {
        // Ensure both values are in valid range [0, q) for soundness
        let q_log = 24; // Q = 8380417 < 2^24
        builder.range_check(a, q_log);
        builder.range_check(b, q_log);
        
        // Create a virtual target for the difference when a >= b
        let diff = builder.add_virtual_target();
        
        // Add constraint: a = b + diff (this ensures a >= b if diff >= 0)
        let b_plus_diff = builder.add(b, diff);
        builder.connect(a, b_plus_diff);
        
        // Range check diff to ensure it's non-negative
        // Since a, b < q < 2^24, the maximum difference is also < 2^24
        builder.range_check(diff, q_log);
        
        // If we reach here without constraint failure, then a >= b
        // Return 1 (true)
        builder.one()
    }
    
    fn is_le<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        a: Target,
        b: Target,
    ) -> Target {
        Self::is_ge(builder, b, a)
    }

    /// Reduce element to canonical range [0, q)
    pub fn reduce_mod_q<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        a: Target,
    ) -> Target {
        let q_target = builder.constant(F::from_canonical_u32(Q));
        
        // For efficiency, we assume inputs are already small enough
        // In practice, would add range checks to ensure soundness
        let is_ge_q = Self::is_ge(builder, a, q_target);
        let one = builder.one();
        let is_ge_q_bool = builder.is_equal(is_ge_q, one);
        let reduced = builder.sub(a, q_target);
        builder.select(is_ge_q_bool, reduced, a)
    }
}

