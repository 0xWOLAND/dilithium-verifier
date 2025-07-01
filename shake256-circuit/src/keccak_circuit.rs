use plonky2::field::extension::Extendable;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::target::Target;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use std::sync::Arc;

/// Keccak-f[1600] permutation circuit implementation
/// 
/// This implements the core Keccak permutation function used in SHAKE256.
/// The Keccak-f[1600] function operates on a 1600-bit state (25 64-bit words)
/// through 24 rounds of 5 operations: θ (theta), ρ (rho), π (pi), χ (chi), ι (iota)
pub struct KeccakCircuit;

impl KeccakCircuit {
    /// Create 8-bit XOR lookup table (returns Arc<Vec<(u16, u16)>>)
    fn create_xor_8bit_table() -> Arc<Vec<(u16, u16)>> {
        let mut table = Vec::new();
        for a in 0..256u16 {
            for b in 0..256u16 {
                let key = (a << 8) | b;
                let value = (a ^ b) as u16;
                table.push((key, value));
            }
        }
        Arc::new(table)
    }

    /// Create 8-bit AND lookup table (returns Arc<Vec<(u16, u16)>>)
    fn create_and_8bit_table() -> Arc<Vec<(u16, u16)>> {
        let mut table = Vec::new();
        for a in 0..256u16 {
            for b in 0..256u16 {
                let key = (a << 8) | b;
                let value = (a & b) as u16;
                table.push((key, value));
            }
        }
        Arc::new(table)
    }

    /// Create 8-bit NOT lookup table (returns Arc<Vec<(u16, u16)>>)
    fn create_not_8bit_table() -> Arc<Vec<(u16, u16)>> {
        let table: Vec<(u16, u16)> = (0..256u16).map(|x| (x, (!x as u8) as u16)).collect();
        Arc::new(table)
    }

    /// Efficient 8-bit XOR using lookup table
    fn xor_8bit_lookup<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        a: Target,
        b: Target,
        xor_table_id: usize,
    ) -> Target {
        // Create key: (a << 8) | b
        let one = builder.one();
        let key_shift = builder.exp_power_of_2(one, 8);
        let shifted_a = builder.mul(a, key_shift);
        let key = builder.add(shifted_a, b);
        
        // Lookup XOR result
        builder.add_lookup_from_index(key, xor_table_id)
    }

    /// Efficient 8-bit AND using lookup table
    fn and_8bit_lookup<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        a: Target,
        b: Target,
        and_table_id: usize,
    ) -> Target {
        // Create key: (a << 8) | b
        let one = builder.one();
        let key_shift = builder.exp_power_of_2(one, 8);
        let shifted_a = builder.mul(a, key_shift);
        let key = builder.add(shifted_a, b);
        
        // Lookup AND result
        builder.add_lookup_from_index(key, and_table_id)
    }

    /// Efficient 8-bit NOT using lookup table
    fn not_8bit_lookup<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        value: Target,
        not_table_id: usize,
    ) -> Target {
        builder.add_lookup_from_index(value, not_table_id)
    }

    /// Helper function to perform bitwise XOR on 64-bit values using 8-bit lookup tables
    fn bitwise_xor<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        a: Target,
        b: Target,
    ) -> Target {
        // Split 64-bit values into 8-bit chunks (8 bytes each)
        let a_bytes = Self::split_into_bytes(builder, a);
        let b_bytes = Self::split_into_bytes(builder, b);
        
        // Create XOR lookup table once (in practice, this would be cached)
        let xor_table = Self::create_xor_8bit_table();
        let xor_table_id = builder.add_lookup_table_from_pairs(xor_table);
        
        // XOR each byte pair using lookup table
        let mut result_bytes = Vec::new();
        for i in 0..8 {
            let xor_byte = Self::xor_8bit_lookup(builder, a_bytes[i], b_bytes[i], xor_table_id);
            result_bytes.push(xor_byte);
        }
        
        // Reconstruct 64-bit value from bytes
        Self::reconstruct_from_bytes(builder, &result_bytes)
    }

    /// Split a 64-bit target into 8 byte targets
    fn split_into_bytes<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        value: Target,
    ) -> Vec<Target> {
        let bits = builder.split_le(value, 64);
        let mut bytes = Vec::new();
        
        for i in 0..8 {
            let start_bit = i * 8;
            let end_bit = start_bit + 8;
            let byte_bits: Vec<Target> = bits[start_bit..end_bit].iter().map(|b| b.target).collect();
            let byte_value = Self::target_sum_from_le_bits(builder, &byte_bits);
            bytes.push(byte_value);
        }
        
        bytes
    }

    /// Reconstruct a 64-bit value from 8 byte targets
    fn reconstruct_from_bytes<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        bytes: &[Target],
    ) -> Target {
        let mut result = builder.zero();
        let one = builder.one();
        
        for (i, &byte) in bytes.iter().enumerate() {
            let multiplier = builder.exp_power_of_2(one, i * 8);
            let term = builder.mul(byte, multiplier);
            result = builder.add(result, term);
        }
        
        result
    }

    /// Helper function to perform bitwise rotation left
    fn rotate_left<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        value: Target,
        positions: u32,
    ) -> Target {
        if positions == 0 {
            return value;
        }
        
        let bits = builder.split_le(value, 64);
        let pos = (positions % 64) as usize;
        
        // Rotate bits: bits[pos..] + bits[..pos]
        let mut rotated_bits = Vec::new();
        for i in 0..64 {
            let src_idx = (i + 64 - pos) % 64;
            rotated_bits.push(bits[src_idx].target);
        }
        
        Self::target_sum_from_le_bits(builder, &rotated_bits)
    }

    /// Helper function to perform bitwise NOT using 8-bit lookup tables
    fn bitwise_not<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        value: Target,
    ) -> Target {
        // Split 64-bit value into 8-bit chunks
        let value_bytes = Self::split_into_bytes(builder, value);
        
        // Create NOT lookup table
        let not_table = Self::create_not_8bit_table();
        let not_table_id = builder.add_lookup_table_from_pairs(not_table);
        
        // NOT each byte using lookup table
        let mut result_bytes = Vec::new();
        for i in 0..8 {
            let not_byte = Self::not_8bit_lookup(builder, value_bytes[i], not_table_id);
            result_bytes.push(not_byte);
        }
        
        // Reconstruct 64-bit value from bytes
        Self::reconstruct_from_bytes(builder, &result_bytes)
    }

    /// Helper function to perform bitwise AND using 8-bit lookup tables
    fn bitwise_and<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        a: Target,
        b: Target,
    ) -> Target {
        // Split 64-bit values into 8-bit chunks
        let a_bytes = Self::split_into_bytes(builder, a);
        let b_bytes = Self::split_into_bytes(builder, b);
        
        // Create AND lookup table
        let and_table = Self::create_and_8bit_table();
        let and_table_id = builder.add_lookup_table_from_pairs(and_table);
        
        // AND each byte pair using lookup table
        let mut result_bytes = Vec::new();
        for i in 0..8 {
            let and_byte = Self::and_8bit_lookup(builder, a_bytes[i], b_bytes[i], and_table_id);
            result_bytes.push(and_byte);
        }
        
        // Reconstruct 64-bit value from bytes
        Self::reconstruct_from_bytes(builder, &result_bytes)
    }

    /// Helper function to sum Target bits as little-endian
    fn target_sum_from_le_bits<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        bits: &[Target],
    ) -> Target {
        let mut result = builder.zero();
        
        for (i, &bit) in bits.iter().enumerate() {
            let one = builder.one();
            let power_of_two = builder.exp_power_of_2(one, i);
            let term = builder.mul(bit, power_of_two);
            result = builder.add(result, term);
        }
        
        result
    }

    /// Keccak round constants for the 24 rounds
    const ROUND_CONSTANTS: [u64; 24] = [
        0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
        0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
        0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x8000000000008003,
        0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
        0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
        0x8000000000000000, 0x0000000080008082, 0x800000000000800A, 0x8000000080008003,
    ];

    /// Rotation offsets for the ρ (rho) step
    const RHO_OFFSETS: [u32; 25] = [
        0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14,
    ];

    /// Pi step permutation indices
    const PI_INDICES: [usize; 25] = [
        0, 6, 12, 18, 24, 3, 9, 10, 16, 22, 1, 7, 13, 19, 20, 4, 5, 11, 17, 23, 2, 8, 14, 15, 21,
    ];

    /// Build Keccak-f[1600] permutation circuit
    /// 
    /// # Arguments
    /// * `builder` - Circuit builder
    /// * `state` - Input state as 25 64-bit word targets
    /// 
    /// # Returns
    /// * Output state after Keccak-f[1600] permutation
    pub fn keccak_f<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        state: &[Target; 25],
    ) -> [Target; 25] {
        let mut current_state = *state;
        
        // Apply 24 rounds of Keccak-f[1600]
        for round in 0..24 {
            current_state = Self::keccak_round(builder, &current_state, round);
        }
        
        current_state
    }

    /// Apply one round of Keccak-f[1600]
    fn keccak_round<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        state: &[Target; 25],
        round: usize,
    ) -> [Target; 25] {
        // Step 1: θ (theta) - column parity computation
        let theta_state = Self::theta_step(builder, state);
        
        // Step 2: ρ (rho) - bit rotation  
        let rho_state = Self::rho_step(builder, &theta_state);
        
        // Step 3: π (pi) - permutation
        let pi_state = Self::pi_step(builder, &rho_state);
        
        // Step 4: χ (chi) - non-linear transformation
        let chi_state = Self::chi_step(builder, &pi_state);
        
        // Step 5: ι (iota) - round constant addition
        Self::iota_step(builder, &chi_state, round)
    }

    /// θ (theta) step: Column parity computation
    fn theta_step<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        state: &[Target; 25],
    ) -> [Target; 25] {
        // Compute column parities C[x] = A[x,0] ⊕ A[x,1] ⊕ A[x,2] ⊕ A[x,3] ⊕ A[x,4]
        let mut c = [builder.zero(); 5];
        for x in 0..5 {
            c[x] = state[x];
            for y in 1..5 {
                c[x] = Self::bitwise_xor(builder, c[x], state[y * 5 + x]);
            }
        }
        
        // Compute D[x] = C[(x+4) mod 5] ⊕ ROT(C[(x+1) mod 5], 1)
        let mut d = [builder.zero(); 5];
        for x in 0..5 {
            let c_prev = c[(x + 4) % 5];
            let c_next = c[(x + 1) % 5];
            let rotated = Self::rotate_left(builder, c_next, 1);
            d[x] = Self::bitwise_xor(builder, c_prev, rotated);
        }
        
        // Apply theta: A[x,y] = A[x,y] ⊕ D[x]
        let mut result = [builder.zero(); 25];
        for y in 0..5 {
            for x in 0..5 {
                let idx = y * 5 + x;
                result[idx] = Self::bitwise_xor(builder, state[idx], d[x]);
            }
        }
        
        result
    }

    /// ρ (rho) step: Bit rotation
    fn rho_step<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        state: &[Target; 25],
    ) -> [Target; 25] {
        let mut result = [builder.zero(); 25];
        
        for i in 0..25 {
            let offset = Self::RHO_OFFSETS[i];
            result[i] = Self::rotate_left(builder, state[i], offset);
        }
        
        result
    }

    /// π (pi) step: Lane permutation
    fn pi_step<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        state: &[Target; 25],
    ) -> [Target; 25] {
        let mut result = [builder.zero(); 25];
        
        for i in 0..25 {
            result[i] = state[Self::PI_INDICES[i]];
        }
        
        result
    }

    /// χ (chi) step: Non-linear transformation
    fn chi_step<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        state: &[Target; 25],
    ) -> [Target; 25] {
        let mut result = [builder.zero(); 25];
        
        for y in 0..5 {
            for x in 0..5 {
                let idx = y * 5 + x;
                let next_x = (x + 1) % 5;
                let next2_x = (x + 2) % 5;
                let next_idx = y * 5 + next_x;
                let next2_idx = y * 5 + next2_x;
                
                // A[x,y] = A[x,y] ⊕ ((¬A[x+1,y]) ∧ A[x+2,y])
                let not_next = Self::bitwise_not(builder, state[next_idx]);
                let and_term = Self::bitwise_and(builder, not_next, state[next2_idx]);
                result[idx] = Self::bitwise_xor(builder, state[idx], and_term);
            }
        }
        
        result
    }

    /// ι (iota) step: Round constant addition
    fn iota_step<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        state: &[Target; 25],
        round: usize,
    ) -> [Target; 25] {
        let mut result = *state;
        
        // XOR round constant with A[0,0]
        let round_constant_target = builder.constant(F::from_canonical_u64(Self::ROUND_CONSTANTS[round]));
        result[0] = Self::bitwise_xor(builder, result[0], round_constant_target);
        
        result
    }
}