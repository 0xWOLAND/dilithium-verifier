use crate::polynomial::Ring;
use crate::constants::F;
use plonky2::field::types::Field;
use std::ops::{Add, Mul, Neg, Sub};

/// A module element over a ring R, represented as a matrix with entries from R.
#[derive(Clone, Debug)]
pub struct Module<R: Ring> {
    data: Vec<Vec<R>>,
    rows: usize,
    cols: usize,
}

impl<R: Ring> Module<R> {
    /// Creates a new module element from a 2D vector of ring elements.
    pub fn new(data: Vec<Vec<R>>) -> Self {
        let rows = data.len();
        let cols = if rows > 0 { data[0].len() } else { 0 };
        Self { data, rows, cols }
    }
    
    /// Creates a column vector from a vector of ring elements.
    pub fn vector(elements: Vec<R>) -> Self {
        let rows = elements.len();
        let data = elements.into_iter().map(|e| vec![e]).collect();
        Self { data, rows, cols: 1 }
    }
    
    /// Creates a zero matrix of given dimensions.
    pub fn zero(rows: usize, cols: usize) -> Self {
        let data = vec![vec![R::zero(); cols]; rows];
        Self { data, rows, cols }
    }
    
    /// Creates an identity matrix of given dimension.
    pub fn identity(size: usize) -> Self {
        let mut data = vec![vec![R::zero(); size]; size];
        for i in 0..size {
            data[i][i] = R::one();
        }
        Self { data, rows: size, cols: size }
    }
    
    /// Returns the dimensions of the matrix as (rows, cols).
    pub fn dim(&self) -> (usize, usize) {
        (self.rows, self.cols)
    }
    
    /// Returns the transpose of the matrix.
    pub fn transpose(&self) -> Self {
        let mut data = vec![vec![R::zero(); self.rows]; self.cols];
        for i in 0..self.rows {
            for j in 0..self.cols {
                data[j][i] = self.data[i][j].clone();
            }
        }
        Self { data, rows: self.cols, cols: self.rows }
    }
    
    /// Scales every element by a ring element.
    pub fn scale(&self, scalar: &R) -> Self {
        let data = self.data.iter()
            .map(|row| row.iter().map(|e| e.clone() * scalar.clone()).collect())
            .collect();
        Self { data, rows: self.rows, cols: self.cols }
    }
    
    /// Computes the dot product with another module element (for vectors).
    pub fn dot(&self, other: &Self) -> R {
        if self.cols != 1 || other.cols != 1 || self.rows != other.rows {
            panic!("Dot product only defined for vectors of same length");
        }
        
        let mut result = R::zero();
        for i in 0..self.rows {
            result = result + self.data[i][0].clone() * other.data[i][0].clone();
        }
        result
    }
    
    /// Gets the element at position (i, j).
    pub fn get(&self, i: usize, j: usize) -> Option<&R> {
        self.data.get(i)?.get(j)
    }
    
    /// Sets the element at position (i, j).
    pub fn set(&mut self, i: usize, j: usize, value: R) -> Result<(), &'static str> {
        if i >= self.rows || j >= self.cols {
            return Err("Index out of bounds");
        }
        self.data[i][j] = value;
        Ok(())
    }
}

impl<R: Ring> Add for Module<R> {
    type Output = Self;
    
    fn add(self, other: Self) -> Self::Output {
        if self.dim() != other.dim() {
            panic!("Cannot add matrices of different dimensions");
        }
        
        let data = self.data.iter()
            .zip(other.data.iter())
            .map(|(row1, row2)| {
                row1.iter()
                    .zip(row2.iter())
                    .map(|(e1, e2)| e1.clone() + e2.clone())
                    .collect()
            })
            .collect();
        
        Self { data, rows: self.rows, cols: self.cols }
    }
}

impl<R: Ring> Neg for Module<R> {
    type Output = Self;
    
    fn neg(self) -> Self::Output {
        let data = self.data.iter()
            .map(|row| row.iter().map(|e| -e.clone()).collect())
            .collect();
        Self { data, rows: self.rows, cols: self.cols }
    }
}

impl<R: Ring> Sub for Module<R> {
    type Output = Self;
    
    fn sub(self, other: Self) -> Self::Output {
        self + (-other)
    }
}

impl<R: Ring> Mul for Module<R> {
    type Output = Self;
    
    fn mul(self, other: Self) -> Self::Output {
        if self.cols != other.rows {
            panic!("Cannot multiply matrices: dimensions don't match");
        }
        
        let mut data = vec![vec![R::zero(); other.cols]; self.rows];
        
        for i in 0..self.rows {
            for j in 0..other.cols {
                for k in 0..self.cols {
                    data[i][j] = data[i][j].clone() + 
                                self.data[i][k].clone() * other.data[k][j].clone();
                }
            }
        }
        
        Self { data, rows: self.rows, cols: other.cols }
    }
}

impl<R: Ring> PartialEq for Module<R> {
    fn eq(&self, other: &Self) -> bool {
        if self.dim() != other.dim() {
            return false;
        }
        
        self.data.iter()
            .zip(other.data.iter())
            .all(|(row1, row2)| {
                row1.iter()
                    .zip(row2.iter())
                    .all(|(e1, e2)| e1 == e2)
            })
    }
}

impl<R: Ring> Eq for Module<R> {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::polynomial::Polynomial;
    use crate::constants::F;
    
    #[test]
    fn test_module_creation() {
        let zero = Module::<Polynomial>::zero(2, 3);
        let identity = Module::<Polynomial>::identity(2);
        
        assert_eq!(zero.dim(), (2, 3));
        assert_eq!(identity.dim(), (2, 2));
    }
    
    #[test]
    fn test_matrix_operations() {
        // Create test matrices
        let m1 = Module::<Polynomial>::new(vec![
            vec![Polynomial::new(vec![F::ONE]), Polynomial::new(vec![F::TWO])],
            vec![Polynomial::new(vec![F::from_canonical_u32(3)]), Polynomial::new(vec![F::from_canonical_u32(4)])]
        ]);
        
        let m2 = Module::<Polynomial>::new(vec![
            vec![Polynomial::new(vec![F::ONE]), Polynomial::new(vec![F::ONE])],
            vec![Polynomial::new(vec![F::ONE]), Polynomial::new(vec![F::ONE])]
        ]);
        
        // Test addition
        let sum = m1.clone() + m2.clone();
        assert_eq!(sum.get(0, 0).unwrap().coefficients()[0], F::TWO);
        
        // Test multiplication
        let product = m1 * m2.clone();
        assert_eq!(product.dim(), (2, 2));
        
        // Test transpose
        let transpose = m2.transpose();
        assert_eq!(transpose.dim(), (2, 2));
    }
    
    #[test]
    fn test_vector_operations() {
        let v1 = Module::<Polynomial>::vector(vec![
            Polynomial::new(vec![F::ONE]),
            Polynomial::new(vec![F::TWO]),
            Polynomial::new(vec![F::from_canonical_u32(3)])
        ]);
        
        let v2 = Module::<Polynomial>::vector(vec![
            Polynomial::new(vec![F::ONE]),
            Polynomial::new(vec![F::ONE]),
            Polynomial::new(vec![F::ONE])
        ]);
        
        // Test dot product
        let dot_product = v1.dot(&v2);
        assert_eq!(dot_product.coefficients()[0], F::from_canonical_u32(6));
        
        // Test scaling
        let scalar = Polynomial::new(vec![F::TWO]);
        let scaled = v1.scale(&scalar);
        assert_eq!(scaled.get(0, 0).unwrap().coefficients()[0], F::TWO);
    }
}