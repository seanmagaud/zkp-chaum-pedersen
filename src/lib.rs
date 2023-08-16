use num_bigint::{BigUint, RandBigInt};

pub struct ZKP {
    p: BigUint,
    q: BigUint,
    alpha: BigUint,
    beta: BigUint,
}

impl ZKP {
    /// output = n^exp mod p
    pub fn exponentiate(n: &BigUint, exponent: &BigUint, modulus: &BigUint) -> BigUint {
        // return will be interpreted on the line which have no semicolon at the end
        n.modpow(exponent, modulus)
    }

    /// output = s = k - c * x mod q
    pub fn solve(&self, k: &BigUint, c: &BigUint, x: &BigUint) -> BigUint {
        if *k >= c * x {
            return (k - c * x).modpow(&BigUint::from(1u32), &self.q);
        }

        return &self.q - (c * x -k).modpow(&BigUint::from(1u32), &self.q);
    }

    /// cond1: r1 = alpha^s * y1^c
    /// cond2: r2 = beta^s * y2^c
    pub fn verify(&self, r1: &BigUint, r2: &BigUint, y1: &BigUint, y2: &BigUint, c: &BigUint, s: &BigUint) -> bool {
        let cond1 = *r1 == (&self.alpha.modpow(s, &self.p) * y1.modpow(c, &self.p)).modpow(&BigUint::from(1u32), &self.p);
        let cond2 = *r2 == (&self.beta.modpow(s, &self.p) * y2.modpow(c, &self.p)).modpow(&BigUint::from(1u32), &self.p);

        cond1 && cond2
    }

    pub fn generate_random_below(bound: &BigUint) -> BigUint {
        let mut rng = rand::thread_rng(); // might be a let mutable to regenerate a new random number each time this fn is called

        // the random generator number should be below the parameter (in test eg: q) because it must be a number in the range of the group
        rng.gen_biguint_below(bound)
}
}

#[cfg(test)] // needed for rust to interpret this as a test
mod test {
    // include all pub fn in lib.rs
    use super::*;

    #[test]
    fn test_example() {
        // alpha = 4 beta = 9 p = 23 q = 11
        // prover x = 6 k = 7
        // verifier c = 4
        let alpha = BigUint::from(4u32); // generator
        let beta = BigUint::from(9u32); // generator
        let p = BigUint::from(23u32); // prime number
        let q = BigUint::from(11u32); // group order
        let zkp = ZKP { p: p.clone(), q: q.clone(), alpha: alpha.clone(), beta: beta.clone() }; // clone is needed because BigUint is not copy

        let x = BigUint::from(6u32); // secret
        let k = BigUint::from(7u32); // random
        
        let c = BigUint::from(4u32); // challenge
        
        // y1 = alpha^x mod p
        // y2 = beta^x mod p
        let y1 = ZKP::exponentiate(&alpha, &x, &p);
        let y2 = ZKP::exponentiate(&beta, &x, &p);

        assert_eq!(y1, BigUint::from(2u32)); // 4^6 mod 23 = 2
        assert_eq!(y2, BigUint::from(3u32)); // 9^6 mod 23 = 3

        // r1 = alpha^k mod p
        // r2 = beta^k mod p
        let r1 = ZKP::exponentiate(&alpha, &k, &p);
        let r2 = ZKP::exponentiate(&beta, &k, &p);

        assert_eq!(r1, BigUint::from(8u32)); // 4^7 mod 23 = 8
        assert_eq!(r2, BigUint::from(4u32)); // 9^7 mod 23 = 4

        let s = zkp.solve(&k, &c, &x); // s = k - c * x mod q
        // using zkp.fn let us remove the mod q because it is already map on var initialization

        assert_eq!(s, BigUint::from(5u32)); // s = 7 - 4 * 6 mod 11 = 5

        let result = zkp.verify(&r1, &r2, &y1, &y2,  &c, &s); // r1 = alpha^s * y1^c mod p
        assert!(result); // should be true

        // fake secret
        let x_fake = BigUint::from(7u32); // secret
        let s_fake = zkp.solve(&k, &c, &x_fake); // s = k - c * x mod q

        let result = zkp.verify(&r1, &r2, &y1, &y2, &c, &s_fake); // r1 = alpha^s * y1^c mod p
        assert!(!result); // should be false
    }

    
    #[test]
    fn test_example_with_random_numbers() {
        // alpha = 4 beta = 9 p = 23 q = 11
        // prover x = 6 k = 7
        // verifier c = 4
        let alpha = BigUint::from(4u32); // generator
        let beta = BigUint::from(9u32); // generator
        let p = BigUint::from(23u32); // prime number
        let q = BigUint::from(11u32); // group order
        let zkp = ZKP { p: p.clone(), q: q.clone(), alpha: alpha.clone(), beta: beta.clone() };

        let x = BigUint::from(6u32); // secret
        let k = ZKP::generate_random_below(&q); // random
        
        let c = ZKP::generate_random_below(&q); // challenge
        
        // y1 = alpha^x mod p
        // y2 = beta^x mod p
        let y1 = ZKP::exponentiate(&alpha, &x, &p);
        let y2 = ZKP::exponentiate(&beta, &x, &p);

        assert_eq!(y1, BigUint::from(2u32)); // 4^6 mod 23 = 2
        assert_eq!(y2, BigUint::from(3u32)); // 9^6 mod 23 = 3

        // r1 = alpha^k mod p
        // r2 = beta^k mod p
        let r1 = ZKP::exponentiate(&alpha, &k, &p);
        let r2 = ZKP::exponentiate(&beta, &k, &p);

        let s = zkp.solve(&k, &c, &x); // s = k - c * x mod q

        let result = zkp.verify(&r1, &r2, &y1, &y2,&c, &s); // r1 = alpha^s * y1^c mod p
        assert!(result); // should be true
    }
}