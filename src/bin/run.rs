extern crate num;
extern crate num_bigint;
extern crate num_traits;

use mimc_rs::Mimc7;
use num_bigint::{BigInt, Sign};
use num_traits::Zero;
use crate::num::{Num, One};
use std::str::FromStr;
use std::ops::*;
use rayon::prelude::*;

fn main() {
    let mimc = Mimc7::new();
    let ub = BigInt::from_str("2671904647441317776153125701325350962957564013722660442345972190744117248").unwrap();
    (0..128u64).into_par_iter().for_each(|yy| {
        for y in (yy*64)..((yy+1)*64)  {
            for x in 0..8192 {
                if x % 100 == 0 {
                    println!("trying {}, {}", x, y);
                }
                let h = mimc.hash(vec![BigInt::new(Sign::Plus, vec![x]), BigInt::new(Sign::Plus, vec![y as u32])]).unwrap();
                if h < ub {
                    let (_, bytes) = h.to_bytes_be();
                    let mut v = vec![0 as u8; 32];
                    let diff = 32 - bytes.len();
                    v[diff..].copy_from_slice(&bytes);
                    println!("{:?}", v);
                    let mut z = BigInt::zero();
                    let mut two = BigInt::one().shl(8*2);
                    for i in 4..7 {
                        z += BigInt::new(Sign::Plus, vec![v[i] as u32])*&two;
                        two = two.shr(8);
                    }

                    let k = if z < BigInt::new(Sign::Plus, vec![8]) {
                        "hyper giant"
                    } else if z < BigInt::new(Sign::Plus, vec![64]) {
                        "super giant"
                    } else if z < BigInt::new(Sign::Plus, vec![512]) {
                        "giant"
                    } else if z < BigInt::new(Sign::Plus, vec![2048]) {
                        "sub giant"
                    } else if z < BigInt::new(Sign::Plus, vec![32768]) {
                        "yellow star"
                    } else if z < BigInt::new(Sign::Plus, vec![131072]) {
                        "white dwarf"
                    } else if z < BigInt::new(Sign::Plus, vec![524288]) {
                        "red dwarf"
                    } else if z < BigInt::new(Sign::Plus, vec![2097152]) {
                        "brown dwarf"
                    } else if z < BigInt::new(Sign::Plus, vec![8388608]) {
                        "big asteroid"
                    } else if z < BigInt::new(Sign::Plus, vec![16777216]) {
                        "little asteroid"
                    } else {
                        "wtf"
                    };
                    println!("found {}, {}, {}, {}", x, y, h, k);
                }
            }
        }
    });
}
