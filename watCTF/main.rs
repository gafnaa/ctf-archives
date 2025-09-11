use rand::{seq::SliceRandom, Rng};
use rustc_hash::FxBuildHasher;
use std::{hash::{BuildHasher, Hash}, io::{self, BufRead, Read, Write}};
use simplehash::fnv1a_64;

fn do_hash(x: i32) -> u64 {
    fnv1a_64(&x.to_le_bytes())
}

const HASH_SIZE: usize = 32;

fn test_perm_restricted_memory(perm: &[i32]) -> bool {
    let mut map = [-1i32; HASH_SIZE];
    for x in perm {
        let idx = (do_hash(*x) % HASH_SIZE as u64) as usize;
        if map[idx] == *x {
            // duplicate, fail
            return false;
        } else {
            // not a duplicate, continue
        }
        map[idx] = *x;
    }
    true
}

fn parse_perm(inp: &str) -> Result<Vec<i32>, &'static str> {
    let ans: Vec<i32> = inp.trim().split(' ').map(|x| x.parse::<u32>().unwrap() as i32).collect();
    if ans.len() != 256 {
        return Err("permutation is not of length 256");
    }
    for x in &ans {
        if *x < 0 || 256 <= *x {
            return Err("permutation element out of range");
        }
    }
    if !test_perm_restricted_memory(&ans) {
        return Err("permutation has non-unique elements");
    }
    Ok(ans)
}

fn compose_perms(p1: &[i32], p2: &[i32]) -> Vec<i32> {
    p1.iter().map(|i| p2[*i as usize]).collect()
}

fn main() {
    let mut rng = rand::rng();
    let mut cipherperm: Vec<i32> = (0..256).collect();
    cipherperm.shuffle(&mut rng);
    let stdin = io::stdin();
    let mut line_iter = stdin.lock().lines();
    let mut get_line = || -> String {
        line_iter.next().unwrap().unwrap()
    };
    println!("Welcome to the Permutation Oracle.");
    loop {
        println!("Main Menu");
        println!("1. Give the oracle a permutation");
        println!("2. Guess the secret permutation");
        print!("Enter your choice: ");
        io::stdout().flush().unwrap();
        let choice = get_line();
        let choice: u32 = choice.trim().parse().unwrap();
        if choice == 1 {
            print!("Enter the permutation seperated by spaces: ");
            io::stdout().flush().unwrap();
            let perm_str = get_line();
            let perm = match parse_perm(&perm_str) {
                Err(e) => {
                    println!("Error: {e}");
                    continue;
                },
                Ok(v) => v,
            };
            let res = compose_perms(&perm, &cipherperm);
            let i = rng.random_range(0..res.len());
            println!("The oracle has divined... {}", res[i]);
        } else if choice == 2 {
            print!("Enter the permutation seperated by spaces: ");
            io::stdout().flush().unwrap();
            let perm_str = get_line();
            let perm = match parse_perm(&perm_str) {
                Err(e) => {
                    println!("Error: {e}");
                    continue;
                },
                Ok(v) => v,
            };
            if perm == cipherperm {
                println!("Good job! Here's your reward: {}", std::env::var("FLAG").unwrap());
            } else {
                println!("Unfortunately, wrong :/");
            }
        }
    }
}
