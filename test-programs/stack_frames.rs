//! Test program with known callers, in functions with real stack frames:
//!   main -> caller -> burn   all of the CPU time
//! Built the way rustc builds by default: no frame pointers, and linked
//! with lld on x86-64 Linux, which starts the code segment partway into a
//! page.
//!
//! Build: rustc -O -o stack_frames stack_frames.rs
//! Usage: stack_frames [rounds]   (each round takes about 25 ms on a 3.5 GHz core)

use std::hint::black_box;

/// The scratch array gives burn a stack frame, so unwinding it needs its
/// real unwind rule.
#[inline(never)]
fn burn(mut x: u64, n: u64) -> u64 {
    let mut scratch = [0u64; 64];
    for i in 0..n {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        scratch[(i & 63) as usize] = x;
    }
    black_box(&scratch);
    x
}

#[inline(never)]
fn caller(x: u64) -> u64 {
    let local = black_box([x; 32]);
    black_box(burn(local[3], 20_000_000)) + local[7]
}

fn main() {
    let rounds: u64 = std::env::args()
        .nth(1)
        .map_or(10, |rounds| rounds.parse().unwrap());
    let mut x = 88172645463325252u64;
    for _ in 0..rounds {
        x = caller(x);
    }
    println!("{x}");
}
