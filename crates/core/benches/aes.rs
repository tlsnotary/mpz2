use criterion::{Criterion, criterion_group, criterion_main};
use std::hint::black_box;

use mpz_core::{aes::AesEncryptor, block::Block};

#[allow(clippy::all)]
fn criterion_benchmark(c: &mut Criterion) {
    let x = rand::random::<Block>();
    let aes = AesEncryptor::new(x);
    let blk = rand::random::<Block>();

    c.bench_function("aes::encrypt_block", move |bench| {
        bench.iter(|| {
            let z = aes.encrypt_block(black_box(blk));
            black_box(z);
        });
    });

    c.bench_function("aes::encrypt_many_blocks::<8>", move |bench| {
        let key = rand::random::<Block>();
        let aes = AesEncryptor::new(key);
        let mut blks = rand::random::<[Block; 8]>();

        bench.iter(|| {
            let z = aes.encrypt_many_blocks(black_box(&mut blks));
            black_box(z);
        });
    });

    c.bench_function("aes::para_encrypt::<1,8>", move |bench| {
        let key = rand::random::<Block>();
        let aes = AesEncryptor::new(key);
        let aes = [aes];
        let mut blks = rand::random::<[Block; 8]>();

        bench.iter(|| {
            let z = AesEncryptor::para_encrypt::<1, 8>(black_box(&aes), black_box(&mut blks));
            black_box(z);
        });
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
