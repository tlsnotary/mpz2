use criterion::{Criterion, criterion_group, criterion_main};
use std::hint::black_box;

use mpz_core::aes::AesEncryptor;

#[allow(clippy::all)]
fn criterion_benchmark(c: &mut Criterion) {
    let x = rand::random::<[u8; 16]>();
    let aes = AesEncryptor::new(x);
    let mut blk = rand::random::<[u8; 16]>();

    c.bench_function("aes::encrypt_block", move |bench| {
        bench.iter(|| {
            aes.encrypt_block(black_box(&mut blk));
            black_box(&blk);
        });
    });

    c.bench_function("aes::encrypt_many_blocks::<8>", move |bench| {
        let key = rand::random::<[u8; 16]>();
        let aes = AesEncryptor::new(key);
        let mut blks = std::array::from_fn::<_, 8, _>(|_| rand::random::<[u8; 16]>());

        bench.iter(|| {
            let z = aes.encrypt_many_blocks(black_box(&mut blks));
            black_box(z);
        });
    });

    c.bench_function("aes::para_encrypt::<1,8>", move |bench| {
        let key = rand::random::<[u8; 16]>();
        let aes = AesEncryptor::new(key);
        let aes = [aes];
        let mut blks = std::array::from_fn::<_, 8, _>(|_| rand::random::<[u8; 16]>());

        bench.iter(|| {
            let z = AesEncryptor::para_encrypt::<1, 8>(black_box(&aes), black_box(&mut blks));
            black_box(z);
        });
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
