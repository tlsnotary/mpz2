use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use std::hint::black_box;

use mpz_core::{block::Block, prg::Prg};
use rand_core::Rng;

fn criterion_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("prg");

    group.throughput(Throughput::Bytes(1));
    group.bench_function("byte", move |bench| {
        let mut prg = Prg::new();
        let mut x = 0u8;
        bench.iter(|| {
            x = prg.random_byte();
            black_box(x);
        });
    });

    const BYTES_PER: u64 = 16 * 1024;
    group.throughput(Throughput::Bytes(BYTES_PER));
    group.bench_function("bytes", move |bench| {
        let mut prg = Prg::new();
        let mut x = (0..BYTES_PER)
            .map(|_| rand::random::<u8>())
            .collect::<Vec<u8>>();
        bench.iter(|| {
            prg.fill_bytes(black_box(&mut x));
        });
    });

    group.throughput(Throughput::Elements(1));
    group.bench_function("block", move |bench| {
        let mut prg = Prg::new();
        let mut x = Block::ZERO;
        bench.iter(|| {
            x = prg.random_block();
            black_box(x);
        });
    });

    const BLOCKS_PER: u64 = 16 * 1024;
    group.throughput(Throughput::Elements(BLOCKS_PER));
    group.bench_function("blocks", move |bench| {
        let mut prg = Prg::new();
        let mut x = (0..BLOCKS_PER)
            .map(|_| rand::random::<Block>())
            .collect::<Vec<Block>>();
        bench.iter(|| {
            prg.random_blocks(black_box(&mut x));
        });
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
