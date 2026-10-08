use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use mpz_core::{Block, prg::Prg};
use mpz_fields::{Field, gf2_64::Gf2_64, gf2_128::Gf2_128};
use rand::{RngExt, SeedableRng};
use std::hint::black_box;

const INNER_PRODUCT_LENS: &[usize] = &[1 << 8, 1 << 16, 1 << 20];

fn naive_inner_product<T: Field>(a: &[T], b: &[T]) -> T {
    a.iter()
        .zip(b.iter())
        .fold(T::zero(), |acc, (x, y)| acc + *x * *y)
}

fn naive_double_inner_product<T: Field>(a: &[T], b: &[T], c: &[T]) -> T {
    a.iter()
        .zip(b.iter())
        .zip(c.iter())
        .fold(T::zero(), |acc, ((x, y), z)| acc + *x * *y * *z)
}

fn bench_mul(c: &mut Criterion) {
    let mut rng = Prg::from_seed(Block::ZERO);

    {
        let a: Gf2_64 = rng.random();
        let b: Gf2_64 = rng.random();
        c.bench_function("gf2_64/mul", move |bench| {
            bench.iter(|| black_box(a) * black_box(b));
        });
    }

    {
        let a: Gf2_128 = rng.random();
        let b: Gf2_128 = rng.random();
        c.bench_function("gf2_128/mul", move |bench| {
            bench.iter(|| black_box(a) * black_box(b));
        });
    }
}

fn bench_square(c: &mut Criterion) {
    let mut rng = Prg::from_seed(Block::ZERO);

    {
        let a: Gf2_64 = rng.random();
        c.bench_function("gf2_64/square", move |bench| {
            bench.iter(|| black_box(a).square());
        });
    }

    {
        let a: Gf2_128 = rng.random();
        c.bench_function("gf2_128/square", move |bench| {
            bench.iter(|| black_box(a).square());
        });
    }
}

fn bench_inverse(c: &mut Criterion) {
    let mut rng = Prg::from_seed(Block::ZERO);

    {
        let a: Gf2_64 = rng.random();
        c.bench_function("gf2_64/inverse", move |bench| {
            bench.iter(|| black_box(a).inverse());
        });
    }

    {
        let a: Gf2_128 = rng.random();
        c.bench_function("gf2_128/inverse", move |bench| {
            bench.iter(|| black_box(a).inverse());
        });
    }
}

fn bench_inner_product(c: &mut Criterion) {
    let mut rng = Prg::from_seed(Block::ZERO);

    {
        let mut group = c.benchmark_group("gf2_64/inner_product");
        for &len in INNER_PRODUCT_LENS {
            let a: Vec<Gf2_64> = (0..len).map(|_| rng.random()).collect();
            let b: Vec<Gf2_64> = (0..len).map(|_| rng.random()).collect();

            group.throughput(Throughput::Elements(len as u64));

            group.bench_with_input(BenchmarkId::new("accelerated", len), &len, |bench, _| {
                bench.iter(|| Gf2_64::inner_product(black_box(&a), black_box(&b)));
            });
            group.bench_with_input(BenchmarkId::new("naive", len), &len, |bench, _| {
                bench.iter(|| naive_inner_product::<Gf2_64>(black_box(&a), black_box(&b)));
            });
        }
        group.finish();
    }

    {
        let mut group = c.benchmark_group("gf2_128/inner_product");
        for &len in INNER_PRODUCT_LENS {
            let a: Vec<Gf2_128> = (0..len).map(|_| rng.random()).collect();
            let b: Vec<Gf2_128> = (0..len).map(|_| rng.random()).collect();

            group.throughput(Throughput::Elements(len as u64));

            group.bench_with_input(BenchmarkId::new("accelerated", len), &len, |bench, _| {
                bench.iter(|| Gf2_128::inner_product(black_box(&a), black_box(&b)));
            });
            group.bench_with_input(BenchmarkId::new("naive", len), &len, |bench, _| {
                bench.iter(|| naive_inner_product::<Gf2_128>(black_box(&a), black_box(&b)));
            });
        }
        group.finish();
    }
}

fn bench_double_inner_product(c: &mut Criterion) {
    let mut rng = Prg::from_seed(Block::ZERO);

    {
        let mut group = c.benchmark_group("gf2_64/double_inner_product");
        for &len in INNER_PRODUCT_LENS {
            let a: Vec<Gf2_64> = (0..len).map(|_| rng.random()).collect();
            let b: Vec<Gf2_64> = (0..len).map(|_| rng.random()).collect();
            let cc: Vec<Gf2_64> = (0..len).map(|_| rng.random()).collect();

            group.throughput(Throughput::Elements(len as u64));

            group.bench_with_input(BenchmarkId::new("accelerated", len), &len, |bench, _| {
                bench.iter(|| {
                    Gf2_64::double_inner_product(black_box(&a), black_box(&b), black_box(&cc))
                });
            });
            group.bench_with_input(BenchmarkId::new("naive", len), &len, |bench, _| {
                bench.iter(|| {
                    naive_double_inner_product::<Gf2_64>(
                        black_box(&a),
                        black_box(&b),
                        black_box(&cc),
                    )
                });
            });
        }
        group.finish();
    }

    {
        let mut group = c.benchmark_group("gf2_128/double_inner_product");
        for &len in INNER_PRODUCT_LENS {
            let a: Vec<Gf2_128> = (0..len).map(|_| rng.random()).collect();
            let b: Vec<Gf2_128> = (0..len).map(|_| rng.random()).collect();
            let cc: Vec<Gf2_128> = (0..len).map(|_| rng.random()).collect();

            group.throughput(Throughput::Elements(len as u64));

            group.bench_with_input(BenchmarkId::new("accelerated", len), &len, |bench, _| {
                bench.iter(|| {
                    Gf2_128::double_inner_product(black_box(&a), black_box(&b), black_box(&cc))
                });
            });
            group.bench_with_input(BenchmarkId::new("naive", len), &len, |bench, _| {
                bench.iter(|| {
                    naive_double_inner_product::<Gf2_128>(
                        black_box(&a),
                        black_box(&b),
                        black_box(&cc),
                    )
                });
            });
        }
        group.finish();
    }
}

criterion_group!(
    benches,
    bench_mul,
    bench_square,
    bench_inverse,
    bench_inner_product,
    bench_double_inner_product
);
criterion_main!(benches);
