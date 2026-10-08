use std::{hint::black_box, sync::Arc};

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use mpz_common::io::Io;
use pollster::FutureExt;
use serde::{Deserialize, Serialize};
use serio::{SinkExt, stream::IoStreamExt};
use tokio::{
    io::duplex,
    net::{TcpListener, TcpStream},
    sync::Mutex,
};
use tokio_util::compat::TokioAsyncReadCompatExt;

#[derive(Clone, Serialize, Deserialize)]
struct Packet {
    data: Vec<u8>,
}

fn criterion_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("io");

    const SIZE: usize = 1024 * 1024;

    group.throughput(Throughput::Bytes(SIZE as u64));
    group.bench_function("memory", |b| {
        let (io_0, io_1) = duplex(16 * 1024 * 1024); // 16 MB buffer.
        let mut io_0 = Io::from_io(io_0.compat());
        let mut io_1 = Io::from_io(io_1.compat());
        let packet = Packet {
            data: vec![0; SIZE],
        };
        b.iter(|| {
            async {
                let (_, out): (_, Packet) =
                    futures::try_join!(io_0.send(packet.clone()), io_1.expect_next()).unwrap();
                black_box(out);
            }
            .block_on()
        });
    });

    group.bench_function("tcp", |b| {
        let rt = tokio::runtime::Runtime::new().unwrap();

        let (io_0, io_1): (TcpStream, TcpStream) = rt.block_on(async {
            let listener = TcpListener::bind("0.0.0.0:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            tokio::join!(
                async {
                    let (io, _) = listener.accept().await.unwrap();
                    io
                },
                async { TcpStream::connect(addr).await.unwrap() }
            )
        });

        let io_0 = Arc::new(Mutex::new(Io::from_io(io_0.compat())));
        let io_1 = Arc::new(Mutex::new(Io::from_io(io_1.compat())));

        let packet = Packet {
            data: vec![0; SIZE],
        };

        b.to_async(&rt).iter(|| async {
            let mut io_0 = io_0.try_lock().unwrap();
            let mut io_1 = io_1.try_lock().unwrap();
            let (_, out): (_, Packet) =
                tokio::try_join!(io_0.send(packet.clone()), io_1.expect_next()).unwrap();
            black_box(out);
        });
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
