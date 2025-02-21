use criterion::{black_box, criterion_group, criterion_main, Criterion};

use nprint_rs::Nprint;
use nprint_rs::Protocol;

fn benchmark(c: &mut Criterion) {
    let raw_packet = vec![
        0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x81, 0x00, 0x20, 0x45, 0x08,
        0x00, 0x45, 0x00, 0x00, 0x48, 0x6f, 0xcd, 0x40, 0x00, 0x40, 0x11, 0x46, 0x1d, 0xac, 0x10,
        0x0c, 0x9b, 0xac, 0x10, 0x1f, 0xff, 0xe1, 0x15, 0xe1, 0x15, 0x00, 0x34, 0x85, 0x00, 0x53,
        0x70, 0x6f, 0x74, 0x55, 0x64, 0x70, 0x30, 0x9e, 0x61, 0x42, 0x3d, 0x11, 0x99, 0x99, 0xee,
        0x00, 0x01, 0x00, 0x04, 0x48, 0x95, 0xc2, 0x03, 0x58, 0xc0, 0x4d, 0x5a, 0xde, 0x92, 0x01,
        0xbb, 0x72, 0x07, 0xf6, 0xa0, 0x00, 0x00, 0x00, 0x00, 0x80, 0x02, 0x20, 0x00, 0x05, 0x24,
        0x00, 0x00, 0x02, 0x04, 0x05, 0xb4, 0x01, 0x03, 0x03, 0x02, 0x01, 0x01, 0x04, 0x02,
    ];

    c.bench_function("new Nprint", |b| {
        b.iter(|| {
            Nprint::new(
                black_box(&raw_packet),
                black_box(vec![Protocol::Ipv4, Protocol::Tcp, Protocol::Udp]),
            );
        })
    });
    c.bench_function("Add 2 packet Nprint", |b| {
        b.iter(|| {
            let mut nprint = Nprint::new(
                black_box(&raw_packet),
                black_box(vec![Protocol::Ipv4, Protocol::Tcp, Protocol::Udp]),
            );
            nprint.add(&raw_packet);
        })
    });

    c.bench_function("Add 5 packet Nprint", |b| {
        b.iter(|| {
            let mut nprint = Nprint::new(
                black_box(&raw_packet),
                black_box(vec![Protocol::Ipv4, Protocol::Tcp, Protocol::Udp]),
            );
            for _i in 0..4 {
                nprint.add(black_box(&raw_packet));
            }
        })
    });

    c.bench_function("Add 10 packet Nprint", |b| {
        b.iter(|| {
            let mut nprint = Nprint::new(
                black_box(&raw_packet),
                black_box(vec![Protocol::Ipv4, Protocol::Tcp, Protocol::Udp]),
            );
            for _i in 0..9 {
                nprint.add(black_box(&raw_packet));
            }
        })
    });
}

criterion_group!(benches, benchmark);
criterion_main!(benches);
