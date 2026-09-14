# BIT Cnidarium 0.83.0 patch

This directory starts from the exact `cnidarium` 0.83.0 crate published on
crates.io with checksum
`2caa1090700cdec4305df871194280f800f8c74e1fed4031697d436a31811af5`.
The original MIT license is retained in `LICENSE`.
`UPSTREAM_SHA256SUMS` pins every copied file that BIT did not modify; the
baseline script verifies that manifest before compiling.

BIT carries a narrow storage patch because ABCI `Commit` must only acknowledge
a state transition after the complete RocksDB WriteBatch is durable:

- commit the atomic batch with WAL enabled and `WriteOptions::set_sync(true)`;
- propagate RocksDB write/fsync errors through `anyhow::Result` instead of
  panicking with `expect`;
- validate the complete Cnidarium WriteBatch encoding before it enters the WAL,
  because RocksDB can persist a truncated batch and report corruption only on
  the next database open;
- expose RocksDB's consistent physical checkpoint operation through the
  asynchronous storage API so BIT can validate and package state snapshots;
- expose construction of a historical snapshot for applications, such as BIT,
  that deliberately write every configured substore at every main-store
  version; this makes old ICS23 proofs recoverable after process restart;
- expose one-shot pre-write, corrupted-batch, and post-write/cache-publication
  fault points behind the disabled-by-default `bit-fault-injection` feature
  for deterministic crash-boundary tests.

When upgrading Cnidarium, rebase these changes onto the new published source,
run its upstream write-batch tests, and rerun BIT's complete baseline before
changing the pinned version.
