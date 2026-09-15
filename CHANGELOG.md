# Changelog — `armature-acme`

All notable changes to this crate will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this crate adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Earlier changes are recorded in the workspace [`CHANGELOG.md`](../CHANGELOG.md).

## [Unreleased]

## [0.4.0] - 2026-09-15

### Changed

- **Breaking:** requires `armature-core` 0.10 (was `0.9`); its types appear in this crate's API, so the requirement change is breaking here and the minor moves. Part of the `armature-core` 0.10 release train.

### Security

- Require `rustls` 0.23.45 or later, which fixes RUSTSEC-2026-0285 (TLS 1.3 handshake messages accepted across encryption-level boundaries).

