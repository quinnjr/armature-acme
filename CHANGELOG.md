# Changelog — `armature-acme`

All notable changes to this crate will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this crate adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Earlier changes are recorded in the workspace [`CHANGELOG.md`](../CHANGELOG.md).

## [Unreleased]

## [0.5.0] - 2026-10-17

### Security

- Key, certificate and account-URL files are now written atomically: a fresh `0600` temp file created with `O_CREAT | O_EXCL | O_NOFOLLOW`, `fsync`ed, given its final mode (`0600` for keys, `0644` for the public chain) and `rename`d into place, then the directory is `fsync`ed. A symlink planted at `key.pem`/`cert.pem`/`account_key.pem` is replaced instead of written through, and readers never see a partial file.
- `cert_dir` and `account_dir` are created with mode `0700` (previously umask-dependent).
- The CA HTTP client now has a connect timeout (default 10 s) and a total per-request timeout (default 30 s), and refuses plain-HTTP requests, including redirects.
- **Breaking:** the ACME directory URL must be `https://`, and every endpoint the client sends a request to — directory endpoints, account/order/authorization/challenge/finalize/certificate URLs taken from CA responses — must share the directory's origin; otherwise `AcmeError::InvalidDirectory`. Migration: use an `https://` directory URL (all public CAs and Pebble already do).
- Challenge tokens received from the CA are validated as base64url (`^[A-Za-z0-9_-]+$`) before `get_challenges` returns them, so a hostile CA cannot inject `../` into a webroot path built from the token. New public `validate_challenge_token`.
- `AcmeConfig`'s `Debug` now redacts `eab_hmac_key`.
- Replaced the unmaintained `rustls-pemfile` (RUSTSEC-2025-0134) with `rustls-pki-types`' `PemObject` for certificate parsing.

### Added

- `AcmeConfig::connect_timeout` / `request_timeout` fields and `AcmeConfig::with_timeouts`, plus `DEFAULT_CONNECT_TIMEOUT` / `DEFAULT_REQUEST_TIMEOUT`. **Breaking** for code that builds `AcmeConfig` with a struct literal; migration: start from `AcmeConfig::new(..)` / `::default()` and use the builders.

## [0.4.0] - 2026-09-15

### Changed

- **Breaking:** requires `armature-core` 0.10 (was `0.9`); its types appear in this crate's API, so the requirement change is breaking here and the minor moves. Part of the `armature-core` 0.10 release train.

### Security

- Require `rustls` 0.23.45 or later, which fixes RUSTSEC-2026-0285 (TLS 1.3 handshake messages accepted across encryption-level boundaries).

