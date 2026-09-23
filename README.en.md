[![ANYKS - Network Transport Security](https://gitflic.ru/project/anyks/nts/blob/raw?file=img%2Fbanner.jpg)](https://anyks.com)

# ANYKS - Network Transport Security (A-NTS)

Русская версия: [README.md](README.md)

[![LicenseRef-A-NTS-1.0](https://img.shields.io/badge/license-A--NTS%201.0-blue.svg)](LICENSE)

A cryptographic library and a TLS implementation in C++ — a standalone project that
depends on no third-party cryptographic code whatsoever.

## Purpose

The library is written from scratch by the texts of the standards, not derived as a fork of
OpenSSL or BoringSSL. Third-party implementations are involved only as a reference for
comparison: the results are checked against them for equality, no code is borrowed from them.

Grounds for the choice:

* **Own ownership of the code.** A derivative of somebody else's library inherits both
  somebody else's decisions and somebody else's responsibility for them.
* **Build without foreign tooling.** OpenSSL has Perl at the foundation of its build,
  BoringSSL has Go and its own CMake. Here there is neither: the project is built with
  one CMake and one C++ compiler.
* **Portability.** The target matrix coincides with the matrix of AWH: macOS, FreeBSD,
  NetBSD, OpenBSD, Solaris, illumos, Linux and MinGW on x86-64 and ARM64.
* **C++ instead of C.** Ownership of the lifetime, views instead of the pair "pointer and
  length", a type instead of a lookup by a string name.

## Relation to AWH

The project is standalone: AWH uses it, but it does not use AWH. What remains shared is
the code style, the structure of the build and the order of testing.

The namespace is `nts`.

Ready modules of AWH are allowed to be moved here and reworked to the needs of the
project — both are ANYKS projects. A moved module must obey the rule of internal
placement.

**Rule of embedding into AWH: sheltered storage of the key material.** The keys that
A-NTS keeps between calls lie in its own sheltered vault
`nts::sys::Vault` (section "Sheltered storage of the key material"). When AWH moves
from BoringSSL to A-NTS (decision of 17.09.2026):

- there is NO need to take the vault out into a separate project and attach it as a
  submodule to both: A-NTS must stay without dependencies, and the dependency AWH → A-NTS
  is one-way anyway;
- the key material that AWH itself keeps between calls (the derived key
  `state_t::key` in `awh::Crypto`, passwords, salt — see `AWH-KEY-EMBEDDING.md`,
  requirement 2a) AWH puts **directly into `nts::sys::Vault`**: as a piece
  `nts::sys::secret_t` or as a set `nts::sys::bytes_t`. There is no need to set up a second
  storage of secrets (`Allocator::secure`) for this — a secret must live in one place
  together with the keys of the connection, with one report `shelter()` and one demand
  `demand()`;
- the allocator of AWH (`awh::alloc`) remains the allocator of the general memory and does
  not contend with the vault: the chunks of the vault are taken from the kernel directly and
  are given to nobody; the only thing shared by them is the limit `RLIMIT_MEMLOCK` — whoever
  locks memory shares it, and each one reports its own honestly;
- the junction with the embedded key: `scatter_t::gather` collects the material, `embed::key` /
  `embed::secret` derive the key from it, the receiver of the derivation is `nts::sys::secret_t`;
  the fields `context::ticket_t::secret` and `context::psk_t::key` AWH fills through
  `assign(begin, end)`, not by assignment.

## Internal modules

Everything moved from AWH or written in aid of the main sections lives under
`src/internal` and **is not exported outside**: the header file of an internal module
is included only from `.cpp`, never from the header files of the directory
`include`.

Grounds. The external view of the library is a contract that later cannot be changed
without breaking the consumers. The internal modules are moved from another project and will
be reworked to the task; having got into the external view, they would fix that contract
by themselves, and together with it they would fix their own structure, chosen for other tasks.
Besides, the external view would thereby stop answering the question of what the
library does, and would start answering the question of what it is assembled from.

The rule is checked at the configuration of the build: an inclusion of `internal/` from a
header file of the directory `include` aborts the configuration with a refusal.

## Comparison with the references

Correctness and speed are checked against OpenSSL and BoringSSL. Their role is
exclusively a reference: the results are checked against them for equality, and the lag
or the lead is measured. No code is borrowed from them, and they do not get into the
tree of the project.

## Layout

| Directory | Purpose |
|---|---|
| `include/sys`, `src/sys` | Common definitions of the build, detection of the machine instructions, wiping of the memory with secrets (`sys::wipe`) and the sheltered vault of the key material (`sys::Vault`, `sys::Secret`, `sys::bytes_t`): forbidding of swapping, hiding from dumps, wiping at the child and on release, the honest report `shelter()` and the demand `demand()` |
| `include/sys/log.hpp`, `src/sys/log.cpp` | Log sink: one function of the consumer, set at run time (`sys::log::sink`); without a sink the library stays silent and builds no strings; no headers or build definitions of foreign projects |
| `include/embed`, `src/embed` | Derivation of a key embedded into the image of the application: `embed::key` (HKDF over the material gathered from the image) and `embed::secret` (Argon2 from a password) with the binding of the version and of the region of the image |
| `include/asn1`, `src/asn1` | Parsing and writing of ASN.1 in the DER encoding |
| `include/x509`, `src/x509` | Parsing of X.509 certificates by RFC 5280 and verification of their signature by RFC 9215 |
| `include/ocsp`, `src/ocsp` | Certificate status by RFC 6960: parsing and verification of an OCSP response against the certificate and the issuer (the issuer itself or a delegated responder with `id-kp-OCSPSigning`, classic and GOST algorithms, validity periods with a tolerance, a nonce), composition of the `OCSPRequest` and the address of the responder from AIA; there is no input and output — the octets are supplied by the consumer |
| `include/digest`, `src/digest` | Hashing "Streebog" by GOST R 34.11-2012, SHA-2, SHA-1 and MD5, the common hash selection `hash_t`, the HMAC authentication tag (one-shot and streaming), HKDF with Expand-Label, PBKDF2, the TLS pseudo-random function by RFC 7836 ("Streebog") and by section 5 of RFC 5246 (SHA-256, SHA-384) and the derived key generation by RFC 7836 |
| `include/cipher`, `src/cipher` | Block ciphers: "Kuznyechik" and "Magma" by GOST R 34.12-2015, AES by FIPS 197; modes of operation by GOST R 34.13-2015 (common to all ciphers, including CBC and CFB), the MGM mode by RFC 9058, GCM by SP 800-38D (one-shot and streaming), ChaCha20, Poly1305 and AEAD_CHACHA20_POLY1305 by RFC 8439 (`chacha_t`, `poly1305_t`, `chachapoly_t`, the streaming contract is the same as with GCM) and the streaming wrapper `stream_t` for AWH: the vector at the head of the stream, the GCM tag at the tail, in chunks of any length |
| `include/math`, `src/math` | Arithmetic of fixed-width numbers by a prime modulus, the field 2^255−19 and multi-precision integers up to 4096 bits for RSA |
| `include/entropy`, `src/entropy` | Source of random values of the system |
| `include/curve`, `src/curve` | Arithmetic of the points of an elliptic curve and the parameter sets of the curves |
| `include/sign`, `src/sign` | Digital signature by GOST R 34.10-2012, ECDSA on P-256/P-384, Ed25519, RSA (PKCS #1 v1.5, PSS, OAEP); generation of long-term keys `generate` and the upper bound of the length of the signature in the written form `limit` |
| `include/agreement`, `src/agreement` | Shared key derivation VKO by RFC 7836, X25519 by RFC 7748 with the generation of a key pair `generate`, fit also as a long-term one, and the ephemeral key exchange of TLS 1.3 |
| `include/record`, `src/record` | The record layer of the TLS protocol by RFC 5246 and RFC 8446; the versions DTLS 1.2 (0xFEFD) and DTLS 1.0 (0xFEFF, the version of HelloVerifyRequest) in the list of versions |
| `include/protect`, `src/protect` | Record protection of TLS 1.3 with the cipher suites on the GOST algorithms and the classic suites AES-GCM and ChaCha20-Poly1305 by RFC 8446; TLS 1.2 records with the suites ECDHE-ECDSA and ECDHE-RSA on AES-GCM (RFC 5288, the explicit part of the nonce is the sequence number) and ChaCha20-Poly1305 (RFC 7905) with the sequence number and the wire record header in the associated data (section 6.2.3.3 of RFC 5246); the record limit of AES-GCM 2^24.5 common to both versions; record protection of DTLS 1.2 with the epoch and the sequence number in the associated data and in the explicit part (section 4.1.2.1 of RFC 6347) through `wrap`/`unwrap` with the given number and version, `prefix` — the length of the explicit part |
| `include/datagram`, `src/datagram` | The record layer of DTLS 1.3 by RFC 9147: the plaintext header and the unified header of a protected record, the framing of the fragments of handshake messages, the acknowledgement message `ack`, encryption of the record number with a mask of AES-ECB or ChaCha20 by the label `sn`, recovery of the number by its low bits and the anti-replay window; the reasons of discarding `reason_t`, including `VERSION` at a foreign version in the DTLS 1.2 header |
| `include/field`, `src/field` | Reading and writing of variable-length fields of the protocol |
| `include/handshake`, `src/handshake` | Framing of the handshake messages by section 4 of RFC 8446; the TLS 1.2 message types: HelloRequest (wire zero), ServerKeyExchange, ServerHelloDone, ClientKeyExchange, CertificateStatus; the DTLS 1.2 type HelloVerifyRequest (3, section 4.2.1 of RFC 6347); the type "not set" `NONE` lies outside the registry (0xFF) and coincides with no wire value |
| `include/hello`, `src/hello` | The hello messages of the handshake by sections 4.1.2 and 4.1.3 of RFC 8446; the client hello over datagrams with the stateless-cookie field after the connection identifier (section 4.2.1 of RFC 6347, section 5.3 of RFC 9147) — the overloads `parse`/`build` with the datagram flag |
| `include/extension`, `src/extension` | The hello extensions by section 4.2 of RFC 8446; the list of the certificate chain compression algorithms `compress_certificate` by RFC 8879; the type `status_request` (0x0005) by RFC 6066; the TLS 1.2 types: `ec_point_formats` (RFC 8422), `extended_master_secret` (RFC 7627), `renegotiation_info` (RFC 5746); the schemes RSASSA-PKCS1-v1_5 (0x0401, 0x0501, 0x0601) for TLS 1.2 |
| `include/message`, `src/message` | The certificate chain, the proof of key possession and the finishing of the handshake |
| `include/session`, `src/session` | The handshake transcript and the key schedule of the connection by section 7.1 of RFC 8446 over the hash of the cipher suite (SHA-256, SHA-384, "Streebog"-256) |
| `include/flow`, `src/flow` | The course of the handshake: the order of messages and the key epoch of the sides |
| `include/context`, `src/context` | Common declarations of the facades: the state of the connection, the errors, the authentication of a side, the transport (records, QUIC levels, datagrams of DTLS 1.3 and DTLS 1.2) and the QUIC protection levels, the resumption ticket and its codec into octets, the description of a certificate chain compression algorithm `codec_t` (two stateless calls of the consumer) |
| `include/client`, `src/client` | The client connection facade: the TLS 1.3 and TLS 1.2 handshake (the version bounds `versions`, `lowest`, `highest`, the negotiated version `version`), data, key update and resumption; the handshake by levels for QUIC with the release of the level secrets; the connection over datagrams by DTLS 1.3 and DTLS 1.2 by the version bounds (`mtu`, `timeout`, `elapsed`, `discarded` total and by reasons; in 1.2 the HelloVerifyRequest of a foreign server is answered with a repeated hello carrying the cookie); certificate chain compression by RFC 8879 with the algorithms of the consumer (`codecs`, `compression`); request and verification of the stapled OCSP response (`status`, `verification`, `certified`) |
| `include/server`, `src/server` | The server connection facade: the TLS 1.3 and TLS 1.2 handshake (the version bounds `versions`, `lowest`, `highest`, `version`, the order of suite selection `preference`), authentication, request of the client authentication and tickets; the handshake by levels for QUIC with the release of the level secrets; the connection over datagrams by DTLS 1.3 and DTLS 1.2 with the mandatory stateless cookie (`address`, `stamp`, `restamp`, `mtu`, `timeout`, `elapsed`, `discarded` total and by reasons; in 1.2 — a stateless server with HelloVerifyRequest); certificate chain compression by RFC 8879 with the algorithms of the consumer (`codecs`, `compression`); stapling of the OCSP response at the request of the client and the request of the client certificate status (`status`, `verification`, `certified`) |
| `include/trust`, `src/trust` | Trust in a certificate chain: the store, verification of the chain and matching of the name |
| `include/pem`, `src/pem` | Storage of records in the PEM form by RFC 7468: the wrapper, the certificate chain and the private key |
| `include/keys`, `src/keys` | Key codecs: SubjectPublicKeyInfo, PrivateKeyInfo, EncryptedPrivateKeyInfo by PBES2, ECPrivateKey, RSAPrivateKey and RSAPublicKey; RSA, EC, Ed25519, X25519 and GOST; from memory into DER and PEM and back |
| `include/alert`, `src/alert` | Alerts: the level, the description and the decision on the closing of the connection; `no_renegotiation` (100) for TLS 1.2 — always a warning, the connection continues |
| `include/schedule`, `src/schedule` | The key schedule of TLS 1.3 by section 7.1 of RFC 8446 over `digest::hash_t`; the methods without the hash argument drive the GOST branch |
| `src/internal` | Internal modules, not exported outside: `engine` — driving of a TLS 1.3 connection in both roles (records, QUIC levels, DTLS 1.3 datagrams) and TLS 1.2 (records: ECDHE, EMS by RFC 7627, renegotiation_info by RFC 5746 without renegotiation — refusal by the warning `no_renegotiation`, CertificateStatus by RFC 6066, version negotiation by supported_versions and legacy_version with the downgrade guard at a server capable of 1.3, matching of the record header version with the negotiated one, closing of the connection with `close_notify` with the error `EXHAUSTED` on exhaustion of the records on a key), `flight` — transport of the handshake by datagrams by DTLS 1.3 and DTLS 1.2 (epochs, flights, reassemblies, anti-replay windows, timers, cookie; in 1.2 — plaintext headers of all records, change of cipher spec within the flight, a stateless server, the last flight without a timer) |

Sections are added as they become ready. The order of work: ASN.1 and X.509, then
hashes and symmetric ciphers, then asymmetric cryptography, then the course of TLS.

The constants of the cryptographic transformations are carried over from the text of the
standard verbatim and are not recomputed in the source text; everything derived from
them is computed at build time.

The parsing of a certificate record and the verification of its signature are separated on
purpose: `x509` parses the record and knows nothing about any cryptography, the signature is
matched in `x509/signature`, and the chain of trust is built in `trust`. That is why the parsing
remains usable where there is nothing and no reason to match the signature with.

## Cipher suites

| Suite | Number | Record cipher | Schedule hash | Key exchange | Signatures |
|---|---|---|---|---|---|
| `KUZNYECHIK_MGM_L` | 0xC103 | "Kuznyechik" MGM, TLSTREE key | "Streebog"-256 | GOST `GC256A…GC512C` | GOST R 34.10-2012 |
| `MAGMA_MGM_L` | 0xC104 | "Magma" MGM, TLSTREE key | "Streebog"-256 | the same | the same |
| `KUZNYECHIK_MGM_S` | 0xC105 | "Kuznyechik" MGM, frequent rekeying | "Streebog"-256 | the same | the same |
| `MAGMA_MGM_S` | 0xC106 | "Magma" MGM, frequent rekeying | "Streebog"-256 | the same | the same |
| `AES_128_GCM_SHA256` | 0x1301 | AES-128-GCM, vector 12, tag 16 | SHA-256 | `X25519`, `SECP256R1`, `SECP384R1` | ECDSA P-256/P-384, RSA-PSS (rsae, SHA-256/384/512), Ed25519 |
| `AES_256_GCM_SHA384` | 0x1302 | AES-256-GCM, vector 12, tag 16 | SHA-384 | the same | the same |
| `CHACHA20_POLY1305_SHA256` | 0x1303 | ChaCha20-Poly1305 (`chachapoly_t`), key 32, vector 12, tag 16, record limit 2^62 | SHA-256 | the same | the same |
| `ECDHE_ECDSA_AES_128_GCM_SHA256` … `ECDHE_ECDSA_CHACHA20_POLY1305_SHA256` | 0xC02B, 0xC02C, 0xC02F, 0xC030, 0xCCA8, 0xCCA9 | TLS 1.2: AES-GCM (RFC 5288, the explicit part is the number) and ChaCha20-Poly1305 (RFC 7905) | SHA-256/384 (PRF) | ECDHE `X25519`, `SECP256R1`, `SECP384R1` | ECDSA, RSA-PSS, PKCS #1 v1.5, Ed25519 |
| `ECDHE_ECDSA_AES_128_CBC_SHA256`, `ECDHE_RSA_AES_128_CBC_SHA256`, `ECDHE_ECDSA_AES_128/256_CBC_SHA`, `ECDHE_RSA_AES_128/256_CBC_SHA` | 0xC023, 0xC027, 0xC009, 0xC00A, 0xC013, 0xC014 | TLS 1.2: AES-CBC with HMAC-SHA256/SHA1 (section 6.2.3.2 of RFC 5246), explicit vector, encrypt_then_mac of RFC 7366 is preferred | SHA-256 (PRF) | ECDHE | the same |
| `RSA_AES_128/256_CBC_SHA`, `RSA_AES_128/256_CBC_SHA256`, `RSA_AES_128/256_GCM_SHA256/384` | 0x002F, 0x0035, 0x003C, 0x003D, 0x009C, 0x009D | TLS 1.2: plain RSA exchange (section 7.4.7.1 of RFC 5246) with AES-CBC or AES-GCM | SHA-256/384 (PRF) | RSAES-PKCS1-v1_5 with the key of the RSA certificate | none (authentication by decryption) |
| `PSK_AES_128/256_CBC_SHA`, `ECDHE_PSK_AES_128/256_CBC_SHA`, `ECDHE_PSK_CHACHA20_POLY1305_SHA256` | 0x008C, 0x008D, 0xC035, 0xC036, 0xCCAC | TLS 1.2: pre-shared key (RFC 4279, RFC 5489, RFC 7905), without certificates | SHA-256 (PRF) | PSK or ECDHE ‖ PSK | none |

Suites, groups and signature schemes are declared by the consumer per connection, in the
order of preference; the defaults are the classics without GOST, as at the browsers and OpenSSL 3.5:
the groups X25519MLKEM768, X25519, secp256r1, secp384r1 with the key shares by the hybrid and by
X25519, the suites 0x1302, 0x1303, 0x1301 and the suites of the edition 1.2, the schemes ECDSA,
RSA-PSS, Ed25519, RSA PKCS #1. Whoever needs GOST declares the curves, the suites and the schemes
by the lists `groups()`, `suites()` and `schemes()` — as a support, appending them to the default
taken from the getters of the same names, or as the only option, replacing the lists entirely;
the list of the consumer is not re-sorted. The order of the list is the preference itself: without
assigned shares the client sends a share by the first group and by the first group of every kind
not yet represented (the GOST curves, the hybrids with ML-KEM, the classic curves), and the server
chooses the suite and the curve by its own order (`preference(true)`, the default) or by the order
of the client (`preference(false)`). So a server with GOST ahead of its list takes GOST from a
client with GOST support and the classics from a client without GOST, all without a retry request
(`ContextTest.Defaults`, `ContextTest.Compatible`, `ContextTest.Gost`, `ContextTest.Preference`).
A resumption ticket is fit only for a suite
with the same hash (§4.6.1): 0x1301 ↔ 0x1303 resume each other, 0x1302 does not with them
(`ClassicTest.Crossing`, `ClassicTest.Reselect`). Values unknown to the connection
(GREASE, RFC 8701) are silently skipped in the lists of the peer; own GREASE values are
inserted by one knob `grease(true)` after the pattern of BoringSSL (section "GREASE by RFC 8701"
below), and beyond that the consumer is free to insert such values from outside into the suites,
groups, schemes and key shares (`client::Context::shares`). Key exchange by the GOST curves, X25519 (RFC 7748) and the
NIST curves with an uncompressed point with a check of membership in the curve; the proof of key
possession by the scheme matching the key of the certificate (PKCS #1 v1.5 is rejected); the private
key of the classic authentication is supplied as a PKCS #8 record in DER or PEM. The vectors of RFC 8448
(sections 3, 4, 5) are pinned by the test `ClassicTest.Rfc8448*`, the exchange with a real
`openssl s_server`/`s_client` — by `ClassicTest.Openssl`.

The boundary between the handshake and the records: the handshake machine (`flow`, `handshake`, `session`,
`schedule`) knows only the level secrets (`session::secrets_t`: early, handshake
and application per side, resumption — of the length of the suite hash), and the record keys are
derived from them by a separate step `session::material` → `protect::protection_t`; the engine owns
only the buffers `push`/`output`/`consume`, the post-handshake messages (key update,
tickets) go through the same message machine.

## Build

```bash
mkdir build && cd build
cmake -DCMAKE_BUILD_TYPE=Release ..
cmake --build . -j
```

Build options:

| Option | Default | Purpose |
|---|---|---|
| `CMAKE_BUILD_TYPE` | `Debug` | Build type |
| `CMAKE_SHARED_BUILD_LIB` | `OFF` | Build a shared library instead of a static one |
| `CMAKE_BUILD_TESTS` | `OFF` | Build the test suite (Google Test is required) |
| `CMAKE_BUILD_SANITIZE` | `OFF` | Build the tests under sanitizers |
| `CMAKE_BUILD_SAMPLES` | `OFF` | Build the samples of working with the library |
| `CMAKE_BUILD_BENCHMARKS` | `OFF` | Build the benchmark suite |
| `CMAKE_BENCHMARK_OPENSSL` | `ON` | Compare the benchmarks with the OpenSSL reference if it is present in the system |
| `CMAKE_CIPHER_COMPACT` | `OFF` | Build the block ciphers with small tables: for "Kuznyechik" 4 KB of memory instead of 128 KB at the price of a ninefold slowdown, for "Magma" 128 bytes instead of 4 KB at the price of a twofold slowdown |
| `CMAKE_CURVE_TABLES` | `ON` | Precompute at build time the multiples of the base points of the curves: signing goes **2.8 times** faster at the price of 1.23 MB in the binary. With the precomputation off, signing goes by the general multiplication by a point, and its result does not change. When cross-building on one machine for another the precomputation turns itself off |
| `CMAKE_CIPHER_CARRYLESS` | `OFF` | Use the machine instructions of carry-less multiplication: enable only where the machine has them |
| `CMAKE_BUILD_COVERAGE` | `ON` with `CMAKE_BUILD_TESTS` | Build the tests with coverage accounting: benchmarks on such a build are unfit |
| `CMAKE_BUILD_SANITIZE_LIST` | `address,undefined` | The list of sanitizers with `CMAKE_BUILD_SANITIZE` |

### For the consumer: find_package, add_subdirectory, shared library

The library is installed as a CMake package and is taken by the consumer in three ways; in all
three the target is one — `nts::nts`, and it carries along the header paths, the language standard,
the static build flag and the system libraries (threads, under Windows `bcrypt`):

```cmake
# 1. Installed package: cmake --install build --prefix /opt/nts
find_package(nts 1.0 CONFIG REQUIRED)      # -DCMAKE_PREFIX_PATH=/opt/nts
target_link_libraries(app PRIVATE nts::nts)

# 2. Submodule in the tree of the consumer: without installation
add_subdirectory(submodules/anyks-tls nts)
target_link_libraries(app PRIVATE nts::nts)
```

The installation puts the headers into `include/nts`, the library into `lib` (the shared one under
Windows — into `bin`), the description of the targets and the files `ntsConfig.cmake`, `ntsConfigVersion.cmake` into
`lib/cmake/nts`; version compatibility is within the major number. The third way — bypassing
CMake, with manual `-I` and `-l` — is described below.

The shared library is built with the option `CMAKE_SHARED_BUILD_LIB=ON`: `libnts.so.1` →
`libnts.so.1.0.0` under Linux and BSD, `libnts.1.dylib` under macOS, `nts.dll` under Windows;
the symbols are exported by the flag `ANTS_SHARED_LIBRARY_EXPORT` when building the
library itself and are imported at the consumer without any flags. The paths inside the project go
from `CMAKE_CURRENT_SOURCE_DIR` and the variable `ANTS_ROOT`, not from the root
`CMAKE_SOURCE_DIR`/`CMAKE_BINARY_DIR`: through `add_subdirectory` the root variables
point to the project of the consumer, and the project used to break on this before.

Verified 17.09.2026 on macOS: an installed static package, an installed shared
package (`@rpath/libnts.1.dylib`) and a submodule through `add_subdirectory` — three consumers
built and run.

### For the consumer of the static library

The headers distinguish three builds: the build of the shared library itself, of its
consumer, and the static one. A consumer taking `libnts.a` through the CMake target `nts`
gets the flag `ANTS_STATICLIB` by itself (it is declared at the target as `PUBLIC`). One who
attaches the library bypassing CMake must define `ANTS_STATICLIB` in his own build:
without it under Windows the symbols are declared as imported from a shared library, and
linking fails; on the other systems the flag affects only the visibility of the
symbols, and its absence stays silent.

### Machine instructions of cryptography

AES, SHA-256 and the multiplication in the GCM field go by the instructions of the extensions (ARMv8 Crypto, AES-NI,
PCLMULQDQ) if the machine where the binary is run has them: both branches are always
built, and the choice is made once at the first access by the detection of the processor
(`sys/machine.hpp`). The environment variable `ANTS_MACHINE=0` or the call
`machine::allow(false)` switch everything to the tables without a rebuild — that is how both
paths are compared on one machine. `ANTS_NO_MACHINE` in the compiler flags throws the instruction branch
out of the build entirely. The option `CMAKE_CIPHER_CARRYLESS` concerns MGM and is still
set at build time.

**Elbrus (e2k).** The lcc compiler declares `__SSE2__`…`__AVX2__` and translates the x86-64
instructions into the vector operations of Elbrus, but does not declare `__x86_64__`: the x86-64
branches of ChaCha20, AES and GCM are open under `__e2k__` too, and the machine flags are derived
from the generation of the instruction set fixed by the build (`__iset__`): from the fifth
generation - the vector operations and the byte shuffle (ChaCha20 goes four blocks at once), from
the sixth - the carry-less multiplication (GHASH). Elbrus has no AES and SHA instructions in any
generation: AES and the hashes go by tables. The emulation of AES-NI and PCLMULQDQ, which lcc
compiles silently, is not enabled by the flags - it is slower than the tables (see
`bench/COMPARISON.md`, section "Elbrus"). The memory of Elbrus is tagged: a word left over from an
uninitialised value crashes the process at the first operation on it - the library is not exposed
(it reads no foreign memory), while the memory measure in the tests reads the stack and the freed
blocks by words with the tag cleared (`__builtin_e2k_ld_64s_cleartag`).

### Tests

The test suite is built with the option `CMAKE_BUILD_TESTS=ON` and is run from the build directory through `ctest`:

```bash
mkdir build && cd build
cmake -DCMAKE_BUILD_TYPE=Debug -DCMAKE_BUILD_TESTS=ON ..
cmake --build . -j
ctest --output-on-failure
```

The tests are run only from the build directory: the paths to the sample files in them are relative. A single test or a subset of them is selected by the option `-R` by name, for example `ctest -R x509`; the test binaries lie in `tests/<module>/`.

### Documentation

The API documentation is built by Doxygen from the bilingual comments of the headers in `include/`: each block has a Russian and an English branch (`\~russian` / `\~english`). When Doxygen is found, the build defines the targets:

| Target | Purpose |
|---|---|
| `doc-ru` | Russian documentation by `Doxyfile.ru`, the result in `doc/ru/html` |
| `doc-en` | English documentation by `Doxyfile.en`, the result in `doc/en/html` |
| `doc` | Both language targets at once |

```bash
cmake --build . --target doc
```

The language configuration files inherit the common `Doxyfile` and override only the output language, the destination directory and the labels of the header. If there are no language files, the target `doc` builds the documentation by the common `Doxyfile` into `doc/html`.

## Test stands

The test suite has been run on eleven systems — everywhere 31 test suites out of 31 and not a single
build warning:

| System | Instruction set | Compiler |
|---|---|---|
| macOS 26 | ARM64 | Apple clang 21 |
| FreeBSD 14.1 and 15.1 | x86-64 | clang 18 and 19 |
| NetBSD 10.1 | x86-64 | g++ 10.5 |
| OpenBSD 7.9 | x86-64 | clang 19 |
| Debian 12 | x86-64 | g++ 12, glibc |
| Astra Linux 1.8 | x86-64 | g++ 12, glibc |
| Alpine 3.24 | x86-64 | g++ 15, musl |
| Solaris 11.4 | x86-64 | g++ 15 |
| OpenIndiana | x86-64 | g++ 14 |
| Windows 10 (MSYS2) | x86-64 | g++ 16.1, MinGW-w64 |
| Ubuntu | x86-64 | g++ 14, glibc |
| Fedora | x86-64 | g++ 16, glibc |
| openSUSE | x86-64 | g++ 15, glibc |
| Alt Linux | x86-64 | g++ 13, glibc |
| DragonFly 6.4 | x86-64 | g++ |
| Windows 11 (MSYS2) | ARM64 | clang, clangarm64 |
| Elbrus Linux 8.1 (Elbrus-8C2) | e2k v5 | lcc 1.27 |

**Astra Linux stands apart in this list** — and not only by its purpose. OpenSSL there
has the provider `gostprov` attached, carrying exactly our algorithms, and only on this stand
do the benchmarks compare **the same thing**, and not work of the same kind. The results are in
[bench/COMPARISON.md](bench/COMPARISON.md). The other systems answer the question of
portability, and this one — the question of purpose: the library is written for the domestic
cryptography and for the domestic certified system likewise. A failure on any other
stand is an annoyance; a failure here would mean that the work is unfit in substance.

This round should be walked in full, not selectively: each of the four portability defects
found during the first round was shown by **its own** system, and none of them was
visible on the workstation.

They must be walked **every time a change touches what the compiler is free to
interpret in its own way**. Forced inlining (`__ANTS_INLINE__`) is a change of
exactly that kind: GCC is entitled to answer it with a hard error if it cannot inline the
body, and there is no way at all to learn about this on a machine with clang. The round of 31.08.2026 checked
exactly that; the oldest compiler of the set, g++ 10.5 on NetBSD, accepted it without complaint.

## Benchmarks

The suite `bench` measures its own work and next to it — the work of the same kind at OpenSSL. The rules of
measurement lie in [bench/README.md](bench/README.md), the results of the comparison — in
[bench/COMPARISON.md](bench/COMPARISON.md).

In short: on the GOST algorithms against GOST (the reference is OpenSSL with the provider `gostprov`
on Astra) the ciphers go faster than the reference by 1.1…3.4 times, "Streebog" lags by 1.15 times, and
signing, verification and the VKO key exchange lag by exactly 2.0…2.4 times. Against the foreign
algorithms with the acceleration of the reference the gap in encryption reaches a hundredfold: there are
no machine instructions for GOST on any machine. The numbers and the work on the remaining lag are
recorded in [bench/COMPARISON.md](bench/COMPARISON.md) and are not repeated here, so as not
to go stale.

## Ticket lifetimes and replay

The library reads no clock: the moment by which the lifetimes of the resumption tickets are judged is supplied
to it by the call `moment` — at both the client and the server. A zero moment forbids judging the lifetimes
at all. A set one enables two rules of the standard: a ticket with an expired lifetime is not put
to use (section 4.6.1 of RFC 8446), and the ticket age declared by the client is matched against the one
observed by the server, and a discrepancy wider than ten seconds rejects the early data
without hindering the resumption itself (section 4.2.10).

The limit of the early data is declared by the ticket: the server sets it by the call `advance`,
the client does not exceed it on its own, and the excess of an offending client the server cuts off with the alert
"unexpected_message" (section 4.2.10). A ticket that declared no limit allows no early data
at all (section 4.6.1).

The guard against the replay of the early data (section 8) stays with the one who owns
the tickets: the second time the ticket is presented to a different connection, and a single connection
cannot judge about a replay. The simplest guard is to issue every ticket for a single
use, removing it from the store immediately upon resumption.

## Early data

A client resuming a connection with a ticket is entitled to send application data together with the
hello — before any answer of the server. It encrypts them with **the cipher suite of the ticket**,
for it knows no other at that moment.

Hence the three conditions under which the server accepts them (section 4.2.10 of RFC 8446):

* the **first** of the tickets offered by the client is recognized;
* the cipher suite of the connection **coincides** with the suite of that ticket;
* the application protocol of the connection **coincides** with the protocol of the connection that issued the ticket.

The last two conditions can be violated without forging anything: the cipher suite and the
application protocol are negotiated by the lists of the sides, and the ticket carries what was agreed
before. That is why the ticket stores both of them — the suite in the field `suite`, the protocol in the field `protocol`.

Rejected early data do not break the connection: the server skips their records, the number of
skips is limited, and the client sends the same data anew over the established connection.

There is also a fourth condition, not belonging to the ticket: the ticket age declared by the client
is matched against the observed one, and a discrepancy wider than ten seconds prevents the acceptance. That is how
a **replay** of the same early data gives itself away.

Both sides declare the acceptance by a separate flag — `accepted()`. It is separate not for
convenience: the rejected records the server skips **silently**, and by the emptiness of what was read
the refusal of acceptance is indistinguishable from no early data having been sent at all. And the acceptance must be known
because the protocol does not cut off a replay: having accepted early data, the one driving the connection
must reckon with the fact that they could have been supplied twice.

## Handshake by levels for QUIC

QUIC (RFC 9001) takes from TLS 1.3 only the handshake: it encrypts the records itself, with its own
keys by protection levels. For it both facades have a second **transport** —
`transport(context::transport_t::LEVELS)`, set before the connection is started. The default is
the records of the protocol, as before: the GOST branch and the classic one are not touched by it.

The structure of the transport by levels:

* **The input and the output are bare handshake messages** marked with a level, without record headers
  (the data of the CRYPTO stream, section 4.1.3 of RFC 9001): `push(level, data)` accepts, and
  `output(level)` and `consume(level, size)` give out. There are four levels — `INITIAL`, `EARLY`,
  `HANDSHAKE`, `APPLICATION`; the messages carry three of them, `EARLY` carries only keys.
  The level of a message coincides with the key epoch of the side: the hellos go at `INITIAL`,
  the output of the server and the answer of the client — at `HANDSHAKE`, the tickets — at `APPLICATION`. A message not
  at its own level aborts the connection with the error `LEVEL` and the alert `unexpected_message`
  (section 4.1.4), and the check is made on every message of the feed — the server hello changes the
  reading level in the middle of a feed.
* **The level secrets are released outside** — `secret(level, direction, result, size)`:
  `client_early_traffic_secret`, `{client,server}_handshake_traffic_secret` and
  `{client,server}_application_traffic_secret` of the length of the suite hash, as they are derived
  by the schedule. The key, the vector and the header protection (`quic key`, `quic iv`, `quic hp`) are derived by the
  consumer through `label`; the next generation of the application keys (`quic ku`, section 6)
  it derives from the current secret — that one is available after the handshake too. The secrets are released also
  with the transport by records: there they are the same that went into the record protection, and the test removes with them
  the protection from the records of the engine. The level `INITIAL` has no TLS secrets — QUIC derives its keys
  from the connection identifier itself.
* **Records, alerts, key update and the end of early data do not go at all.** The record protection in
  this transport is not set up; `write`, `read`, `update` and `close` answer with the error
  `STATE`; a received `KeyUpdate` or `EndOfEarlyData` aborts the connection (sections 6 and 8.3);
  the alert about the abort is put nowhere — its code is taken from `alert()` and goes as
  the QUIC closing message (section 4.8).
* **The transport parameters** (`quic_transport_parameters`, 0x0039, section 8.2): own ones are put
  by the call `parameters(...)` and go as they are — by the client into the hello, by the server into the
  encrypted extensions; the foreign ones are read by the call `parameters()`, and `acquired()` distinguishes
  the empty ones from the absent ones. By levels the extension is mandatory on both sides (the error
  `PARAMETERS`, the alert `missing_extension`), with the transport by records it is not allowed:
  received there, it is rejected (`unsupported_extension`).
* **The application protocol is mandatory** (section 8.1): a connection without a list of protocols is not
  started (`SETTINGS`), and without a common protocol it is aborted with the alert
  `no_application_protocol`.
* **Early data without their end**: enabled as before (`advance`), the server
  declares the acceptance (`accepted`), both sides know whether they are going right now
  (`earlying`), and the client — whether they are rejected (`rejected`), to reset their state and
  send them anew with the application keys. The early secret is released right after the client
  hello. A ticket accepted by levels carries with it the transport parameters of the server
  (`ticket.parameters`) — by them the client judges whether early data are allowed to a future connection.
* **The ticket into octets and back** — `context::encode` and `context::decode`: the record is
  self-contained, does not depend on the process and carries a version byte; truncation, corruption of the lengths,
  an extra tail and a foreign version are rejected entirely (`TICKET`).

The tests lie in `tests/quic`: a loopback handshake by levels over all suites, groups and
keys, a retry request, matching of the released secrets against the schedule on records and against RFC
8448, errors, the ticket codec, rejection of early data and memory exhaustion.

## Connection over DTLS 1.3 datagrams

DTLS 1.3 (RFC 9147) drives the same TLS 1.3 handshake over datagrams, which get lost,
duplicated and arrive out of order. For it both facades have a third **transport** —
`transport(context::transport_t::DATAGRAMS)`, set before the connection is started. The course of
the handshake, the key schedule, authentication, tickets and alerts are the same as with records;
the difference lies in the record layer, in the layout of the messages over the datagrams and in the
retransmission. There is still no input-output: the transport over UDP or SCTP SEQPACKET and the timer
stay with the one who drives the connection.

The structure: the record layer is `include/datagram`; everything by which the datagrams differ from a stream
(the key epochs with anti-replay windows, the flight with fragments and acknowledgements, the reassemblies of the received
messages, the deferred records, the timer, the stateless cookie) is the internal object
`src/internal/flight` (`flight_t`); the connection engine keeps only the hooks in `emit`, `push`,
`start`, `clear`, `output` and the version request; the classic path reads as before.

* **The input and the output are whole datagrams.** `push(data)` accepts exactly one received
  datagram, `output()` gives out exactly one ready datagram — the first from the queue, and
  `output`/`consume` must be called until empty: per one feed there may be several ready datagrams,
  every record of data or of an alert goes in its own datagram, none is
  lost. `consume(size)` removes the datagram entirely. The own size is set by `mtu(size)`
  (the default is 1200 by section 4.4, the lower threshold `DATAGRAM_MTU_LEAST` = 256, there is no upper
  limit — over SCTP the messages are longer than 1500); the received datagrams are not limited by the own
  size, sides with different sizes converge; up to `DATAGRAM_LONGEST` is accepted
  (the header and the record of the greatest length, 2^14 + 256), longer ones are discarded with `LENGTH`.
* **Records** (`include/datagram`): the plaintext header DTLSPlaintext with the key epoch and a
  48-bit number at the zero epoch (the version in it is not interpreted at all by section 4),
  the unified header DTLSCiphertext (0b001CSLEE) at the protected epochs — the connection composes
  it with a 16-bit number and a length, and accepts all four kinds; the connection identifier
  (bit C, RFC 9146) is not supported. The record number is encrypted with a mask by section 4.2.3:
  AES-ECB with the AES suites, the ChaCha20 keystream with 0x1303; the mask key is derived with the label `sn`. The full
  number is recovered by the low bits as the closest to the expected one (section 4.2.2).
  The GOST suites have no mask and are not offered over datagrams.
* **Key epochs** (section 4.2.1): the zero one — plaintext hellos, the second — the handshake,
  the third — application data, further one per every key update. The previous reading epoch
  is kept for the sake of late records; a record of the next epoch (after the zero one — the second), having outrun
  its keys, is deferred until they arrive (no more than `DATAGRAM_DEFERRED` = 8), and the peer
  is sent an empty acknowledgement (section 7.1), by which it repeats the flight at once.
  The first epoch (early data) is not set up: an offer of early data answers
  `SETTINGS`.
* **The anti-replay window** (section 4.5.1): a sliding window of `DATAGRAM_WINDOW` (64) records at
  every reading epoch; a replay and a record behind the window are discarded before the protection is removed.
* **Silent discards** (section 4.5.2): corruption, replay, a foreign epoch, a connection identifier,
  a plaintext record out of time, a distant fragment, data before the connection is established, a foreign cookie —
  all without alerts; `discarded()` gives the total count, `discarded(datagram::reason_t)` — by
  reasons: `LENGTH`, `TYPE`, `EPOCH`, `IDENTIFIER`, `REPLAY`, `DAMAGE`, `PLAIN`, `AHEAD`,
  `FRAMING`, `PREMATURE`, `COOKIE`.
* **The handshake** (section 5): the messages carry the framing with the message number, the offset and the
  length of the fragment; the outgoing ones are split to the size of the datagram, the incoming ones are reassembled from fragments with
  any overlap and in any order. The reassembly is bound to the key epoch: once the reading keys
  appear, plaintext fragments are accepted only as a repeat of an already parsed message, and a forged
  plaintext record does not break the protected handshake. There are no more than `DATAGRAM_AHEAD` (8) reassemblies, of
  `DATAGRAM_ASSEMBLY` (64 KB) each. The transcript is kept with the messages in the TLS framing.
* **Acknowledgements** (section 7): the message `ack` (type 26) with the record numbers in
  ascending order, at the highest epoch of a record; only the records whose fragments are parsed
  or put into a reassembly are acknowledged, what is discarded is not acknowledged. A flight answered with an own
  flight is acknowledged implicitly; a part of a flight, the client finishing and the post-handshake messages
  are acknowledged explicitly; the plaintext records (the server hello) are acknowledged in the protected
  epoch. In the plaintext epoch only an empty acknowledgement is accepted, and only with a flight waiting for the timer.
* **The timer and retransmission** (section 5.8): `timeout()` gives the deadline in milliseconds and
  zero when there is nothing to repeat; on expiry the driver calls `elapsed()` — the unacknowledged
  fragments are cut anew with new record numbers, the deadline doubles up to 60000; the doubled
  deadline is kept until a flight is acknowledged without repeats (section 5.8.2), and only then
  returns to 1000; on exhaustion of `DATAGRAM_ATTEMPTS` attempts — `TIMEOUT`. The own flight
  is repeated on a repeat by the peer of an already parsed message (section 5.8.1), and not on
  every record without progress. Application data and alerts know no retransmission.
* **The stateless cookie** (section 5.1): the server always answers the first hello with a
  retry request with a cookie. The cookie is the generation of the secret, the hash of the hello and an HMAC-SHA256
  by the secret of the generation over them and the address of the peer; the address is supplied by `address(view)` before
  the connection is started (without it `start` answers `SETTINGS`), its content is opaque and
  is matched byte by byte, the length is up to `DATAGRAM_ADDRESS` (256) bytes. At verification the hash of the hello
  is checked against the remembered one: a cookie of a foreign connection from the same address is rejected. The secret is set by
  `stamp(secret)` or is generated from entropy; `restamp()` opens the next generation,
  two are alive. A hello with an unfit cookie is discarded silently (deliberately, see
  CONFORMANCE).
* **The version** (section 5.3): the `legacy_version` of the hello and of the plaintext records is 0xFEFD, in
  `supported_versions` the only one is 0xFEFC. There is no `EndOfEarlyData` (section 5.6),
  `KeyUpdate` goes with an acknowledgement, the new writing epoch comes into force only by it, and a second update
  before the acknowledgement of the first answers `STATE` (section 8).

The tests lie in `tests/dtls`: the headers and the number mask with the vectors from FIPS 197 and RFC 8439,
a loopback handshake over three suites, two groups and three keys, losses, reorderings and
replays, fragmentation, the anti-replay window, key update, discards by reasons, forgery of a plaintext
record, the replay flag, deferral with an empty acknowledgement, a cookie of a foreign connection, the order of the
acknowledgement numbers, the wait deadline, different sizes of the sides, the output contract, errors, the timer
and memory exhaustion.

## Connection over DTLS 1.2 datagrams

DTLS 1.2 (RFC 6347) is the fourth combination of the same engine: the handshake of version 1.2 (ECDHE,
AEAD, extended master secret, everything as with TLS 1.2 over records) over the datagram transport
`flight_t`. There is no separate transport: `transport(DATAGRAMS)` drives both versions, and
they are selected by the bounds `versions(lowest, highest)` — 0x0303 corresponds to DTLS 1.2 (on the wire 0xFEFD),
0x0304 — to DTLS 1.3 (on the wire 0xFEFC), the default is 1.2…1.3. The scale of the versions is uniform on any transport:
the bounds are set and `version()` is given out with the TLS codes 0x0303/0x0304, and the wire ones 0xFEFD/0xFEFC are
shown outside nowhere (the numbering of the DTLS versions is inverted, and in the wire scale the range "from 1.2 to 1.3"
would look upside down). The client sends `legacy_version` 0xFEFD and `supported_versions`
[0xFEFC, 0xFEFD] by the bound and the suites (a version is offered only when its suites are present), the server
picks the highest common one; a foreign 1.2 server answers with ServerHello 0xFEFD without the version extension —
the connection goes DTLS 1.2, `version()` gives 0x0303. The bounds "only 1.3" reject 1.2
with the alert `protocol_version`, "only 1.2" are accepted by starting the connection; a header of
the client hello with a version that is not DTLS or older than 1.2 (0x0303, 0xFEFF, 0x0000) — `protocol_version`.

* **Records** (section 4.1): all records, the protected ones too, go with the plaintext header
  type(1) version(2) epoch(2) sequence(6) length(2); there is no unified header and no encryption of the
  number. The protection is by the 1.2 suites (RFC 5288, RFC 7905) with the epoch and the sequence number in
  the associated data (section 4.1.2.1) and the explicit part with AES-GCM; there are two epochs: the zero one until the change
  of the cipher spec, the first after it. The anti-replay window is the same `datagram::window_t` of 64
  records; corruption and replay are discarded silently (`DAMAGE`, `REPLAY`), a record of an unknown epoch —
  `EPOCH`, a foreign version in the header — `VERSION` (0xFEFF is allowed only to a plaintext handshake
  record: the first hello and the request of foreign nodes; at a protected record it is also
  `VERSION`, before the protection is removed). The header of version 1.2 is parsed and composed by the overloads
  `datagram::parse`/`build` with the flag `legacy`, next to the DTLS 1.3 header. A record of the first
  epoch that outran the change of the cipher spec is deferred until it — but not at a stateless server.
  The records of one datagram belong to one epoch.
* **The handshake** (section 4.2): the framing of the messages with the number, the offset and the length of the fragment is
  the same as with DTLS 1.3, the reassembly and the fragmentation to `mtu` are shared. The change of the cipher spec is
  a separate record (type 20), it goes into the flight and is repeated together with it, raising the epoch;
  the finishing goes in the first epoch. The order of the flights by section 4.2.4: CH → HVR → CH(cookie) →
  SH, Cert, SKE, [CR], SHD → [Cert], CKE, [CV], CCS, Fin → CCS, Fin. The transcript for
  Finished and CertificateVerify is kept with the messages in the DTLS framing without regard to fragmentation
  (section 4.2.6) and without HelloVerifyRequest and the first hello (section 4.2.1).
* **HelloVerifyRequest and the cookie** (section 4.2.1): a stateless server answers the first
  hello with a request with the version 0xFEFF (by the letter of section 4.2.1, the same at all six
  versions of openssl) and a cookie; the cookie is the same `stamp()`/`restamp()`/`address()` and the same
  generation secret as with DTLS 1.3, but short: the generation and an HMAC-SHA256 by the secret over the
  generation, the hash of the hello without the cookie and the address — 33 bytes, so that the request (61 bytes)
  is shorter than the smallest hello (69 bytes) and does not amplify a foreign flood; it is verified
  statelessly — the hash is computed anew over the repeated hello and is checked by the
  authentication tag, therefore the cookie is recognized also by a neighbouring server with the same secret and address.
  Until the address is confirmed the server spends no state and sends no alerts: a truncated,
  corrupted or otherwise unfit hello is discarded silently (`GREETING`), a hello
  is accepted only whole in one fragment (a fragmented one and foreign fragments — `GREETING`, as at
  `DTLSv1_listen`), records of the first epoch are not deferred (`EPOCH`), the window of the zero epoch is not
  kept; a hello without a cookie is answered with a request again (and a repeat of the first one — too), one with
  an unfit or foreign cookie is discarded silently (`COOKIE`); the flight of the request is dropped,
  there is no timer, the client hello is accepted with the number 0 or 1. Once the cookie is accepted, the record of the
  hello goes into the window of the zero epoch — its repeat is `REPLAY`. The client repeats the
  hello with the same random value and identifier, repeats a cookie of any length up to 255
  bytes verbatim, does not judge the version in the request, accepts the request always — also from a
  server without `-listen` (openssl always sends it); a repeated request (the server changed the cookie
  secret) is accepted with the new cookie and a hello with the number one again, but no more than three
  per handshake — the fourth is `unexpected_message`.
* **The timer and retransmission** (section 4.2.4): the same `timeout()`/`elapsed()`, 1000 ms with
  doubling up to 60000, `DATAGRAM_ATTEMPTS`, a repeat of the whole last flight; there are no acknowledgements
  — a flight is acknowledged only by the answering flight, a repeat by the peer of an already parsed
  message repeats the own flight; the last flight of the server (CCS, Fin) waits for no timer and
  is repeated only on a repeat of the client finishing, and is dropped by the first application
  data. A change of the cipher spec that outran the messages of its flight at losses or reordering
  waits for its turn at the server; at the client and in the other stages — `unexpected_message`.
* **Alerts**: a fatal alert as a record, `close_notify`, `no_renegotiation` as a warning
  on HelloRequest and a repeated hello after the connection, `EXHAUSTED` by the AES-GCM limit — as with
  TLS 1.2.
* **Not supported and rejected explicitly**: a post-handshake ticket (`issue()` — `STATE`;
  the RFC 5077 ticket goes inside the handshake, see "TLS 1.2: the second round"), SRTP (`use_srtp`
  is neither offered nor recognized), the RFC 9146 connection identifier, renegotiation, compression
  other than null, the GOST suites over datagrams.

Exchange with a foreign implementation: the system openssl 3.6 over UDP — our client against
`s_server -dtls1_2 -listen -Verify 1 -mtu 300` and our server against `s_client -dtls1_2 -mtu 300`
over six suites and three groups; the vectors of six versions of openssl (3.0.15…3.5.7) in
`tests/corpus/dtls12` — datagram by datagram with a key log file.

The tests lie in `tests/dtls12`: the acceptance contract, the vectors (server, client, the finishings by the
key log file), the loopback over six suites and three groups, a stateless server, a forged
client with an independent computation of the PRF over the transcript in the DTLS framing, losses, reorderings and replays,
fragmentation to 300, the anti-replay window and corruption, a change of the cipher spec out of turn, version
negotiation, exchange with openssl and memory exhaustion.

## TLS 1.2: the second round - CBC, plain RSA, PSK and RFC 5077 tickets

Decision of 06.09.2026 (see AWH-REQUIREMENTS): in TLS 1.2 and DTLS 1.2 the CBC suites,
the plain RSA exchange, pre-shared keys and session tickets are added. All in the same engine and the
same facades; the new suites in the registry `protect::suite_t` carry the exchange method `protect::exchange`
(`ECDHE`, `RSA`, `PSK`, `ECDHE_PSK`) and the hash of the authentication tag `protect::mac` (with CBC).

* **CBC** (section 6.2.3.2 of RFC 5246): an explicit initialization vector, HMAC-SHA1/SHA256 over the number,
  the header and the content, padding to the block with a check of all bytes; the order
  `encrypt_then_mac` (RFC 7366, extension 0x0016) is offered by the client and is confirmed by the
  server always when a CBC suite is in play; without it — MAC-then-encrypt with the removal of the protection in
  constant time relative to the length of the padding (Lucky13: masks, dummy hash compressions,
  extraction of the authentication tag by scanning a window — see CONFORMANCE, "Deliberate decisions of the second
  round"). The knobs of the facades: `etm()` — whether the order of RFC 7366 is negotiated (false with AEAD),
  `etm(true)` — require it with CBC (otherwise `handshake_failure`, the error `ETM`). Corruption of a
  record — `bad_record_mac`. There are no initialization vectors in the key_block (`protect::block` = 0).
* **Plain RSA** (section 7.4.7.1): without ServerKeyExchange, ClientKeyExchange carries the
  EncryptedPreMasterSecret by RSAES-PKCS1-v1_5 with the version from the header of the client hello;
  only with an RSA certificate. Protection against Bleichenbacher: on any decryption failure, a foreign
  length or a foreign version the premaster is replaced with a random one under a mask without branching, there is no answer
  to CKE, and the handshake fails only at the client finishing with `bad_record_mac`.
* **PSK** (RFC 4279, RFC 5489): the server — `psk(context::psk_t)` with the call `respond`
  "given identity → the key or a refusal" (many nodes with one context), an optional
  hint `identity` (psk_identity_hint) and the knob `disclose` (an unknown identifier —
  `unknown_psk_identity` (115) at once, or a random key and `bad_record_mac` at the finishing);
  the client — `identity` + `key` and an optional call `advise` "given the hint → identity +
  key" (a client with several identities picks the needed one). The identifier ≤ 128 bytes, the key
  ≤ 64 (otherwise `SETTINGS`); certificates and CertificateRequest do not go; the PSK suites
  are offered only with a set key or `advise` and are recognized only with a set
  `respond`; a server without a certificate is started with `respond`. A wrong key — `bad_record_mac`
  at the finishing (the record keys diverged; the same at openssl).
* **RFC 5077 tickets**: the extension `session_ticket` (0x0023) is empty at a client without a ticket,
  NewSessionTicket before the change of the cipher spec of the server, the ticket = key_name ‖ IV ‖ length ‖
  AES-128-CBC(state: the record version, the suite, the master secret, the EMS flag, the moment, the lifetime,
  the application protocol) ‖ HMAC-SHA256; the key of the tickets is `server::vault(secret)` (exposed, two
  live generations, neighbouring nodes with one secret recognize each other's tickets; an unset one
  is generated from entropy). There is no session cache — all the state is in the ticket. The external form is uniform with
  1.3: `tickets()` gives `context::ticket_t` (the body of the ticket in `identity`, the master secret in
  `secret`, the version is told by the suite), `context::encode`/`decode` carry it into another
  process, the client supplies `resume(ticket)`. The abbreviated handshake: ServerHello, [NST],
  CCS, the server Finished first, then the CCS and Finished of the client; the flag `shared()`; an unfit,
  foreign, expired ticket or a suite outside the offer — a full handshake without a refusal;
  resumption only with EMS. The client judges the abbreviated handshake by the first message after the
  server hello (openssl does not repeat the connection identifier). In DTLS 1.2 — the same
  with datagrams; a 1.2 flight is acknowledged only whole (the loss of the tail of the flight with the ticket
  is repeated by the timer).
* **Order and defaults**: the default offer of the client is ECDHE-AEAD, then ECDHE-CBC,
  the RSA exchange (GCM, then CBC), the PSK suites last and only with a key; the choice of the server is
  by the order of the server or of the client by `preference`, by the key of the certificate and the presence of `respond`.

Tests: `tests/tls12` (`Chained`, `Plain`, `Preshared`, `Tickets`, `Interop`,
`VectorSecond`, `StarvedSecond`), `tests/dtls12` (`Second`, `Interop`),
`tests/protect` (`Chaining`), `tests/cipher` (`AesChaining`, SP 800-38A F.2); the vectors of six
versions of openssl 3.0.15…3.5.7 in `tests/corpus/tls12x` (eleven scenarios: CBC with ETM and
without, PSK with a hint, ECDHE-PSK without certificates, a wrong PSK key, plain RSA with two
suites, a ticket with a full and a resumed handshake with `session.pem`).

## Fuzzer

The suite `tests/fuzzer` forges what nobody has promised: it distorts a real handshake
stream by a single bit and feeds random regions of bytes to the parsers.

Three rules are pinned by it:

* the parsing of the stream does not depend on its cutting into chunks — arrival one byte at a time
  differs in nothing from arrival in whole;
* the distortion of any byte of the stream, except the record version, establishes no connection —
  section 5.1 of RFC 8446 orders the version to be skipped without parsing, and everything else is covered by
  the handshake transcript and the record protection;
* an untransmitted region of bytes is untrusted data too, and every parser
  answers it with a refusal.

The seed of the fuzzer is fixed as a number: its finding is reproducible, whereas a random seed
would give a finding that can be neither reproduced nor pinned by a test.

## Stateless cookie

The server is entitled to keep no state between the hellos: it gives the retry request
with a cookie, and the client repeats it in the new hello verbatim (section 4.2.2
of RFC 8446).

Both sides can do this. The client stores the cookie and repeats it itself. The server gives it out with the call
`cookie(...)` and receives the repeated one with the call `cookie()`. **The content of the cookie is composed by
the consumer**: the connection carries it verbatim and parses nothing in it — what to put into the cookie
and how to judge the received one is known only by the one who composed it.

## Hostile peer

The guards of the own side are tested by a peer that does not intend to obey the protocol.
The hellos go in plaintext, and forging them right in the stream of bytes is quite direct — that is what
`forge` and `submit` of the suite `tests/context` are busy with.

Everything that goes after the server hello lies under the protection of the handshake, and a forgery in
the stream of bytes proves nothing there: a distorted record will not decrypt at all, and the
refusal will come not from the guard being tested. That is why the hostile server
`tests/adversary.hpp` drives its side itself — parses the client hello,
generates its ephemeral pair, derives the handshake keys for real and
composes with them a message distorted to the order of the test.

The mirror — the hostile client — is composed in the same way: it composes its hello,
derives the keys from the answer of the server and forges what already goes under their protection. Without it
there is nothing to test the guards of the server after the hello with: a forgery of the plaintext hello does not reach beyond
the answer of the server.

The hostile server can also play a **two-step**: first it asks for a repeat of the hello, and the answer
to the repeated hello it composes already distorted. That is how the guards are tested of what the
server is entitled to change between the request and the hello, and what it is not.

Every guard is pinned twice: by a test that touches it, and by muting its
condition, under which the same test must fail. A guard without the second experiment
proves nothing — it could well not work at all, with the refusal coming from a neighbour.

It drives the handshake exactly to the place where the guard under test stands: some distortions
need only the encrypted extensions, others need the certificate chain, and the
guards of the ticket — the whole handshake, together with the proof of key possession, the finishing
and the application data stage. A course of the handshake driven to the end is proven by itself:
with the lifetime guard muted the client accepts the ticket and drives the connection.

## Placement of an extension

Section 4.2 of RFC 8446 assigns every extension its own list of messages, and separates
**two** refusal alerts that are easy to confuse:

* an extension **known** to the side, but arriving **not in its message**, aborts the
  connection with the alert `illegal_parameter`;
* an extension that the side **did not ask for at all** — with the alert
  `unsupported_extension`.

These guards do not cover each other, and the second does not replace the first. The public part of the
exchange key, the protocol version, the pre-shared key, the modes of exchanging it, the stateless
cookie and the signature schemes are offered by the connection **every time** — hence a check against the
offered ones would let them through in the encrypted extensions of the server, where not one of them
has a place.

The placements of the recognized extensions are gathered in the table `PLACEMENTS` of the engine, and the guard stands at
**all five** messages of the server that carry extensions: the hello, the retry request,
the encrypted extensions, the authentication request and the resumption ticket.

Every guard is tested by its own distortion: `MISPLACED` sends in the encrypted extensions
what belongs to the client hello alone, `OUTPLACED` — in the ticket what has its place only
in the hello, `OFFPLACED` — in the authentication request the same, and `EXTENSION` sends what
is allowed to the encrypted extensions but was not offered by the connection.

The course of the check of the source text against the standard is kept in [CONFORMANCE.md](CONFORMANCE.md):
**every** verified requirement is recorded there, not only the discrepancies found.
The unverified and the verified-fit are indistinguishable from the outside, and without such a record the next
pass parses the same thing anew.

## Certificate chain compression

RFC 8879 "TLS Certificate Compression": the client declares with the hello the extension
`compress_certificate` (0x001B) with a list of algorithms, the server answers with the message
`CompressedCertificate` (type 25) instead of `Certificate` if a common algorithm was found; with the same
extension in the authentication request the server declares which compressed chain it will accept from the client.

The library **does not depend** on zlib, Brotli or Zstandard and does not drag them in: the
algorithms themselves are provided by the consumer with the description `context::codec_t` — the identifier by the registry
(zlib 1, Brotli 2, Zstandard 3, private 16384…65535) and two stateless calls,
`compress(source, result, context)` and `decompress(source, expected, result, context)`,
as function pointers with a pointer to the context of the consumer. The list is registered at the facade
`codecs(list, limit)` in the order of preference of the consumer and is not re-sorted;
an empty list turns the compression off entirely, and the handshake goes byte for byte as before (the GOST branch
and the classic one do not change).

The structure. The compression covers only the transport of the message: the body of `Certificate` is composed as
usual, is compressed with the first common algorithm **in the order of the declaring side** (the server goes by
the list of the client, the client — by the list of the authentication request; unknown values of the peer
are skipped silently) and goes with the fields `algorithm(2) uncompressed_length(3)
compressed_certificate_message<1..2^24-1>`. Into the transcript the compressed message goes **as is**,
the proof of key possession and the finishing are computed over it. On receipt `CompressedCertificate`
is decompressed with the call of the consumer and is fed into **the same** chain parsing as the uncompressed one —
one entry point, the same guards, the same alerts. The QUIC levels mode changes nothing: the message
goes at the same level as `Certificate`.

The guards of section 4 of RFC 8879: a side is entitled not to compress (a compression failure at the consumer, a chain
longer than 2^24-1 or the absence of a common algorithm send the usual `Certificate`); the length after
decompression must match `uncompressed_length`, a decompression failure and a length beyond the limit —
`bad_certificate`; an algorithm outside the declared ones — `illegal_parameter`; a compressed chain without its
declaration — `unexpected_message`; the extension in the encrypted extensions — `illegal_parameter`
(placement of an extension). The limit of the length after decompression is set by the consumer (the default is 64 KiB, zero
keeps the default, the top is the limit of the protocol): the memory for the chain by the word of the peer
is allocated only within these limits. A foreign exception from the call of the consumer is held by the connection:
on compression it counts as a compression failure, on decompression — as an unfit chain.

With which algorithm the chain of the peer came and with which the own one went is reported by
`compression(direction)`: reading — the received one, writing — the sent one, zero — uncompressed.

The suite `tests/compress` carries sample codecs of the consumer: zlib with "stored" blocks by
RFC 1950/1951 with the Adler-32 checksum (a stream without compression, but every real zlib parses it;
checked against zlib through `python3`) and the private algorithm 16384 with a reversible transformation. The exchange with
a real openssl 3.2+ goes in both directions: `s_server -cert_comp` sends us a pre-compressed
chain and accepts our compressed one, `s_client` accepts our compressed one and sends its own compressed by
our authentication request; skipped with a notice where openssl is built without zlib.

## OCSP certificate status and stapling of the response

RFC 6960 "Online Certificate Status Protocol", section 4.4.2.1 of RFC 8446 "OCSP Status and SCT
Extensions" and section 8 of RFC 6066: the client requests the status of the server certificate
with the extension `status_request` (0x0005) of the hello, the server answers with the same extension in
the record of the certificate chain with the body `CertificateStatus` — the type `ocsp` (1) and the record
`OCSPResponse` with a three-byte length. On a request of the client authentication the same extension goes
in `CertificateRequest`, and the client staples its response with the same chain record.

The core **does no input and output**: the response of the responder is obtained by the consumer itself and is fed as octets.
In aid of it the module `ocsp` composes the request (`ocsp::request(certificate, issuer, hash,
nonce) → DER`, byte for byte with `openssl ocsp -reqout`; the nonce by RFC 8954) and
extracts the address of the responder from the certificate (`ocsp::responder` — `id-ad-ocsp` from the
authority information access extension). The response is parsed by the class `ocsp::response_t` (`OCSPResponse` with
`BasicOCSPResponse`: the status, the responder by name or by key hash, `producedAt`, the responses per
certificate with `CertID`, the status `good`/`revoked`/`unknown`, `thisUpdate`/`nextUpdate` and
extensions, the signature, the attached certificates) without exceptions on the parsing path and with the error
`MEMORY` on memory exhaustion; the views look inside the supplied record, as with `x509`.
The verification `ocsp::verify(response, certificate, issuer, moment, tolerance, nonce, status)`: the status
`successful`, a response with the identifier of exactly this certificate (the hashes of the name and the key of the issuer by
the declared algorithm — SHA-1, SHA-2, "Streebog" — and the serial number), the signature of the responder
with the existing `x509::verify` (classic and GOST) and its right to answer (the issuer itself or an
attached certificate with `id-kp-OCSPSigning`, issued by the same issuer and valid at the
moment of verification — section 4.2.2.2 of RFC 6960), the periods `thisUpdate`/`nextUpdate` relative to the moment with
a tolerance in both directions (a zero moment does not judge the periods), the nonce if expected.
The status is not counted as a failure: a revoked certificate is a successfully verified response with the
status `REVOKED`, the decision about the connection is made by the caller.

At the facades. The client: `status(true)` — request the status, `status()` — the received response as
is (empty if the server did not answer), `verification(verify, tolerance, store)` — verification of the
received response by the connection against the certificate of the peer and its issuer (the issuer is looked up
by name among the links of the chain, at a self-signed one — itself, otherwise in the trusted store), the periods
are judged by the moment `moment()`; `certified()` — the status by the verified response. The server:
`status(DER, place)` — the response for stapling by the place of the certificate in the chain (zero — the leaf; responses
for the other links are allowed), `status(true)` — request the status of the client certificate
with the authentication request, `status()`, `verification`, `certified` — the same. The policy: the absence of a
response on a request is **not a failure** (section 4.4.2.1 of RFC 8446 allows the server not to answer),
the consumer learns about it from an empty `status()`; a response without a request is not sent and, having come,
is rejected as an unrequested extension (`unsupported_extension`); with the verification enabled
an unfit response (structure, signature, responder, a foreign identifier, period) and a revoked
certificate abort the connection with the alert `bad_certificate_status_response` (113); a certificate unknown
to the responder does not abort the connection — the status `UNKNOWN` is available to `certified()`.
Without the verification the response is only stored, and the judgement about it is made by the consumer with the module `ocsp`.
The QUIC levels mode changes nothing: the extension goes with `Certificate` at its level.

The suite `tests/ocsp`: responses and requests generated by a real `openssl ocsp` (the directory
`tests/corpus/ocsp`: good/revoked/unknown, a delegated responder by name and by key hash,
a responder without the purpose, a foreign responder, sha256, a short period, without `nextUpdate`, with
a nonce, RSA and self-signed keys of the set), a GOST response of own generation
(the signature GOST R 34.10-2012, the identifier by "Streebog"-256), composition of the request byte for byte
with `openssl ocsp -reqout` and live, loopback handshakes over records and over levels with stapling in
both directions (self-signed keys, a chain of three links, the issuer from the store, the GOST branch),
failures with the alert 113 and distortions on the way, exchange with a real openssl (`s_server -status_all
-status_file` → our client with verification, `s_client -status` → our server with stapling) and
memory exhaustion.

The request for an OCSP response from the client (section 4.4.2.1 of RFC 8446) goes as an EMPTY extension `status_request` in
CertificateRequest — that is how GnuTLS sends it; the client accepts also the former form with the structure
CertificateStatusRequest (as in the hello), and our server sends the RFC form. Found by the foreign reference
`gnutls-serv`, which asks for the client certificate by default.

## Hybrid public key encryption HPKE

RFC 9180 "Hybrid Public Key Encryption": the module `hpke` (`include/hpke/hpke.hpp`,
`src/hpke/hpke.cpp`) — a standalone primitive over `agreement` (X25519), `digest`
(HKDF on the streaming HMAC) and `cipher` (AES-GCM, ChaCha20-Poly1305); it takes nothing from the TLS engine
and is designated as the foundation of the encrypted client hello ECH of the second stage, but is fit also
for the consumer directly. The composition: KEM `DHKEM(X25519, HKDF-SHA256)` (0x0020); KDF `HKDF-SHA256`
(0x0001), `HKDF-SHA384` (0x0002), `HKDF-SHA512` (0x0003); AEAD `AES-128-GCM` (0x0001),
`AES-256-GCM` (0x0002), `ChaCha20-Poly1305` (0x0003) and `Export-only` (0xFFFF); all four
modes of section 5 — `BASE`, `PSK`, `AUTH`, `AUTH_PSK`.

The structure. A suite is the triple `hpke::suite_t(kem, kdf, aead)`; a KEM key pair is
`hpke::key_t`: `generate(kem)` from random bytes, `derive(kem, ikm)` by `DeriveKeyPair`
of section 7.1.3 (that is how the vectors are reproduced), `set(kem, secret)` from the bytes of the private
key, `secret()`/`point()` — views, `clear()` and the destructor wipe. The state of a connection is
`hpke::context_t` (the key, base_nonce, the sequence number, the exporter secret): at the sender
`seal(aad, text, place | buffer)`, at the recipient `open(aad, ciphertext, place |
buffer)`, at both `exporter(binding, place, length)`; the ciphertext carries the tag at the tail
(`+ TAG_SIZE`), the nonce is `base_nonce XOR seq`, the number grows after every
message and is read/reset by `sequence()` (section 9.7.1 — out-of-order messaging).
The setup: `hpke::sender(suite, mode, pkR, info, psk, authenticator, [ephemeral,] enc,
context)` and `hpke::recipient(suite, mode, own, enc, info, psk, pkS, context)`; the pre-shared
key is supplied as the pair `hpke::shared_t(key, identity)` and must correspond to the mode
(section 5.1: both non-empty in `PSK`/`AUTH_PSK`, both empty otherwise — else `PSK`), the key of the
sender — only in `AUTH`/`AUTH_PSK` (else `KEY`). KEM separately: `encapsulate` and
`decapsulate` (Encap/AuthEncap, Decap/AuthDecap of section 7.1.1). The single-shot wrappers
of section 6: `hpke::seal`/`hpke::open` (one message) and `hpke::dispatch`/`hpke::receive`
(SendExport/ReceiveExport).

The errors are codes `hpke::error_t` without exceptions: `SUITE`, `MODE`, `PSK`, `KEY`,
`ENCAPSULATION` (the length of `enc` or a zero shared value — section 7.1.4), `ENTROPY`,
`READY`, `AEAD` (an export-only suite, the wrong side of the state), `SEQUENCE`
(the numbers are exhausted), `OPEN` (the authentication did not match; the place for the plaintext is wiped),
`LENGTH` (an export outside `1…255·Nh`), `ARGUMENT`, `MEMORY`. The key path — the setup,
`seal`/`open` into a place, the export — allocates no memory at all (the HPKE labels are fed to the streaming
HMAC in parts); only the `vector` buffers of the wrappers allocate, the exhaustion is returned as `MEMORY`.
All the secrets — the shared values, the cipher key, the exporter secret, the private keys — are wiped
with `sys::wipe` on completion and on every failure.

The suite `tests/hpke` (`ctest -R hpke`, 9 tests): the vectors of appendix A of RFC 9180 (A.1
AES-128-GCM, A.2 ChaCha20-Poly1305, all four modes) and the full X25519 set from
`test-vectors.json` of the CFRG working group of the same edition — 32 vectors on HKDF-SHA256 and
HKDF-SHA512 over the four ciphers: the pairs from `ikm`, `enc`, `shared_secret`, the ciphertexts by
the numbers 0, 1, 2, 4, 255, 256 and three exports at both sides byte for byte; live messaging
over 12 suites and 4 modes (empty text, empty associated data, 1000 bytes); failures
(a foreign key of the recipient, a foreign key of the sender, a foreign PSK and identifier, a foreign mode with
the same key, corruption of every byte of the ciphertext, truncation, foreign `info`/`aad`, modes against
keys, exhaustion of the numbers at both sides, desynchronization of the numbers, the export lengths); the difference of the
secrets by suites (the identifier of the suite in the schedule); starvation of the single-shot wrappers and
a zero allocation budget on the key path. HKDF-SHA384 is not covered by an external vector (CFRG has none for X25519)
— only live messaging and the difference of the suites.

## GREASE by RFC 8701

One knob per connection: `client::Context::grease(bool)`, `server::Context::grease(bool)`,
the state — `grease()`. By default **off**, and the bytes of the messages are as before
(`GreaseTest.Disabled`). The behaviour when enabled is as at BoringSSL with
`SSL_CTX_set_grease_enabled(1)`.

The client (section 3.1 of RFC 8701) in the hello:

* a GREASE suite **first** in the list of suites;
* a GREASE extension **first** with an empty body and a second GREASE extension **last
  among the extensions of the consumer** with a body of one zero byte; the values of the two extensions
  differ; the pre-shared key (section 4.2.11 of RFC 8446) stays after the second one;
* a GREASE group **first** in the list of groups and a GREASE share **first** in the list of shares with
  a body of one byte (the group of the share is the same as in the list);
* a GREASE version **first** in the list of versions.

The values of the form `0x?A?A` are derived from a seed of six bytes, taken from entropy at the
start of the connection, one byte per place (the high four bits of the byte, the low ones `0xA`, the byte
repeated twice); coinciding high bits of the two extensions are separated. The seed lives until the
reset of the connection, and the repeated hello after the retry request carries **the same** values
in the same places (`GreaseTest.Retry`, `GreaseTest.Cookie`). One deviation by the letter of
RFC 8446 and by openssl: a retry request **with a key share** orders to send a share by the one
requested group only (section 4.2.8), and the GREASE share is removed together with the previous ones — otherwise
`openssl s_server` answers `illegal_parameter`; a request with a cookie alone (DTLS 1.3) does not touch the
shares, and the GREASE share stays. BoringSSL does the same.

The server (section 3.2 of RFC 8701) of version TLS 1.3: an empty GREASE extension **first** in the
request of the client authentication and an empty GREASE extension in the resumption ticket after
the early data limit (`GreaseTest.Server`). In version TLS 1.2 neither the RFC 5077 ticket
nor the authentication request carry extensions, and there is no insertion there. The peer's GREASE
values are never selected under any conditions — that is the former guard (`ClassicTest.Grease`).

The exchange with a real openssl with the knob enabled: TLS 1.3 directly and through a retry
request, `s_client` against our server with the authentication request and a ticket
(`GreaseTest.Openssl13`), TLS 1.2 (`GreaseTest.Openssl12`), DTLS 1.2 with a repeated
hello by the cookie (`GreaseTest.Dtls`). Entropy: at sixteen connections in a row the GREASE
suite must differ (`GreaseTest.Entropy`). Memory exhaustion — `GreaseTest.Starved`.

The point of override by a fingerprint profile: the decision on the insertion lives in one place of the engine —
`Engine::greased()`; the hello, the authentication request and the ticket ask it, and not the flag
directly. The profile (the places and the number of GREASE values from the snapshot) overrides the default in the same place,
and the knob `grease` does not affect the profile; the profile branch is a separate work.

## Hello fingerprints and application of a snapshot

The module `fingerprint` (`include/fingerprint/fingerprint.hpp`) is moved from AWH
(`awh::tls::Fingerprint`) and reworked for the library: without input-output, log, threads,
virtuality and exceptions on the parsing paths. The parsing of the hello is done by the module `hello`:
the fingerprint is taken from the same parsing that drives the handshake.

- `fingerprint::parse(view, profile)` parses a handshake record or a bare client hello
  message (over records and over datagrams, the layout is told by the record version;
  for a bare message over datagrams there is `parse(view, profile, true)`) into
  `profile_t`: the versions of the record and of the hello, the random value, the connection identifier, the
  cookie, the suites, the compression methods and the extensions in the wire order with raw bodies and
  parsed fields (names, protocols, groups, schemes, versions, point formats, PSK modes,
  compression algorithms, shares, key identifiers, SRTP profiles, numbers). GREASE values
  are marked with a flag, the unknown is stored as wire numbers.
- `fingerprint::imprint(profile, imprint)` computes JA3 and its MD5, JA4 by the FoxIO description
  (SHA-256; AWH computed MD5 — the discrepancy is fixed), JA4_r, JA4_o, PeetPrint and its MD5,
  the records of the random value and of the identifier, the negotiable version; `browser()` — a rough
  estimate "looks like a browser"; `print()` — a human-readable print of the profile.
- `fingerprint::parse(view, stream)` and `akamai(stream, text)` — the Akamai fingerprint by the beginning of an
  HTTP/2 stream (SETTINGS, WINDOW_UPDATE, PRIORITY, the order of the pseudo-headers of the first request).
- `fingerprint::dump`/`load` — a portable snapshot of a profile: the marker `ANTSFP`, the version, big-endian,
  fixed widths; the parsed fields are derived anew on loading.
  `store_t` — a bundle of profiles with identifiers and its own snapshot, without thread guarding.

Application of a snapshot "as is" — `client::profile(profile)` before `start()`: the engine composes the
hello by the profile, and not by its own defaults. The version of the hello, the length of the connection
identifier (fresh bytes of the same length), the compression methods, the order of the suites with GREASE in the recorded
places (own and fresh values, stable through a retry request), the order and composition of the
extensions verbatim, the bodies of the static extensions as recorded, the groups and versions with GREASE in
place, the key shares with fresh keys by the recorded groups, the padding by RFC 7685 by the
BoringSSL rule up to 512 bytes. The host name — from `name()` (without a name the extension does not go), the application
protocols and the compression algorithms — own if set, otherwise those of the profile; `status_request` of the profile
enables the status request; the encrypted client hello 0xFE0D goes as a GREASE value with a
random body of the recorded length; pre-shared keys — only with a ticket. The lists of
suites, groups, shares and schemes of the connection are narrowed to the known values of the profile in the order of the profile,
the version bounds are taken from the profile. Suites and groups unknown to the connection are offered as
recorded; should the server pick such a suite — the connection is aborted with the error `context::error_t::PROFILE`.
The share X25519MLKEM768 (0x11EC) goes as a fresh hybrid pair of 1216 bytes (the encapsulation key of
ML-KEM-768 and an X25519 point), as at Chrome; the shares of the other post-quantum groups are omitted, and the
groups stay in the list. The knob `grease` does not affect the profile; the profile is for the client only.

The server gives out the received hello as a parsed profile `server::profile(profile)` (from the
moment of receiving the hello) and as raw bytes `server::greeting()` for own parsing.
The criterion "as is" is pinned by tests: for a hello composed by a snapshot, JA3, JA4,
JA4_r, JA4_o and PeetPrint are equal to the snapshot (`ProfileTest.Loopback`, `Retry`, `Unknown`), the exchange with
`openssl s_server` by a profile passes (`ProfileTest.Openssl`), a forged choice of an
unknown suite is aborted with `PROFILE` (`ProfileTest.Alien`). The sample is `sample/fingerprint`.

## Encrypted client hello ECH

The module `ech` (`include/ech/ech.hpp`) implements RFC 9849 over `hpke`: the configurations
`ECHConfig` of version 0xFE0D and their list `ECHConfigList` (parsing with skipping of foreign versions
and composition byte for byte, checked against `bssl generate-ech`), the extension `encrypted_client_hello`
of the outer and inner kinds, encoding of the inner hello `EncodedClientHelloInner` with
compression `ech_outer_extensions` and padding by section 6.1.3, recovery by the rules of
section 7.1 (the connection identifier from the outer one, references in order, refusal on a repeat, absence and
a reference to ECH itself, a zero tail), the additional data `ClientHelloOuterAAD`, the HPKE binding
`"tls ech" || 0 || ECHConfig` and the acceptance confirmation of sections 7.2 and 7.2.1.

The client: `client::ech(ECHConfigList)` before `start()` — the first recognized configuration is taken
(KEM X25519, the HPKE suites of the module); the hello of the engine becomes the inner one (the ECH extension
of the inner kind, its own random value), the outer one carries the public name of the configuration and the
HPKE ciphertext; the leading run of identical extensions is taken out by `ech_outer_extensions`. With ECH
the connection is driven by version 1.3 alone (section 6.1); the resumption ticket is presented in the
inner hello with the binding over its truncated body, the outer one carries neither
`pre_shared_key` nor `early_data` (otherwise the identifier of the ticket would give the connection away to an observer no
worse than the name), the inner ECH extension goes before `pre_shared_key`; early data under
ECH are not offered (their keys are derived before the answer of the server, when it is unknown whether ECH is accepted).
Over DTLS 1.3 datagrams ECH works the same way: the inner and the outer hellos go
as a record with the stateless cookie field (RFC 9147), the inner one offers 0xFEFC, the cookie
from the retry request lives in both; the fragmentation of a long outer hello by MTU and its
reassembly at the server is the business of the flight, and the opening of ECH goes over the whole message
(`EchTest.Datagram`). There is no reference for ECH over datagrams: bssl and openssl do not drive it. The acceptance is judged by the confirmation in the server hello
or in the retry request in constant time (`shrouded()`); on acceptance the transcript is switched to the
inner hello, and the repeated hello after the retry request is encrypted with the same
HPKE state with an empty `enc` and is written into the transcript as the inner one. On the refusal of the server the handshake
is composed by the outer hello, the retry configurations from the encrypted extensions are put
into `retry()`, and upon establishment the connection is aborted with the alert `ech_required` and the error
`context::error_t::ECH` (section 6.1.7); the name for the verification of the certificate in that case is
`visible()` (the public one), on acceptance — `name()`; the verification by name is done by the consumer over
`peer()`. Without configurations, with `grease(true)` a GREASE ECH value goes (section 6.2): a random
identifier, the mandatory suite, a valid X25519 point and a random ciphertext of a plausible length.

The server: `server::ech(X25519 secret or empty, public name, identifier, maximum length
of the name)` before `start()` composes one configuration with the suites AES-128-GCM and ChaCha20-Poly1305 on
HKDF-SHA256; `server::ech()` gives the `ECHConfigList` for the DNS HTTPS record (the secret is not
given out). The outer hello is opened by the identifier, the suite and the key, the inner one is
recovered and verified (ECH of the inner kind, versions 1.3 only), the handshake goes by
it, the confirmation is written into the tail of the random value of the hello or into the extension of the
retry request; after the request the second hello is opened with the same state. A foreign or
unopenable ECH is rejected: the connection goes by the outer hello, the own configurations go as
`retry_configs`. `greeting()` and `profile()` of the server give out the outer hello as it went on the
wire. The check against BoringSSL (`bssl server`/`bssl client`, `bssl generate-ech`) in both directions,
including the retry request, — `EchTest.Boringssl2` (skipped with a notice without the tool; the path is
`ANTS_BSSL`). The sample is `sample/ech`.

Early data under ECH (section 6.1 of RFC 9849) go: `early_data` only in the inner
hello, the early keys from the transcript of ClientHelloInner; a server that declined ECH skips the
early data records (section 4.2.10 of RFC 8446), and the connection is broken by the client's ech_required.

## Code audit and the pinning suite `tests/audit`

The audit rounds are run until a zero finding: independent readers by zones, every finding with a
failure scenario and a probe, a fix, a pin. The results of round 1 (09.09.2026) are in CONFORMANCE.md, section
"Code audit, round 1": 27 findings, all fixed, the confirmed ones pinned by the suite `tests/audit`.
Out of the round came also contract changes: `trust::verify(chain, store, moment, role_t)` judges the purpose
of the leaf by the role of the peer (`SERVER` requires serverAuth, `CLIENT` — clientAuth, `ANY` — as the former
three-argument call); `x509::recognized()` checks the critical extensions also at the links of the chain and at
the delegated OCSP responder; `math::integer_t::power(…, bits)` exponentiates with the given width of the
exponent scan; two host_name records in server_name are rejected (section 3 of RFC 6066).
Round 3b (ciphers and mathematics) added `math::integer_t::residue(value, modulus)` — reduction by an
odd modulus in constant time with Montgomery passes; the RSA private operation takes the inverse
of the blinding number by Fermat's little theorem, not by Euclid, and reduces by the factors through
`residue` — there is no branching on the secret on the hot path, the cost of the private operation is about two of the former.
Round 4 (all zones) gave 26 findings and three contract changes: `trust::verify` rejects links with an
SHA-1/MD5 signature and RSA keys shorter than 2048 bits (`trust::error_t::WEAK`, RFC 9155 and SP 800-131A);
an OCSP response without `nextUpdate` is valid no longer than `ocsp::OCSP_STALE` (ten days); warnings
of the versions before 1.3 do not break the connection (`alert::grave` lists the descriptions that are always fatal). The pins are in
`tests/audit`, the table is in CONFORMANCE.md "Code audit, round 4".

## SHA-3 and SHAKE by FIPS 202

The module `digest::keccak_t` (`include/digest/sha3.hpp`): a sponge over Keccak-f[1600] with the
variants `sha3_t::SHA3_224/256/384/512` and the extendable-output functions
`SHAKE128/SHAKE256`. For the hashes the result is taken by `finish(result, size)` exactly at the length of the
variant; for SHAKE the result is squeezed by `squeeze(result, size)` in any chunks as many
times as desired, absorbing after squeezing is rejected. One call — `digest::sha3(type, data,
result, size)`; `length(type)` and `rate(type)` give the length of the result and the rate. The vectors of FIPS
202 (the empty message, "abc", 448 bits, a million "a", SHAKE128 at 200 bytes beyond
the rate) are pinned in `tests/digest/sha3.cpp`, checked against `openssl dgst`.

## Key exchange groups by curves and by a finite field

Besides `X25519`, `SECP256R1` and `SECP384R1` the connection drives the exchange by the groups previously
deferred. All of them are declared by the consumer per connection on a par with the others, the key share
goes as a record of section 4.2.8 of RFC 8446, and the choice of the group by the server obeys the rules of the version.

| Group | Number | Key share | Versions | Primitive |
|---|---|---|---|---|
| `X448` | 0x001E | the first coordinate of the point, 56 bytes (RFC 7748) | 1.3 and 1.2 | `agreement::x448` |
| `SECP521R1` | 0x0019 | uncompressed point `0x04‖X‖Y`, 133 bytes | 1.3 and 1.2 | the curve P-521, the signature `ecdsa_secp521r1_sha512` (0x0603) |
| `SECP256K1` | 0x0016 | uncompressed point, 65 bytes | **1.2 only** (RFC 8422) | the curve secp256k1 |
| `FFDHE2048…FFDHE8192` | 0x0100…0x0104 | public key of the modulus length, 256…1024 bytes | **1.3 only** | Diffie-Hellman in a finite field (RFC 7919) |

The curve `X448` goes by the Montgomery ladder in the general arithmetic by the modulus of the field
2^448 − 2^224 − 1; an all-zero shared value is rejected, as with X25519 (§6.2 of RFC 7748).
The curve `secp521r1` takes 521 bits, therefore the width of the number of the arithmetic is raised to
576; the signature `ecdsa_secp521r1_sha512` is declared with the scheme 0x0603 and is fit for both versions.
The curve `secp256k1` is not allowed in version 1.3 (RFC 8446 knows only five groups) and the server
in version 1.3 does not select it even with a share of the client — the connection goes by the next common group.

The finite field of RFC 7919, on the contrary, is fit only for version 1.3: the connection drives no DHE suites
of version 1.2. The moduli of the five groups are derived from the expansion of the number e and are checked against openssl 3.6.3;
the generator of all of them is two. The public key of the peer is checked by the bounds
`1 < Y < p − 1` (§4.2.8.1 of RFC 8446). There is deliberately no check of membership in the subgroup of order `q`
by the exponentiation `Y^q`: the moduli of RFC 7919 are safe primes, they have no small-order subgroups
except those cut off by the bounds, and the exponentiation to `q` of the modulus length would cost
about a second per every handshake at `ffdhe8192`. The private exponent is taken of the length of
double the strength of the group (§5.2 of RFC 7919), with the top bit in place, hence the number of
steps of the exponentiation does not give away its width. The largest modulus `ffdhe8192` raised the width of the
multi-precision integer to 8192.

Tests: `X448Test` (the vectors of §6.2 of RFC 7748, comparison with openssl), `FfdheTest` (the moduli against
openssl, the exchange, the bounds), `ParametersTest.Deferred` (P-521 and secp256k1: exchange and signature),
`GroupsTest` (the shares, the handshakes of both versions, the rules of the version, the P-521 signature and comparison with
openssl in both roles for every group).

## ML-KEM by FIPS 203

The module `agreement::mlkem` (`include/agreement/mlkem.hpp`): the sets `kem_t::MLKEM512/768/1024`,
the lengths `encapsulation`, `decapsulation`, `ciphertext`, the key check `validate` (section 7.2:
the length and the coefficients within the range of the modulus), the generation `generate(kem, seed d||z, key, secret)`
deterministically and on a random seed, `encapsulate(kem, key, message m, cipher, shared)` with the
message from outside and on a random one, `decapsulate(kem, secret, cipher, shared)` with the checks of
section 7.3 (the lengths, the hash of the key inside the decapsulation key) and the implicit rejection J(z||c) on an
unfit ciphertext in constant time. The decapsulation key is kept as the full record
dk_PKE||ek||H(ek)||z. All the memory is on the stack, the methods do not answer with exhaustion. The vectors are
the official ones (BoringSSL `mlkem768/1024_{keygen,encap,decap}_tests`, including the failing ones with
coefficients outside the modulus) and NIST (d/z separately; decapsulation of unfit ciphertexts with the
expected J(z||c)) in `tests/corpus/mlkem`; comparison with `openssl pkeyutl -encap/-decap`
(3.5+) in both directions.

## Hybrid group X25519MLKEM768 (0x11EC)

By draft-ietf-tls-ecdhe-mlkem: the share of the client is the ML-KEM-768 encapsulation key and an X25519 point
(1216 bytes), the share of the server is the ciphertext and a point (1120 bytes), the shared value is the
encapsulation secret and the shared value of the curve (64 bytes). The group `extension::group_t::X25519MLKEM768`
is the first in the list of defaults, and its share goes in every default hello together with the
X25519 share (since 23.09.2026; before that it stood between the GOST groups and X25519 with a single
share by the first group of the list); `extension::hybrid(group)` distinguishes it,
`extension::length(group)` gives the length of the client share. The server generates its share by
encapsulation to the share of the client (`Engine::encapsulating`), the client opens the ciphertext with its
key (`Engine::agree`); for version TLS 1.2 the hybrid is unfit on both sides. The retry request
works as with any group: after it one share of the hybrid goes. In fingerprint profiles the share
0x11EC is generated fresh, the order of the shares of the snapshot is kept. The negotiated group is given by
`client::group()` and `server::group()` next to `suite()` (NONE before the connection is established and at
resumption without an exchange) — that is how the consumer counts the connections made with a post-quantum
exchange. Pinned by `tests/hybrid`:
loopback, retry, the Chrome profile, starvation, comparison with `openssl s_server`/`s_client`
(3.5+) and `bssl server`/`bssl client`.

The NIST hybrids by the same draft: `SECP256R1MLKEM768` (0x11EB: a secp256r1 point ‖ ML-KEM-768) and
`SECP384R1MLKEM1024` (0x11ED: a secp384r1 point ‖ ML-KEM-1024) — with them the curve goes first, the shared
value is ss_ECDH ‖ ss_ML-KEM; they are not in the list of defaults, they are enabled through `groups()`/`shares()`
or by a profile; checked against openssl 3.5+ in both roles.

## BLAKE2b and BLAKE2s by RFC 7693

The module `digest::blake2_t` (`include/digest/blake2.hpp`): the variants `blake_t::BLAKE2B`
(64-bit words, block 128, result up to 64 bytes) and `BLAKE2S` (32 bits, block 64, result up to
32). The length of the result is set at the start `start(type, length, key)`, a key up to the maximum length of the
variant gives an authentication tag (section 3.3); one call `digest::blake2(type, key, data,
result, size)`. The vectors: appendices A and B of RFC 7693, the empty message and the keyed mode
checked against `openssl dgst`/`openssl mac`, the self-test of appendix E (both constants of the standard, matched also with hashlib), independence from
the chunking.

## Argon2 by RFC 9106

The module `digest::argon2` (`include/digest/argon2.hpp`): `argon_t::ARGON2D/ARGON2I/ARGON2ID`,
the parameters `argon_params_t{type, memory (KiB), passes, lanes}` (the default is Argon2id, 64 MiB,
three passes, four lanes — the second set of section 4), the call `argon2(params, password,
salt, secret, associated, result, size)`. Version 0x13; the lanes are computed sequentially,
the result does not depend on the number of threads; the memory for the matrix is taken for the duration of the call, on
exhaustion — a failure, not a crash. The parameters m/t/p, the salt and the tag are stored by the consumer (at AWH —
the container) and are read at verification. The vectors of section 5 of RFC 9106 (all three variants, with
a secret value and associated data) and comparison with `openssl kdf` on other parameters
(a long tag through H′, several lanes and passes). The PHC string: `digest::phc(text,
record)` and `phc(record, text)` — the parameters and the salt are mandatory, the output is optional (key
derivation has none); only `v=19`, the order `m,t,p`, base64 without padding. PBKDF2 remains for
PKCS #8 and RFC 7914. BLAKE2S256/BLAKE2B512 are also in `digest::hash_t`: HMAC and HKDF over them —
as in Noise and WireGuard.

## Raw stream cipher: XChaCha20 and AES-CTR without an authentication tag

`cipher::chacha_t::start(key, nonce, counter)` with a nonce of 24 bytes goes as XChaCha20
(draft-irtf-cfrg-xchacha): the HChaCha20 subkey (`chacha_t::hchacha`) from the first sixteen
bytes, the ChaCha20 nonce from four zeros and the last eight; `encrypt`/`decrypt`
apply the keystream to the data without a tag. `chachapoly_t::start` with a 24-byte nonce is
XChaCha20-Poly1305 in the IETF variant (as at libsodium). AES-CTR without GCM is `cipher::counter_t`
over `block_t`. The contract of the raw stream beyond the vectors: the output is indistinguishable from uniform under
any key, including a deliberately wrong one — pinned by `RawTest.Statistics` (monobit and χ²).
The purpose is containers where an authentication tag would be an oracle for password brute-forcing, and
integrity is carried out to a signature.

## SipHash-2-4

`digest::siphash(key16, data, result, 8|16)` and `siphash(key16, data, uint64_t &)`:
a keyed hash function for hash table keys and short tags (WireGuard); the vectors of the paper
by Aumasson and Bernstein, the 128-bit variant.

## Noise framework (revision 34)

The namespace `nts::noise`, the headers `include/noise/{noise,cipher,symmetric,handshake}.hpp`,
a core without input-output, a refusal by value instead of exceptions: in Noise all parsing is untrusted.

- The patterns are given as data — a table of tokens in `src/noise/patterns.cpp`: the one-way N, K, X,
  the fundamental NN, NK, NX, XN, XK, XX, KN, KK, KX, IN, IK, IX and the twenty-three deferred ones (§7.3);
  adding a pattern is a row of the table. Pre-shared keys — by the modifiers `psk0..psk3`
  in any combination (`Noise_XXpsk0+psk3_…`).
- The suites: `25519_{ChaChaPoly,AESGCM}_{SHA256,SHA512,BLAKE2s,BLAKE2b}` — all eight; at a hash
  length of 64 the cipher key is truncated to 32 octets, `ck` stays full. The curve 448 is not supported:
  a name with it is parsed, `dh` stays `NONE`.
- `noise::cipher_t` (CipherState): a key and a 64-bit counter, the value 2^64-1 is forbidden on
  encryption, decryption and setting; on a mismatched tag the counter does not grow; `rekey()`
  is exposed and does not reset the counter; raw access with an explicit counter `encrypt(n, …)/decrypt(n, …)` and
  the key output `key(out)` — for the pair tables and the replay window of WireGuard.
- `noise::symmetric_t` (SymmetricState): `start(name, suite)`, `key` (MixKey), `hash` (MixHash),
  `blend` (MixKeyAndHash with three outputs), `seal/open` (EncryptAndHash/DecryptAndHash, `h` is not
  touched on failure), `split`, `digest`. The HKDF of Noise = `digest::extract` with the salt `ck` and
  `digest::expand` with an empty info.
- `noise::handshake_t` (HandshakeState): `start(name, role, prologue)` or by enumerations;
  the keys `statics/ephemeral/remote/psks` strictly before the first message; `step()` — whose move it is;
  `write/read` over the buffers of the caller without memory allocations; the message limit is 65535 in whole;
  `split(one, two)` — from the initiator to the responder and back, at the one-way ones `two` has no key;
  `digest()` for channel binding, `peer()` — the static key of the peer. A received key of the
  peer is matched against the one set beforehand, on a mismatch a refusal. After any read failure
  the state is broken (`step() == NONE`). A small-order point at DH is a refusal (as at WireGuard).
- Acceptance: the corpora in the tree as they are — `tests/corpus/noise/flynn.txt` (flynn/noise v1.1.0,
  1920 vectors, psk in all positions, 1920 of 1920 taken), `flynn-hashes.txt` (the handshake
  hashes for all 1920, generated with the library that published the corpus),
  `cacophony.txt` (944; an own JSON reader in the test; 472 of 944 taken, exactly 448
  skipped with a printed count). The corpora diverge in the direction of the transport after the split: flynn
  alternates anew from the initiator and sends the backward move even at the one-way ones (with us `two` has no
  key — these 288 messages are skipped with a count, the forward move is matched), Cacophony continues by the
  message number. The core: HKDF against a manual computation by §4.3, the counter, rekey by definition,
  the limit 65535, failures, eight suites in both roles, the allocation budget at zero.

## PQNoise and WireGuard

- **WireGuard.** The handshake frames are assembled in the test `tests/noise/wireguard.cpp` over
  `Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s` with the prologue `WireGuard v1 zx2c4 Jason@zx2c4.com`: 148 and
  92 bytes, TAI64N, mac1 = BLAKE2s-128 with the key HASH("mac1----" ‖ Spub of the recipient), the transport with
  an explicit counter from the header through `cipher_t::encrypt(n, …)`. The reference
  `tests/corpus/noise/wireguard.txt` is generated by wireguard-go on fixed keys, ephemerals and
  timestamp: both frames match byte for byte, including mac1. The core knows nothing of the frames.
- **PQNoise** by the paper of Angel, Dowling, Hülsing, Schwabe, Weber (CCS 2022): the tokens `ekem` (a ciphertext
  to the ephemeral key of the recipient in plaintext, MixHash, MixKey) and `skem` (to the static one, through
  EncryptAndHash, MixKey), the thirteen patterns `pqN … pqIX` as the same rows of the table. The hybrid lives
  inside the KEM abstraction: `noise::kem_t::X25519MLKEM768` (composite, as in the TLS hybrid group:
  ek ‖ pk, ct ‖ pk_e, ss_mlkem ‖ ss_x25519) and `MLKEM768` as a row of the enumeration, not the default. The sizes are
  a property of the KEM (`kemlength(kem, part)`), not constants of the header. A name of the form
  `PQNoise_pqXX_X25519MLKEM768_ChaChaPoly_SHA256` is ours: there is no registry, a peer with which it would
  match does not exist. psk is not set up for PQNoise. The deterministic calls
  `kemgenerateDeterministic`, `encapsulateDeterministic`, `handshake_t::coinsDeterministic`
  are exposed for the sake of the corpora: a repeat of the seed or of the randomness is a total loss without a refusal.
- **Acceptance of PQNoise** (there is no foreign corpus and no live implementation in the world as of 08.09.2026: nyquist is without KEM; when a second implementation appears the frozen corpus is compared with it, and on a discrepancy the corpus is the more likely culprit): the integrity of the classics with the same
  numbers after the generalization of the table; the composite KEM against a separate computation of ML-KEM + X25519; both
  roles over 13 patterns × 2 KEMs × 8 suites; the maximum message lengths are computed beforehand
  (pqXX on the composite 1216 / 2368 / 2384 / 1152) and pinned; an own frozen corpus
  `tests/corpus/noise/pqnoise.txt` (52 records) — it proves invariance since the day of freezing, not
  correctness; regeneration only explicitly through `ANTS_NOISE_FREEZE`.

## Application-layer settings ALPS (draft-vvv-tls-alps)

The application-layer settings are negotiated by the TLS 1.3 handshake (and DTLS 1.3, and by levels under
QUIC) for the selected ALPN protocol: `client::settings(protocol, value)` and
`server::settings(protocol, value)` declare the settings per protocol (the protocol must be listed
in `protocols()`, otherwise `start()` answers `PROTOCOL`), `codepoint(type)` selects the codepoint —
`extension::type_t::SETTINGS` (0x44CD, the new one, the default as at BoringSSL) or `SETTINGS_OLD`
(0x4469, the former one); `settled()` says whether the settings are negotiated, `settings()` gives the settings
of the peer as they are, `codepoint()` — the codepoint of the connection. The wire is as at BoringSSL: the list of
protocols with settings in the client hello, the settings of the server in the encrypted extensions,
the answer of the client with an encrypted extensions message (type 8) right after the server finishing; with
accepted early data neither the extension nor the message goes — both sides inherit the
state from the ticket (`ticket_t::settled`, `settings`, `obtained`, the ticket record of version 3), and
changed settings allow neither to offer nor to accept early data. Divergent codepoints of the
sides leave the connection without settings silently: from outside this is told apart by `codepoint()`. A fingerprint
profile with the ALPS extension sets the codepoint of the profile itself and declares the protocols of the snapshot with
empty settings — that is how the Chrome snapshot is composed byte for byte, and the Google server gets the
message it expects. Version 1.2 does not carry the extension.

## Signed certificate timestamps SCT (RFC 6962)

`client::timestamps(true)` requests the timestamps with an empty extension `signed_certificate_timestamp`
(0x0012) of the hello; the answer in version 1.3 comes as an extension of the leaf record of the chain, in version
1.2 — as an extension of the server hello, and is given by `client::timestamps()` as recorded
(SignedCertificateTimestampList); `extension::timestamps(data, entries)` splits the list into
entries, `extension::timestamps(entries, out)` assembles it. `server::timestamps(list)` sets the
list for issuance on request — only with certificate authentication and not at resumption;
an unfit list (empty, an empty entry, a tail) is rejected by `start()` with the error `SETTINGS`, and
an unfit list of the peer — with the error `TIMESTAMPS` and the alert decode_error. A fingerprint profile
with the extension 0x0012 enables the request itself. The timestamps themselves (the CT logs, the signatures) the connection does not
interpret — as at BoringSSL, that is the business of the consumer.

## List of trusted authorities in the authentication request (RFC 8446 §4.2.4)

`server::authorities(names)` sets the list of the DER names of the certification authorities whose certificates
the server will accept from the client; the subject name of the certificate of an authority is given by
`x509::certificate_t::subjects().element`. The list goes with the authentication request: in version 1.3
as the extension `certificate_authorities` (0x002F), in version 1.2 as a field of the request (RFC 5246 §7.4.4);
without a list the request goes as before. The client gives the received list by `client::authorities()`
parsed into names — the choice of the certificate by it is up to the consumer. An unfit name (empty, not a
DER SEQUENCE) is rejected by `start()` with the error `SETTINGS`, an unfit list of the peer —
decode_error; `extension::authorities()` parses and assembles the list.

## Next protocol negotiation NPN (draft-agl-tls-nextprotoneg)

For the sake of fingerprint snapshots carrying the extension 0x3374, and of old servers: `client::negotiation(true)`
offers NPN with an empty extension in version 1.2 over a stream (not 1.3, not datagrams, not under ECH);
`server::negotiation(true)` declares `protocols()` in the server hello on request and only when
ALPN is not selected; the client picks the first of its `protocols()` declared by the server (without a common one —
the first of its own, without its own — the first declared, without anything — an empty name, as at BoringSSL), and sends
the message NextProtocol (type 67, zero padding of the length 32 − ((len + 2) mod 32), that is from 1 to 32 bytes) after the change of the cipher spec and before
the finishing; the result is in `protocol()`, `negotiated()` tells NPN from ALPN. The server waits for NextProtocol
at the negotiation, an arrival without it or twice — unexpected_message, unfit padding —
decode_error. The 1.2 ticket does not carry the protocol selected by NPN. `extension::negotiation()` parses
and assembles the list.

## Version DTLS 1.0 (RFC 4347 over TLS 1.1)

For the sake of old peers, by the statement of the task: `versions(0x0302, …)` at both sides over
datagrams allows DTLS 1.0 (on the wire 0xFEFF in the hellos and all records; in the TLS codes
the version is 0x0302, as DTLS1_VERSION ↔ TLS1_1_VERSION at BoringSSL). Version 1.1 is allowed only
the CBC suites with HMAC-SHA1 (ECDHE and RSA, PSK); the PRF is `digest::legacy` (P_MD5 ⊕ P_SHA1 by RFC 4346 §5),
the transcript hash is MD5 ‖ SHA-1, the signatures without schemes: RSA PKCS #1 v1.5 over MD5 ‖ SHA-1 without DigestInfo
(`x509::verify(digest, signature, key)`), ECDSA over SHA-1; the authentication request without a list of schemes,
the signature_algorithms of the client is not required. The extended master secret, renegotiation_info,
ec_point_formats, the RFC 5077 tickets and ETM are applicable as with 1.2. The choice of the version: the header 0xFEFD with
a list of versions including 0xFEFF at a client up to 1.2; a client clamped to 1.0 sends 0xFEFF without
the 1.2 list; a server capable of 1.2, driving 1.1, sets the guard DOWNGRD00, and a client that offered
1.2 aborts on it. TLS 1.0/1.1 over a stream are not started — `start()` answers `SETTINGS`.

## Sheltered storage of the key material

A key that the library keeps **between calls** does not lie in the ordinary heap: it lives in the
sheltered vault `sys::Vault` (`include/sys/vault.hpp`). The vault is one per process, takes
memory from the kernel directly (`mmap`/`VirtualAlloc`, bypassing any allocator), forbids it
swapping (`mlock`/`VirtualLock`), hides it from memory dumps (`MADV_DONTDUMP` on Linux,
`MADV_NOCORE` on FreeBSD and DragonFly), gives it wiped to the child after `fork` (`MADV_WIPEONFORK`,
`INHERIT_ZERO` or a `pthread_atfork` handler), and wipes a released piece at the moment of
return. Which of this has happened **in fact** is told by `Vault::shelter()`: three flags —
`wired` (swapping is forbidden), `hidden` (outside dumps), `forked` (wiped for the child). A lowering
by default is not a refusal but an honest report: the library works also where the forbidding of swapping is not
granted (DragonFly does not grant it to the unprivileged at all, macOS cannot hide from dumps). One to whom
the lowering is unacceptable calls `Vault::instance().demand(true)` — then a chunk without the forbidding of
swapping is not accepted, and a connection without a sheltered piece is unfit from birth: `state()` is
`FAILED`, `error()` is `MEMORY`, `start()` answers with a refusal, destruction is safe.

What lies in the vault: at a connection — the master secret of version 1.2, the keys of the handshake finishing,
the keys and vectors of the application data, the CBC authentication tag keys, the values of the directions by the protection
levels, the shared value of the exchange and the pre-shared key; at the key schedule
(`session::Secrets`) — its five values; at the ticket keeper — the keys of two generations. What
lives within a call (plaintext buffers, intermediate values on the stack) needs no sheltering and
is wiped by `sys::wipe`.

**The contract with the consumer.** Two public structures carry a key living between calls, and
their fields lie in the vault too: `context::ticket_t::secret` (the key of the resumption ticket) and
`context::psk_t::key` (the pre-shared key). Their type is `sys::bytes_t`, that is
`std::vector <uint8_t>` over the allocator of the vault. What it means:

- reading `data()`, `size()`, `empty()`, iteration — as with an ordinary set;
- assignment from an ordinary `vector <uint8_t>` does not compile (the allocators differ): put
  the bytes through `assign(begin, end)` or `assign(ptr, ptr + size)`;
- copying and moving a ticket as a whole (`ticket_t` into an own `vector <ticket_t>`, `resume(...)`)
  work as before — the copy of the key goes into the vault too;
- the calls of the consumer `psk_t::respond` and `psk_t::advise` still accept ordinary sets: the
  engine moves the issued key into the sheltered memory and wipes it in the heap itself;
- `Vault::instance().owns(secret.data())` confirms that the bytes lie in the vault.

This adds no dependencies: the vault is a part of A-NTS, the allocator of AWH is not needed by it, and
a foreign project without it gets the same behaviour. The vault does not contend with the allocator of AWH:
the chunks are taken from the kernel directly and are given to nobody; the only shared resource is the limit
`RLIMIT_MEMLOCK`, which is shared by everyone who locks memory, and each one reports its own honestly.

Pins: `tests/sys/vault.cpp` (taking, wiping on return, merging, growth, the report, the piece,
the allocator, the child, the demand), `tests/sys/demand.cpp` (a connection without a piece under the
demand — as a separate program), `tests/sys/trace.cpp` (the ticket key does not pass through the C++ heap
and does not remain on the stack), `tests/context` (`Sheltered`: the keys of the ticket and the PSK lie in the
vault, the contract `assign`). The samples are `sys/sys-vault`, `context/tls-connection`,
`tls12/tls12-psk`. The acceptance by a third-party walk of the memory on ten systems is in CONFORMANCE.md, round 17.

## Memory wiping: the mechanism and the classes

A secret that has served its purpose must not remain in memory: a foreign read of the memory, a
dump of the process or a reuse of a freed block would carry it out. The wiping is done by `sys::wipe`
(`include/sys/wipe.hpp`): an area by a pointer and a length, a byte vector and a string with emptying.
What and when the connection wipes is chosen by the consumer with the wiping classes.

**The mechanism.** A plain `memset` is unfit for wiping: by the as-if rule the compiler may drop a
write whose result nobody reads, and the wiping itself drops out with it. This is not a theory: the
inspection of the generated code of a function where a key on the stack serves its purpose showed
one and the same thing at clang 21, GCC 12, GCC 16 and lcc 1.27 - with a plain `memset` there is no
zeroing, and the bytes of the key remain on the stack; under the link-time optimization (`-flto`,
enabled at AWH on Windows) a test cannot catch this, since a program cannot observe whether a dead
write was dropped. Hence `sys::wipe` calls `memset` through a volatile function pointer (the way of
OpenSSL without assembly, `crypto/mem_clr.c`): the compiler has to read the pointer at every call and
may not know that `memset` stands behind it - and a compiler barrier stands after the call (the way of
BoringSSL and libsodium): an empty asm insertion with the pointer as an argument and the `memory`
mark, declaring the area read. Both keep the wiping at all three compilers and under `-flto`, and both
go at the full speed of `memset`. Before round 32 the wiping went by a word-wise volatile write - the
same guarantee, but a bandwidth of 35 GB/s on M4 and 6 on Elbrus against 140 and 43 of `memset`;
the assembly `OPENSSL_cleanse` of OpenSSL, by the way, is word-wise too. The system `memset_s` and
`explicit_bzero` are unfit as a replacement: the former exists only on macOS and FreeBSD, the latter
on FreeBSD, glibc and Elbrus but not on macOS and MinGW, and `SecureZeroMemory` of Windows is
byte-wise. The limit of every way: the register spills with the bytes of the key, which the compiler
makes around the calls, are wiped by nobody.

The guarantee is verified not by a test but by the inspection of the generated code: `tools/wipe/probe.sh`
builds five ways of wiping (a plain `memset`, `memset` with the barrier, the word-wise volatile write,
the same by four words, `memset` through the volatile pointer) with the given compiler and flags, prints
for each the number of instructions, of `memset` calls and of lines with zeroing in the function with the
key on the stack, and then the bandwidth of the wiping of 16 KiB. The plain `memset` has to show the
absence of the wiping, the others its presence. The header `wipe.hpp` carries this as a deliberate
decision: a plain `memset` in `sys::wipe` is forbidden.

**The wiping classes of a connection** - `context::wiping_t`, the knob `wiping(vector)` at
`client::Context` and `server::Context`, the getter `wiping()`:

| Class | What is wiped | When | Cost | Default |
|---|---|---|---|---|
| `SECRETS` | The secrets of the handshake and the keys on the paths of the connection: the ephemeral keys and shared values, the premaster, the PSK binders, the ticket keys, the intermediate values of the key derivation | As soon as there is nothing more to derive from them, and on the reset of the connection | One-off, small | Enabled |
| `PLAINTEXT` | The plaintext of the received records: the accumulator of the application data, the accumulator of the opened content of a record, the content of the opened DTLS datagrams | Between the records, after the hand-over by the `read` call and on the reset | Per record | Disabled |

The default is `SECRETS` only: the wiping of the secrets is one-off and cheap, the wiping of the
plaintext costs per record and protects only the window until the next record - the copy handed to the
consumer by the `read` call is out of reach, and its wiping is up to the consumer (`sys::wipe`). OpenSSL
has the same - `SSL_OP_CLEANSE_PLAINTEXT`, disabled by default; BoringSSL does not wipe the plaintext
of the records at all. An empty list disables the wipings of the connection: one who has no secrets in the
connection (measurements, public data) pays nothing. The classes do not concern what is always wiped by
the contract of its own object: the sheltered vault of the key material on the return of a piece, the value
objects (the ticket, the pre-shared key, the ephemeral pair) in the destructor, the primitives (the ciphers,
the hashes, the key schedule, the protection of records) on the reset of the state and in the temporary
buffers of a call. There are no bare `wipe` calls in the engine: the secrets go through `purge` by the
`SECRETS` class, the plaintext accumulators through `cleanse` by the `PLAINTEXT` class (deliberate
decision 20 of the engine header).

```cpp
client::context_t client;
// The default is the secrets only
client.wiping({context::wiping_t::SECRETS, context::wiping_t::PLAINTEXT}); // the received data is a secret
server::context_t server;
server.wiping({}); // no secrets at all: the connection wipes nothing
```

Pins: `tests/sys/wipe.cpp` (the bounds, empty arguments, containers with emptying, a large unaligned
area), `tests/context` (`Wiping`: the default, the return of the list, a connection under every list),
`tests/audit` (`PlaintextCleansing`: the accumulators of the engine are zero only with the `PLAINTEXT`
class, without it they hold the received bytes; `SecretsViaPurge`: no bare `wipe` in the engine). The
samples are `sys/sys-wipe`, `context/tls-connection`. The inspection of the generated code on five
stands, the bandwidth and the cost on the record path are in CONFORMANCE.md, round 32.

## Log sink

The library keeps no log — it has only a **sink** (`include/sys/log.hpp`): one
function `void (*)(level, const char * text, void * context)`, which the consumer sets by the
call `sys::log::sink(fn, context)` at the start of the process, before any connections are started. Until the sink is
set, the library stays silent, and a message costs one comparison with nullptr — the string is
not built at all. The levels `INFO`, `WARNING`, `CRITICAL` coincide with the kinds of messages of the AWH
log, therefore the adapter at AWH is one function, translating the level into `log::flag_t` and calling
the static function of its log; no object, no lifetime, no AWH headers inside
A-NTS. A foreign project without a log sets nothing.

Deliberately **not** done: weak symbols (unreliable in static archives and under MinGW) and
build definitions with foreign headers (they break the absence of dependencies). Attachment only
at run time — that is why it "attaches itself" when a log is present, and does not break the API
when there is none.

What goes into the sink: the failures that otherwise reach the consumer only as a code — the abort of a connection
with an alert (`CRITICAL`: the side, the error code, the name of the alert), the lowering of the sheltering of the vault
(`WARNING`: what exactly did not happen), the refusal of the vault under the demand (`CRITICAL`),
the exhaustion of retries over datagrams (`WARNING`). Secrets — keys, random values, bodies of
records — never go into the log; that is the rule of the header of the module, and the pin `LogTest.Abort` keeps
the abort line short and without them. The `printf`-style line is built in a buffer on the stack of 512
bytes, a longer one is truncated.

Pins: `tests/sys/log.cpp` — silent without a sink, the sink gets the level, the string and the context,
truncation, removal of the sink, the abort of a connection into the sink, the lowering and the refusal of the vault into the sink. The sample
`sys/sys-log` shows the adapter to a static log of the consumer, as at AWH.

## Development rules

* Implementation only in `.cpp`; in the header files — declarations and forwarders
  for inlining.
* Internal modules are included only from `.cpp` and are not taken out into the external view
  of the library.
* Access to the fields always through `this->`.
* On the path of parsing untrusted data exceptions are not used: a refusal
  is returned by value.
* Inside the cryptographic primitives exceptions, templates and
  virtuality are forbidden — everything that produces branching on a secret value.

## Record length limits record_size_limit and max_fragment_length (RFC 8449, section 4 of RFC 6066)

Fingerprint profiles carry `record_size_limit` (0x001C, that is how Firefox sends it: 16385) and
`max_fragment_length` (0x0001), and the promise is kept: the client offers them only by a profile with the raw
body, and the answer of the server is applied — the received limit cuts the SENDING (`emit()` cuts every record:
handshake, alerts, data; in 1.3 the limit is counted together with the content type octet, therefore the payload
is one shorter — section 4 of RFC 8449), the own offered and confirmed limit guards
the RECEIVING (a longer record — record_overflow). A value below 64, a length code not 1…4 or not equal to the
offered one, both answers at once (section 5 of RFC 8449) — illegal_parameter. The server answers every
client: to `record_size_limit` — with its protocol limit (16384, in 1.3 — 16385) and cuts the sending
to the limit of the client; to `max_fragment_length` — with the same code, the length binds both sides; to both
at once — only `record_size_limit`. The server binds the receiving only with the sending of the answer: the second
hello after HelloRetryRequest is not limited in length. At a client of version 1.2 the limit on receiving
comes into force from the parsing of the flight of the server (the hello and the chain go in one flight under the limit of the
protocol), further — the negotiated one. Over datagrams the limits are not negotiated: the length of the record is dictated by
the MTU of the flight. The result outside: `ceiling()` — the sending limit, `threshold()` — the receiving limit at the client and
the server. The class of the change is a defect fix: an extension offered by a profile and not obeyed
broke the connection against a strict server (GnuTLS, NSS, wolfSSL, rustls).

## Heartbeat (RFC 6520): tolerance without an answer

Fingerprint profiles of old clients carry the extension `heartbeat` (0x000F); the hello goes byte for
byte, and on receiving, the engine with the offered extension DROPS a record of type 24 silently and does NOT answer with
HeartbeatResponse — a deliberate deviation from RFC 6520: an answer would give the peer an amplifier and
a keep-alive (the Heartbleed family), and a fingerprint is the octets of the hello, not the behaviour on
receiving. Without the offered extension a record of type 24 is unexpected_message, as before. The server behaves
the same way by the offer of the client.

The condition of reconsideration is lifted by the statement of the task: to a consumer who really needs heartbeat,
an explicit call `heartbeat(payload)` (`client`/`server`) is open. It sends HeartbeatRequest over an
established connection of version 1.2 (or DTLS 1.2), only with the offered extension and the permission of the
peer `peer_allowed_to_send`, one at a time until an answer (§4 of RFC 6520); the payload is returned word for
word, the number of received answers is available by `pulses()`. To an **incoming** HeartbeatRequest the engine answers with
HeartbeatResponse with the same payload and its own padding, but only over an established connection — it remains
deliberate that there is no automatic answer on receiving before the connection is established (the Heartbleed amplifier
lived exactly there). A message outside an established connection, shorter than the header or with a payload length beyond
the bound of the record is dropped silently. Over datagrams unknown record types are dropped by the flight anyway,
and a DTLS 1.2 heartbeat record is parsed by the same path.

## Samples

The samples of working with the library lie in the directory `sample` and are built with the option `CMAKE_BUILD_SAMPLES`:

```bash
cmake .. -DCMAKE_BUILD_SAMPLES=ON && make
```

The built samples are put into `samples` of the build directory:

| Sample | What it shows |
|---|---|
| `digest/digest-streebog` | Hashing streamed and at once, both lengths and both records of the hash, the HMAC authentication tag, derived key generation and the pseudo-random sequence |
| `cipher/cipher-kuznyechik` | Transformation of one block, counter-mode keystream encryption, the OMAC1 authentication tag and authenticated encryption in the MGM mode |
| `sign/sign-gost` | Setting up a curve by the identifier of the parameter set, generation of a key pair by selection, signing and verification of the signature |
| `record/record-layer` | Cutting data into records and assembling them back from chunks of arbitrary length |
| `record/record-protect` | Applying and removing the protection of TLS 1.3 records, padding against the analysis of the exchange by its type, rejection of a substitution |
| `handshake/handshake-hello` | Composition of a client hello with extensions and parsing it back |
| `handshake/handshake-message` | Signing the proof of key possession, verification of the signature by the opposite side and finishing of the handshake |
| `session/session-state` | The handshake transcript, passing through the key schedule and transfer of a record with the derived keys |
| `handshake/handshake-flow` | A full handshake as a whole: from the hellos to the application data, with key switching |
| `agreement/agreement-ecdhe` | Ephemeral key exchange: the key pairs of the sides and convergence of the shared value |
| `context/tls-connection` | A connection as a whole: handshake, key update, ticket, resumption and early data; the wiping classes `wiping` and the wiping of the copy by the consumer |
| `trust/trust-chain` | Trust in a chain: the connection accepts it, and the decision is made by the trusted store |
| `pem/pem-storage` | Writing the authentication of a side into text and raising it from there back into a connection |
| `protocol/alpn-choice` | Choice of the application protocol by the server and declaration of the host name by the client |
| `alert/alert-notice` | Alerts: transfer as a record of the record layer and the decision on continuing the connection |
| `tls12/tls12-handshake` | Version TLS 1.2: the bounds `versions`, the order of suite selection `preference`, data exchange, the mandatory extended master secret, the RFC 5077 session ticket as octets through `vault`/`resume`/`shared` |
| `tls12/tls12-psk` | Pre-shared key RFC 4279/5489: `respond` by identifier and the hint at the server, `advise` at the client, the knob `disclose`, a wrong key, the length limits |
| `tls12/tls12-cbc` | CBC suites with the RFC 7366 order: `etm()` negotiated by the sides, the requirement `etm(true)` against a foreign client without the extension, the MAC-then-encrypt order without the requirement |
| `dtls/dtls-datagrams` | DTLS 1.3 and DTLS 1.2 over datagrams: `transport(DATAGRAMS)`, `mtu`, `address`/`stamp`/`restamp`, a retry request with a cookie, `timeout`/`elapsed` with a lost datagram, `discarded(reason)`, choice of the version by the bounds |
| `quic/quic-levels` | Handshake by levels for QUIC: `protocols`, `parameters`, `push`/`output`/`consume` by levels, the level `secret` in both directions, refusal of a feed with the wrong transport |
| `ocsp/ocsp-stapling` | OCSP certificate status: stapling `status(DER)` by the server, `status(true)`+`verification`+`moment`+`certified()` at the client, a revoked certificate and the alert 113, `ocsp::request`/`ocsp::responder` |
| `compress/compress-chain` | Chain compression RFC 8879: its own back-reference codec (`sample/compress/lz77.hpp`) under a private identifier, the system zlib if present, `codecs`/`compression` and the saving of the flight |
| `keys/keys-codec` | Key codecs: generation of ECDSA P-256 and Ed25519, PKCS #8 and SubjectPublicKeyInfo, PEM open and password-encrypted, parsing back and signing with the parsed key |
| `cipher/cipher-stream` | Streaming encryption `cipher::stream_t` in chunks of any length (GCM and keystream mode), ChaCha20-Poly1305 at once and streamed, wiping of secrets with `sys::wipe` |
| `digest/digest-sha3` | Hashes of FIPS 202 and RFC 7693: the four widths of SHA-3, SHAKE with the output length per call, streamed hashing with `hasher_t`, BLAKE2b/BLAKE2s with and without a key, SipHash-2-4 at 64 and 128 bits |
| `digest/digest-argon2` | Argon2id by RFC 9106: a key from a password with 64 MiB of memory, the PHC record for the store `phc()`, verification of a right and a wrong password by the parsed record |
| `agreement/agreement-mlkem` | ML-KEM-768 by FIPS 203: a pair, `encapsulate`/`decapsulate`, implicit rejection of a corrupted ciphertext and the hybrid X25519MLKEM768 as in TLS |
| `hpke/hpke-hpke` | HPKE by RFC 9180: `seal`/`open` with one call, refusal on corruption, a stream of messages through `sender`/`recipient` and contexts, the PSK mode |
| `noise/noise-noise` | The Noise framework: the XX handshake with message exchange, `split` into two cipher states and data transfer, matching of the handshake hashes, the same with the pattern pqXX on X25519MLKEM768 |
| `cipher/stream-raw` | A raw stream cipher without an authentication tag: XChaCha20 with a 24-byte nonce, garbage instead of a refusal on a wrong key (no brute-force oracle), HChaCha20, AES-256-CTR through `counter_t` |
| `embed/embed-key` | A key embedded into the image: `embed::key` from the material in sheltered memory with the binding of the hash of the image region and the version (a change of the version and a substitution of the region give a different key), `embed::secret` from a password by Argon2id |
| `sys/sys-vault` | The sheltered vault of secrets: the piece `sys::Secret` with a single owner and moving, wiping on return, the set `sys::bytes_t` over the vault, the report `shelter()` about what has happened in fact, the demand `demand()` |
| `sys/sys-log` | The log sink: without a sink the library stays silent, the adapter with one function to a static log of the consumer (as at AWH), the abort of a connection and the lowering of the sheltering in the log, removal of the sink |
| `sys/sys-wipe` | Wiping of the memory with secrets: an area on the stack with exact bounds, a byte vector and a string with emptying, the bandwidth of wiping 16 KiB, the wiping classes of a connection `wiping` (the default, with the plaintext, without wipings) and the copy of the consumer |

The samples of version 1.2, datagrams, levels, OCSP stapling and compression read the keys, certificates
and the responses of the responder from the set `tests/corpus` (the path is passed by the build): generating
ECDSA and RSA certificates on the spot is not a sample's business. Every sample ends with the code 0
on success and a non-zero one on failure, therefore it is fit as a test too.
