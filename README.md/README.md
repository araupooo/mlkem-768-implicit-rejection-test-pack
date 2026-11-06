# ML-KEM-768 Implicit-Rejection Test Pack

A runnable behavioral test pack for ML-KEM-768 decapsulation implicit
rejection, checked against NIST FIPS 203.

## What it checks

Using an established ML-KEM-768 implementation, the harness
(`harness/mlkem_implicit_rejection.py`) verifies, over 25 fresh key pairs:

1. **Valid shared-secret agreement** — encapsulation followed by
   decapsulation of the unmodified ciphertext produces the same 32-byte
   shared secret.
2. **Modified-ciphertext rejection** — decapsulating a ciphertext with one
   flipped byte (first byte and last byte) returns a value that differs
   from the valid shared secret, as required by the implicit-rejection
   rule of FIPS 203, Section 6.3, Algorithm 18.
3. **Repeated-decapsulation determinism** — decapsulating the same
   modified ciphertext three times returns the same value every time.
4. **Second distinct modification** — a ciphertext modified at a different
   byte position yields a value that differs from the valid shared secret
   and from the first modification's value.
5. **Sizes** against FIPS 203, Section 8, Table 3: encapsulation key
   1184 bytes, ciphertext 1088 bytes, shared secret 32 bytes. The private
   key is serialized by this library as the 64-byte seed (d || z) of
   FIPS 203, Section 7.1, from which the 2400-byte decapsulation key is
   derived internally.
6. **Ciphertext type check** — decapsulation of a wrong-length ciphertext
   is refused with `ValueError` (cf. FIPS 203, Section 7.3).

## Implementation under test

- **Library:** pyca/cryptography **50.0.2** (pinned in `requirements.txt`),
  ML-KEM API `cryptography.hazmat.primitives.asymmetric.mlkem`, backed by
  OpenSSL. The ML-KEM API was added in cryptography 47.0.0.
- **Source:** <https://github.com/pyca/cryptography>
- **API documentation:**
  <https://cryptography.io/en/latest/hazmat/primitives/asymmetric/mlkem/>

## How to run

```sh
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/python3 harness/mlkem_implicit_rejection.py
```

The harness prints the environment (Python version, platform,
`cryptography` version, OpenSSL version), SHA-256 digests of the shared
secrets of the first trial as comparison evidence, a results table and a
final `ALL CHECKS PASSED` / `FAILURES PRESENT` line. The exit code is 0
only when every check passes.

The same commands run in continuous integration on every push to `main`
(see `.github/workflows/run-harness.yml`: `ubuntu-24.04`, Python 3.12).

## Primary source

NIST FIPS 203, "Module-Lattice-Based Key-Encapsulation Mechanism
Standard", August 2024, DOI 10.6028/NIST.FIPS.203:
<https://doi.org/10.6028/NIST.FIPS.203>

## Results and limitations

The full evidence pack, including verbatim FIPS 203 citations and the
unedited run output, is
`evidence/ML-KEM-768-Implicit-Rejection-Test-Pack.md`.

These are behavioral checks on this one implementation. They show that the
implementation rejects modified ciphertexts by returning a different,
deterministic value, as FIPS 203 requires. They do not prove full
standards compliance: they do not run NIST known-answer tests
(NIST CAVP / ACVP ML-KEM test vectors), do not verify the internal
re-encryption comparison, and do not test side-channel or
constant-time properties.
