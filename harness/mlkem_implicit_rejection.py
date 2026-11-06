#!/usr/bin/env python3
"""Behavioral test harness: ML-KEM-768 decapsulation implicit rejection.

This harness checks observable behavior of an established ML-KEM-768
implementation against the requirements of FIPS 203. It does not implement
any ML-KEM algorithm itself, and it does not claim standards compliance.

Checks
------
1. Valid shared-secret agreement: encapsulation and decapsulation of an
   unmodified ciphertext produce the same 32-byte shared secret.
2. Modified-ciphertext rejection: decapsulating a ciphertext with one
   flipped byte returns a value that differs from the valid shared secret.
3. Repeated-decapsulation determinism: decapsulating the same modified
   ciphertext repeatedly returns the same value every time.
4. Second distinct modification: a ciphertext modified at a different byte
   position also yields a value that differs from the valid shared secret
   and from the first modification's value.
5. Sizes against FIPS 203 Table 3 (Section 8): encapsulation key 1184
   bytes, ciphertext 1088 bytes, shared secret 32 bytes. The private key
   is serialized by this library as the 64-byte seed (d || z) of FIPS 203
   Section 7.1, from which the 2400-byte decapsulation key is derived
   internally.
6. Ciphertext type check: decapsulation of a wrong-length ciphertext is
   refused with ValueError (cf. FIPS 203 Section 7.3, ciphertext type
   check).

References
-----------
- NIST FIPS 203, "Module-Lattice-Based Key-Encapsulation Mechanism
  Standard", August 2024, DOI 10.6028/NIST.FIPS.203.
  https://doi.org/10.6028/NIST.FIPS.203
- Implementation: pyca/cryptography, ML-KEM API
  (cryptography.hazmat.primitives.asymmetric.mlkem).
  https://cryptography.io/en/latest/hazmat/primitives/asymmetric/mlkem/

Run
---
    python3 -m venv .venv
    .venv/bin/pip install -r requirements.txt
    .venv/bin/python3 harness/mlkem_implicit_rejection.py

Exit code is 0 only when every check passes.
"""

from __future__ import annotations

import hashlib
import platform
import sys

import cryptography
from cryptography.hazmat.backends.openssl.backend import backend as openssl_backend
from cryptography.hazmat.primitives.asymmetric.mlkem import MLKEM768PrivateKey

TRIALS = 25
REPEAT_DECAPP = 3

EXPECTED_ENCAPSULATION_KEY_BYTES = 1184
EXPECTED_PRIVATE_SEED_BYTES = 64
EXPECTED_CIPHERTEXT_BYTES = 1088
EXPECTED_SHARED_SECRET_BYTES = 32


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def flip_byte(data: bytes, index: int) -> bytes:
    mutated = bytearray(data)
    mutated[index] ^= 0x01
    return bytes(mutated)


def main() -> int:
    print("ML-KEM-768 implicit-rejection behavioral test harness")
    print(f"python: {sys.version.split()[0]} ({platform.python_implementation()})")
    print(f"platform: {platform.platform()}")
    print(f"cryptography: {cryptography.__version__}")
    print(f"openssl: {openssl_backend.openssl_version_text()}")
    print(f"trials: {TRIALS}")
    print()

    agreement = 0
    rejection_first_byte = 0
    rejection_last_byte = 0
    deterministic = 0
    distinct_second_modification = 0
    sizes_ok = True
    example = None

    for trial in range(TRIALS):
        private_key = MLKEM768PrivateKey.generate()
        public_key = private_key.public_key()

        shared_secret, ciphertext = public_key.encapsulate()
        recovered_secret = private_key.decapsulate(ciphertext)

        if shared_secret == recovered_secret:
            agreement += 1

        if len(public_key.public_bytes_raw()) != EXPECTED_ENCAPSULATION_KEY_BYTES:
            sizes_ok = False
        if len(private_key.private_bytes_raw()) != EXPECTED_PRIVATE_SEED_BYTES:
            sizes_ok = False
        if len(ciphertext) != EXPECTED_CIPHERTEXT_BYTES:
            sizes_ok = False
        if len(shared_secret) != EXPECTED_SHARED_SECRET_BYTES:
            sizes_ok = False
        if len(recovered_secret) != EXPECTED_SHARED_SECRET_BYTES:
            sizes_ok = False

        modified_first = flip_byte(ciphertext, 0)
        rejected_first = private_key.decapsulate(modified_first)
        if rejected_first != shared_secret:
            rejection_first_byte += 1

        modified_last = flip_byte(ciphertext, len(ciphertext) - 1)
        rejected_last = private_key.decapsulate(modified_last)
        if rejected_last != shared_secret:
            rejection_last_byte += 1

        repeated = [
            private_key.decapsulate(modified_first) for _ in range(REPEAT_DECAPP)
        ]
        if len(set(repeated)) == 1 and repeated[0] == rejected_first:
            deterministic += 1

        modified_mid = flip_byte(ciphertext, len(ciphertext) // 2)
        rejected_mid = private_key.decapsulate(modified_mid)
        if rejected_mid != shared_secret and rejected_mid != rejected_first:
            distinct_second_modification += 1

        if example is None:
            example = {
                "valid_shared_secret_sha256": sha256_hex(shared_secret),
                "decapsulated_shared_secret_sha256": sha256_hex(recovered_secret),
                "modified_byte_0_sha256": sha256_hex(rejected_first),
                "modified_byte_1087_sha256": sha256_hex(rejected_last),
                "modified_byte_544_sha256": sha256_hex(rejected_mid),
            }

    # Ciphertext type check: wrong-length ciphertexts must be refused.
    type_check_refused = True
    probe_key = MLKEM768PrivateKey.generate()
    for bad_length in (EXPECTED_CIPHERTEXT_BYTES - 1, EXPECTED_CIPHERTEXT_BYTES + 1):
        try:
            probe_key.decapsulate(b"\x00" * bad_length)
        except ValueError:
            pass
        else:
            type_check_refused = False

    checks = [
        ("valid shared-secret agreement", agreement, TRIALS),
        ("modified ciphertext (byte 0) rejected", rejection_first_byte, TRIALS),
        ("modified ciphertext (byte 1087) rejected", rejection_last_byte, TRIALS),
        ("repeated decapsulation of same modified ciphertext deterministic", deterministic, TRIALS),
        ("second distinct modification (byte 544) differs from valid secret and from first", distinct_second_modification, TRIALS),
        ("sizes match FIPS 203 Table 3 / Section 7.1 seed form", 1 if sizes_ok else 0, 1),
        ("wrong-length ciphertext refused (type check)", 1 if type_check_refused else 0, 1),
    ]

    print("Example digests (trial 1, SHA-256 of each 32-byte output):")
    for label, digest in example.items():
        print(f"  {label}: {digest}")
    print()

    print("Results")
    print("-------")
    all_passed = True
    for name, passed, total in checks:
        status = "PASS" if passed == total else "FAIL"
        if passed != total:
            all_passed = False
        print(f"[{status}] {name}: {passed}/{total}")
    print()

    if all_passed:
        print("ALL CHECKS PASSED")
        return 0
    print("FAILURES PRESENT")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
