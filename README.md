# AI Certification — Public Demo

Public verification artifacts.

- demo_bundle.json — bundle with REAL ML-DSA-65 signatures (3309 bytes)
- demo_pubkey.hex — ML-DSA-65 public key
- verify_cert_bundle.py — offline verifier

## Verify signature size

    python3 -c "import json; d=json.load(open('demo_bundle.json')); print(len(d['run']['signature'])//2, 'bytes')"

Expected: 3309 bytes (ML-DSA-65, FIPS 204)
