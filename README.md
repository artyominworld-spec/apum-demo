# AI Certification — Public Demo

Public verification artifacts for the AI Certification Evidence System.

## Files

- demo_bundle.json — evidence bundle with REAL ML-DSA-65 signatures (3309 bytes)
- demo_pubkey.hex — ML-DSA-65 public key
- verify_cert_bundle.py — offline verifier

## Verify (10 seconds)

    python3 -c "import json; d=json.load(open('demo_bundle.json')); print(len(d['run']['signature'])//2, 'bytes')"

Expected: 3309 bytes (ML-DSA-65, FIPS 204)

## Note

Full source code is available on purchase. Demo bundle uses synthetic data, no commercial value.
