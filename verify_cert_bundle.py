#!/usr/bin/env python3
import argparse
import json
import sys

from apum.crypto.pqc_signer import verify as pqc_verify
from apum.merkle.log import verify_inclusion


def _load_json(path):
    if path == "-":
        return json.load(sys.stdin)
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def _load_hex(path):
    if path == "-":
        return bytes.fromhex(sys.stdin.read().strip())
    with open(path, "r", encoding="utf-8") as f:
        return bytes.fromhex(f.read().strip())


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--bundle", required=True)
    ap.add_argument("--public-key", required=True)
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    b = _load_json(args.bundle)
    pub = _load_hex(args.public_key)
    root = bytes.fromhex(b["anchor"]["root_hash"])
    tree_size = b["anchor"]["tree_size"]

    run = b["run"]
    leaf = bytes.fromhex(run["leaf_hash"])
    sig = bytes.fromhex(run["signature"])
    ok_sig = pqc_verify(pub, leaf, sig)

    proof = [bytes.fromhex(x) for x in run["merkle_proof"]]
    ok_run_incl = verify_inclusion(leaf, run["merkle_index"], proof, root, tree_size)

    test_results = []
    for t in b["tests"]:
        tleaf = bytes.fromhex(t["leaf_hash"])
        tsig = bytes.fromhex(t["signature"])
        tproof = [bytes.fromhex(x) for x in t["merkle_proof"]]
        ok_t_sig = pqc_verify(pub, tleaf, tsig)
        ok_t_incl = verify_inclusion(tleaf, t["merkle_index"], tproof, root, tree_size)
        test_results.append({
            "test_id": t["test_id"],
            "signature_ok": ok_t_sig,
            "inclusion_ok": ok_t_incl,
        })

    all_tests_ok = all(r["signature_ok"] and r["inclusion_ok"] for r in test_results)
    intact = ok_sig and ok_run_incl and all_tests_ok

    if args.json:
        print(json.dumps({
            "run_signature_ok": ok_sig,
            "run_inclusion_ok": ok_run_incl,
            "tests": test_results,
            "verdict": run.get("verdict"),
            "methodology_ref": run.get("methodology_ref"),
            "intact": intact,
        }, indent=2))
    else:
        print(f"Run signature:      {'PASS' if ok_sig else 'FAIL'}")
        print(f"Run inclusion:      {'PASS' if ok_run_incl else 'FAIL'}")
        ok_count = sum(1 for r in test_results if r["signature_ok"] and r["inclusion_ok"])
        print(f"Tests verified:     {ok_count}/{len(test_results)}")
        print(f"Verdict:            {run.get('verdict')}")
        print(f"Methodology:        {run.get('methodology_ref')}")
        print()
        if intact:
            print("VERDICT: EVIDENCE PACKAGE INTACT")
        else:
            print("VERDICT: EVIDENCE PACKAGE TAMPERED")

    sys.exit(0 if intact else 1)


if __name__ == "__main__":
    main()
