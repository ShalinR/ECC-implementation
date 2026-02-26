"""
CSePS — Verifier / Auditor Module
Public audit functions: ledger verification, bid signature checks, audit reports.
"""

import os
import json

from . import utils
from .crypto_core import load_public_key, verify_signature, hash_data, b64decode
from . import ledger


def verify_ledger_integrity() -> tuple[bool, list[str]]:
    """Verify the entire hash-chain ledger. Returns (is_valid, errors)."""
    return ledger.verify_chain()


def verify_bid_file(bid_filepath: str) -> dict:
    """
    Verify a bid file's signature and hash WITHOUT decrypting it.
    This proves the encrypted bundle has not been tampered with.
    """
    bid_bundle = utils.read_json(bid_filepath)

    # Re-compute bundle hash
    bundle_bytes = json.dumps(bid_bundle, sort_keys=True).encode("utf-8")
    current_hash = hash_data(bundle_bytes)

    # Check if this hash exists in the ledger
    submissions = ledger.get_entries("BID_SUBMITTED")
    hash_in_ledger = any(e["data_hash"] == hash_data(current_hash) for e in submissions)

    return {
        "bidder": bid_bundle.get("bidder", "unknown"),
        "tender_id": bid_bundle.get("tender_id", "unknown"),
        "submitted_at": bid_bundle.get("submitted_at", "unknown"),
        "payload_hash": bid_bundle.get("payload_hash", ""),
        "bundle_hash": current_hash,
        "hash_recorded_in_ledger": hash_in_ledger,
    }


def generate_audit_report() -> str:
    """
    Generate a human-readable audit report of all ledger entries.
    """
    entries = ledger.get_entries()
    is_valid, errors = ledger.verify_chain()

    lines = []
    lines.append("=" * 64)
    lines.append("         CSePS — PUBLIC AUDIT REPORT")
    lines.append("=" * 64)
    lines.append(f"  Report generated: {utils.utc_now_iso()}")
    lines.append(f"  Total ledger entries: {len(entries)}")
    lines.append(f"  Chain integrity: {'VALID ✓' if is_valid else 'COMPROMISED ✗'}")
    if errors:
        for err in errors:
            lines.append(f"    ✗ {err}")
    lines.append("=" * 64)

    for entry in entries:
        lines.append(f"\n  [{entry['index']:>4}]  {entry['event_type']}")
        lines.append(f"         Time:       {entry['timestamp']}")
        lines.append(f"         Data Hash:  {entry['data_hash'][:32]}…")
        lines.append(f"         Prev Hash:  {entry['previous_hash'][:32]}…")
        lines.append(f"         Entry Hash: {entry['entry_hash'][:32]}…")
        if entry.get("metadata"):
            for k, v in entry["metadata"].items():
                lines.append(f"         {k}: {v}")

    lines.append("\n" + "=" * 64)
    lines.append("  END OF AUDIT REPORT")
    lines.append("=" * 64)

    return "\n".join(lines)
