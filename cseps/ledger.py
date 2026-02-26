"""
CSePS — Tamper-Proof Append-Only Ledger (Hash-Chain).

Each entry links to the previous entry's hash, forming an immutable chain.
Any modification to a past entry will break the chain during verification.
"""

import os
from . import utils
from .crypto_core import hash_string


EVENTS = [
    "TENDER_CREATED",
    "BIDDER_REGISTERED",
    "BID_SUBMITTED",
    "DEADLINE_PASSED",
    "BID_OPENED",
    "AUDIT_VERIFIED",
]


def _genesis_hash() -> str:
    """The fixed hash for the very first entry's 'previous_hash'."""
    return "0" * 64


def _load_chain() -> list[dict]:
    """Load the ledger chain from disk."""
    if not os.path.exists(utils.LEDGER_FILE):
        return []
    return utils.read_json(utils.LEDGER_FILE)


def _save_chain(chain: list[dict]):
    """Persist the ledger chain to disk."""
    utils.write_json(utils.LEDGER_FILE, chain)


def _compute_entry_hash(entry: dict) -> str:
    """Compute the hash of a ledger entry (excluding its own 'entry_hash' field)."""
    payload = (
        str(entry["index"])
        + entry["timestamp"]
        + entry["event_type"]
        + entry["data_hash"]
        + entry["previous_hash"]
    )
    return hash_string(payload)


def add_entry(event_type: str, data: str, metadata: dict | None = None) -> dict:
    """
    Append a new entry to the ledger.

    Args:
        event_type: One of the recognised event types.
        data: Arbitrary data string to be hashed into the entry.
        metadata: Optional dict of extra display info (not part of the hash).

    Returns:
        The newly created entry dict.
    """
    chain = _load_chain()

    previous_hash = chain[-1]["entry_hash"] if chain else _genesis_hash()
    data_hash = hash_string(data)
    timestamp = utils.utc_now_iso()

    entry = {
        "index": len(chain),
        "timestamp": timestamp,
        "event_type": event_type,
        "data_hash": data_hash,
        "previous_hash": previous_hash,
        "entry_hash": "",          # placeholder
        "metadata": metadata or {},
    }
    entry["entry_hash"] = _compute_entry_hash(entry)

    chain.append(entry)
    _save_chain(chain)
    return entry


def verify_chain() -> tuple[bool, list[str]]:
    """
    Walk the entire chain and verify every link.

    Returns:
        (is_valid, list_of_error_messages)
    """
    chain = _load_chain()
    errors: list[str] = []

    if not chain:
        return True, []

    for i, entry in enumerate(chain):
        # Check previous_hash link
        expected_prev = chain[i - 1]["entry_hash"] if i > 0 else _genesis_hash()
        if entry["previous_hash"] != expected_prev:
            errors.append(
                f"Entry #{i}: previous_hash mismatch "
                f"(expected {expected_prev[:16]}…, got {entry['previous_hash'][:16]}…)"
            )

        # Check self-hash
        expected_hash = _compute_entry_hash(entry)
        if entry["entry_hash"] != expected_hash:
            errors.append(
                f"Entry #{i}: entry_hash mismatch "
                f"(expected {expected_hash[:16]}…, got {entry['entry_hash'][:16]}…)"
            )

    return len(errors) == 0, errors


def get_entries(event_type: str | None = None) -> list[dict]:
    """Return ledger entries, optionally filtered by event type."""
    chain = _load_chain()
    if event_type:
        return [e for e in chain if e["event_type"] == event_type]
    return chain


def entry_count() -> int:
    return len(_load_chain())
