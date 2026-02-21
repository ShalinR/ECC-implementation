"""
CSePS — Threshold Key Management via Shamir's Secret Sharing.

Generates a random AES-256 master key for each tender, splits it into
n shares with threshold k, and reconstructs it when >= k shares are provided.
"""

import os
import base64
import pyshamir


def generate_master_key() -> bytes:
    """Generate a random 32-byte (256-bit) AES master key."""
    return os.urandom(32)


def split_key(master_key: bytes, num_shares: int, threshold: int) -> list[str]:
    """
    Split a master key into `num_shares` shares using Shamir's Secret Sharing.
    At least `threshold` shares are required to reconstruct the key.

    Returns a list of base64-encoded share strings.
    """
    if threshold > num_shares:
        raise ValueError("Threshold cannot exceed the number of shares.")
    if threshold < 2:
        raise ValueError("Threshold must be at least 2.")

    # pyshamir.split returns list of bytes
    shares = pyshamir.split(master_key, num_shares, threshold)
    return [base64.b64encode(s).decode() for s in shares]


def reconstruct_key(shares_b64: list[str]) -> bytes:
    """
    Reconstruct the master key from a list of base64-encoded shares.
    Requires at least `threshold` shares (as defined at split time).
    """
    shares = [base64.b64decode(s) for s in shares_b64]
    return pyshamir.combine(shares)


def format_share_for_display(index: int, share_b64: str) -> str:
    """Return a short display string for a share (truncated for readability)."""
    truncated = share_b64[:20] + "..." if len(share_b64) > 20 else share_b64
    return f"Share #{index + 1}: {truncated}"
