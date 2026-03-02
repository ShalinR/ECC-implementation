"""
CSePS — Bidder Module
Bidder registration (ECC key generation) and bid submission workflow.
"""

import os
import json

from . import utils
from .crypto_core import (
    generate_ecc_keypair,
    save_private_key,
    save_public_key,
    load_private_key,
    sign_data,
    hash_data,
    ecies_encrypt,
    b64encode,
)
from . import ledger


def list_bidders() -> list[str]:
    """Return names of all registered bidders."""
    utils.ensure_dirs()
    bidders = []
    for fname in os.listdir(utils.KEYS_DIR):
        if fname.endswith("_private.pem"):
            bidders.append(fname.replace("_private.pem", ""))
    return sorted(bidders)


def register_bidder(name: str, password: str = None) -> dict:
    """
    Register a new bidder:
    1. Generate ECC key pair
    2. Save keys to data/keys/
    3. Log registration to ledger
    """
    utils.ensure_dirs()
    safe_name = name.strip().lower().replace(" ", "_")

    priv_path = os.path.join(utils.KEYS_DIR, f"{safe_name}_private.pem")
    pub_path = os.path.join(utils.KEYS_DIR, f"{safe_name}_public.pem")

    if os.path.exists(priv_path):
        raise ValueError(f"Bidder '{name}' is already registered.")

    # Generate keys
    private_key, public_key = generate_ecc_keypair()
    save_private_key(private_key, priv_path, password)
    save_public_key(public_key, pub_path)

    # Log to ledger
    ledger.add_entry(
        "BIDDER_REGISTERED",
        f"bidder:{safe_name}",
        {"bidder_name": safe_name},
    )

    return {
        "name": safe_name,
        "private_key_path": priv_path,
        "public_key_path": pub_path,
    }


def submit_bid(
    bidder_name: str,
    tender_id: str,
    bid_amount: float,
    details: str,
    password: str = None,
) -> dict:
    """
    Submit a bid:
    1. Serialize bid data as JSON bytes
    2. Sign with bidder's ECDSA private key
    3. Encrypt bid payload with tender's public key (ECIES)
    4. Hash the encrypted bundle
    5. Log to ledger
    6. Save encrypted bundle to data/bids/

    Returns the bid record dict.
    """
    utils.ensure_dirs()
    safe_name = bidder_name.strip().lower().replace(" ", "_")

    # Load bidder's private key
    priv_path = os.path.join(utils.KEYS_DIR, f"{safe_name}_private.pem")
    if not os.path.exists(priv_path):
        raise FileNotFoundError(f"Bidder '{bidder_name}' is not registered.")

    private_key = load_private_key(priv_path, password)

    # 1. Serialize bid
    bid_payload = json.dumps({
        "bidder": safe_name,
        "tender_id": tender_id,
        "bid_amount": bid_amount,
        "details": details,
        "timestamp": utils.utc_now_iso(),
    }, sort_keys=True).encode("utf-8")

    # 2. Sign
    signature = sign_data(private_key, bid_payload)

    tender_path = os.path.join(utils.TENDERS_DIR, f"{tender_id}.json")
    if not os.path.exists(tender_path):
        raise FileNotFoundError(f"Tender '{tender_id}' not found.")
    tender_data = utils.read_json(tender_path)
    tender_pub_pem = tender_data.get("public_key_pem")
    if not tender_pub_pem:
        raise ValueError(f"Tender '{tender_id}' does not possess a public key.")

    from cryptography.hazmat.primitives import serialization
    tender_public_key = serialization.load_pem_public_key(tender_pub_pem.encode("utf-8"))

    # 3. Encrypt with tender public key (ECIES)
    encrypted = ecies_encrypt(tender_public_key, bid_payload)

    # 4. Build the bid bundle
    bid_bundle = {
        "bidder": safe_name,
        "tender_id": tender_id,
        "encrypted_bid": encrypted,
        "signature": b64encode(signature),
        "payload_hash": hash_data(bid_payload),
        "submitted_at": utils.utc_now_iso(),
    }

    # 5. Hash of the entire bundle for ledger
    bundle_bytes = json.dumps(bid_bundle, sort_keys=True).encode("utf-8")
    bundle_hash = hash_data(bundle_bytes)

    # 6. Log to ledger
    ledger.add_entry(
        "BID_SUBMITTED",
        bundle_hash,
        {"bidder": safe_name, "tender_id": tender_id},
    )

    # 7. Save to disk
    bid_filename = f"{tender_id}_{safe_name}.json"
    bid_path = os.path.join(utils.BIDS_DIR, bid_filename)
    utils.write_json(bid_path, bid_bundle)

    return {
        "bid_file": bid_path,
        "bundle_hash": bundle_hash,
        "payload_hash": bid_bundle["payload_hash"],
    }
