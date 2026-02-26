<<<<<<< HEAD
"""
CSePS — Admin Module
Tender creation (with threshold key split) and bid opening ceremony.
"""

import os
import json
from datetime import datetime, timezone

from . import utils
from .crypto_core import (
    generate_ecc_keypair,
    save_private_key,
    save_public_key,
    load_private_key,
    load_public_key,
    public_key_to_pem_str,
    private_key_to_pem_str,
    ecies_decrypt,
    verify_signature,
    hash_data,
    b64decode,
)
from .threshold import generate_master_key, split_key, reconstruct_key
from . import ledger

def register_admin(name: str, password: str = None) -> dict:
    """Register a new admin user with a password-protected key."""
    utils.ensure_dirs()
    safe_name = name.strip().lower().replace(" ", "_")

    priv_path = os.path.join(utils.KEYS_DIR, f"admin_{safe_name}_private.pem")
    pub_path = os.path.join(utils.KEYS_DIR, f"admin_{safe_name}_public.pem")

    if os.path.exists(priv_path):
        raise ValueError(f"Admin '{name}' is already registered.")

    # Generate keys
    private_key, public_key = generate_ecc_keypair()
    save_private_key(private_key, priv_path, password)
    save_public_key(public_key, pub_path)

    # Log to ledger
    ledger.add_entry(
        "ADMIN_REGISTERED",
        f"admin:{safe_name}",
        {"admin_name": safe_name},
    )

    return {
        "name": safe_name,
        "private_key_path": priv_path,
        "public_key_path": pub_path,
    }

def authenticate_admin(name: str, password: str = None) -> str:
    """Authenticate an admin by decrypting their private key."""
    safe_name = name.strip().lower().replace(" ", "_")
    priv_path = os.path.join(utils.KEYS_DIR, f"admin_{safe_name}_private.pem")
    if not os.path.exists(priv_path):
        raise FileNotFoundError(f"Admin '{name}' is not registered.")
    
    # Will raise ValueError (Bad decrypt) if password is wrong
    load_private_key(priv_path, password)
    return safe_name



def list_tenders() -> list[dict]:
    """Return all tenders from data/tenders/."""
    utils.ensure_dirs()
    tenders = []
    for fname in os.listdir(utils.TENDERS_DIR):
        if fname.endswith(".json"):
            tenders.append(utils.read_json(os.path.join(utils.TENDERS_DIR, fname)))
    return tenders


def get_tender(tender_id: str) -> dict | None:
    """Load a single tender by ID."""
    path = os.path.join(utils.TENDERS_DIR, f"{tender_id}.json")
    if os.path.exists(path):
        return utils.read_json(path)
    return None


def create_tender(
    title: str,
    deadline_iso: str,
    num_evaluators: int = 3,
    threshold: int = 2,
    admin_name: str = None,
    admin_password: str = None,
) -> dict:
    """
    Create a new tender:
    1. Generate AES-256 master key
    2. Split via Shamir's Secret Sharing
    3. Save tender metadata
    4. Log to ledger

    Returns dict with tender info and evaluator shares.
    """
    utils.ensure_dirs()

    tender_id = f"TND-{utils.utc_now_iso()[:10].replace('-', '')}-{os.urandom(3).hex().upper()}"

    # Generate tender ECC keypair (Private key split, Public key stored)
    tender_priv, tender_pub = generate_ecc_keypair()
    tender_priv_pem = private_key_to_pem_str(tender_priv).encode("utf-8")
    tender_pub_pem = public_key_to_pem_str(tender_pub)
    
    shares = split_key(tender_priv_pem, num_evaluators, threshold)

    admin_id = authenticate_admin(admin_name, admin_password) if admin_name else "unknown"

    tender = {
        "tender_id": tender_id,
        "title": title,
        "deadline": deadline_iso,
        "num_evaluators": num_evaluators,
        "threshold": threshold,
        "public_key_pem": tender_pub_pem,
        "status": "OPEN",
        "created_by": admin_id,
        "created_at": utils.utc_now_iso(),
    }

    # Save tender (master key is NOT stored — only shares exist)
    tender_path = os.path.join(utils.TENDERS_DIR, f"{tender_id}.json")
    utils.write_json(tender_path, tender)

    # Log to ledger
    ledger.add_entry(
        "TENDER_CREATED",
        json.dumps({"tender_id": tender_id, "title": title, "deadline": deadline_iso, "created_by": admin_id}, sort_keys=True),
        {"tender_id": tender_id, "title": title, "created_by": admin_id},
    )

    return {
        "tender": tender,
        "shares": shares,
        "master_key_hex": "N/A (Using ECIES)",
    }


def is_deadline_passed(tender: dict) -> bool:
    """Check if the tender's deadline has passed."""
    deadline = datetime.fromisoformat(tender["deadline"])
    if deadline.tzinfo is None:
        deadline = deadline.replace(tzinfo=timezone.utc)
    return datetime.now(timezone.utc) >= deadline


def open_bids(tender_id: str, shares_b64: list[str], admin_name: str = None, admin_password: str = None) -> list[dict]:
    """
    Open bids for a tender after deadline:
    1. Verify deadline has passed
    2. Reconstruct master key from evaluator shares
    3. Decrypt each bid
    4. Verify each bid's ECDSA signature
    5. Log BID_OPENED events

    Returns list of decrypted bid records with verification status.
    """
    tender = get_tender(tender_id)
    if tender is None:
        raise FileNotFoundError(f"Tender '{tender_id}' not found.")

    if not is_deadline_passed(tender):
        raise PermissionError(
            f"Deadline ({tender['deadline']}) has NOT passed yet. "
            "Bids cannot be opened."
        )

    admin_id = authenticate_admin(admin_name, admin_password) if admin_name else "unknown"

    # Reconstruct private key PEM bytes and load it
    tender_priv_pem = reconstruct_key(shares_b64)
    from cryptography.hazmat.primitives import serialization
    master_key = serialization.load_pem_private_key(tender_priv_pem, password=None)

    # Find all bid files for this tender
    results = []
    for fname in os.listdir(utils.BIDS_DIR):
        if fname.startswith(tender_id) and fname.endswith(".json"):
            bid_bundle = utils.read_json(os.path.join(utils.BIDS_DIR, fname))

            # Decrypt
            try:
                plaintext = ecies_decrypt(master_key, bid_bundle["encrypted_bid"])
                bid_data = json.loads(plaintext.decode("utf-8"))
                decrypted = True
            except Exception as e:
                bid_data = {"error": str(e)}
                decrypted = False

            # Verify signature
            sig_valid = False
            if decrypted:
                try:
                    bidder_pub_path = os.path.join(
                        utils.KEYS_DIR, f"{bid_bundle['bidder']}_public.pem"
                    )
                    pub_key = load_public_key(bidder_pub_path)
                    sig_bytes = b64decode(bid_bundle["signature"])
                    sig_valid = verify_signature(pub_key, plaintext, sig_bytes)
                except Exception:
                    sig_valid = False

            # Verify payload hash
            hash_valid = False
            if decrypted:
                computed_hash = hash_data(plaintext)
                hash_valid = computed_hash == bid_bundle.get("payload_hash", "")

            result = {
                "bidder": bid_bundle["bidder"],
                "decrypted": decrypted,
                "signature_valid": sig_valid,
                "hash_valid": hash_valid,
                "bid_data": bid_data,
                "submitted_at": bid_bundle.get("submitted_at", "unknown"),
            }
            results.append(result)

            # Log
            ledger.add_entry(
                "BID_OPENED",
                json.dumps({
                    "tender_id": tender_id,
                    "bidder": bid_bundle["bidder"],
                    "sig_valid": sig_valid,
                    "hash_valid": hash_valid,
                    "opened_by": admin_id
                }, sort_keys=True),
                {
                    "tender_id": tender_id,
                    "bidder": bid_bundle["bidder"],
                    "signature_valid": sig_valid,
                    "opened_by": admin_id
                },
            )

    # Update tender status
    tender["status"] = "OPENED"
    utils.write_json(os.path.join(utils.TENDERS_DIR, f"{tender_id}.json"), tender)

    return results
=======
"""
CSePS — Admin Module
Tender creation (with threshold key split) and bid opening ceremony.
"""

import os
import json
from datetime import datetime, timezone

from . import utils
from .crypto_core import (
    load_public_key,
    aes_decrypt,
    verify_signature,
    hash_data,
    b64decode,
)
from .threshold import generate_master_key, split_key, reconstruct_key
from . import ledger


def list_tenders() -> list[dict]:
    """Return all tenders from data/tenders/."""
    utils.ensure_dirs()
    tenders = []
    for fname in os.listdir(utils.TENDERS_DIR):
        if fname.endswith(".json"):
            tenders.append(utils.read_json(os.path.join(utils.TENDERS_DIR, fname)))
    return tenders


def get_tender(tender_id: str) -> dict | None:
    """Load a single tender by ID."""
    path = os.path.join(utils.TENDERS_DIR, f"{tender_id}.json")
    if os.path.exists(path):
        return utils.read_json(path)
    return None


def create_tender(
    title: str,
    deadline_iso: str,
    num_evaluators: int = 3,
    threshold: int = 2,
) -> dict:
    """
    Create a new tender:
    1. Generate AES-256 master key
    2. Split via Shamir's Secret Sharing
    3. Save tender metadata
    4. Log to ledger

    Returns dict with tender info and evaluator shares.
    """
    utils.ensure_dirs()

    tender_id = f"TND-{utils.utc_now_iso()[:10].replace('-', '')}-{os.urandom(3).hex().upper()}"

    # Generate and split master key
    master_key = generate_master_key()
    shares = split_key(master_key, num_evaluators, threshold)

    tender = {
        "tender_id": tender_id,
        "title": title,
        "deadline": deadline_iso,
        "num_evaluators": num_evaluators,
        "threshold": threshold,
        "status": "OPEN",
        "created_at": utils.utc_now_iso(),
    }

    # Save tender (master key is NOT stored — only shares exist)
    tender_path = os.path.join(utils.TENDERS_DIR, f"{tender_id}.json")
    utils.write_json(tender_path, tender)

    # Log to ledger
    ledger.add_entry(
        "TENDER_CREATED",
        json.dumps({"tender_id": tender_id, "title": title, "deadline": deadline_iso}, sort_keys=True),
        {"tender_id": tender_id, "title": title},
    )

    return {
        "tender": tender,
        "shares": shares,
        "master_key_hex": master_key.hex(),   # shown once for demo; in production never revealed
    }


def is_deadline_passed(tender: dict) -> bool:
    """Check if the tender's deadline has passed."""
    deadline = datetime.fromisoformat(tender["deadline"])
    if deadline.tzinfo is None:
        deadline = deadline.replace(tzinfo=timezone.utc)
    return datetime.now(timezone.utc) >= deadline


def open_bids(tender_id: str, shares_b64: list[str]) -> list[dict]:
    """
    Open bids for a tender after deadline:
    1. Verify deadline has passed
    2. Reconstruct master key from evaluator shares
    3. Decrypt each bid
    4. Verify each bid's ECDSA signature
    5. Log BID_OPENED events

    Returns list of decrypted bid records with verification status.
    """
    tender = get_tender(tender_id)
    if tender is None:
        raise FileNotFoundError(f"Tender '{tender_id}' not found.")

    if not is_deadline_passed(tender):
        raise PermissionError(
            f"Deadline ({tender['deadline']}) has NOT passed yet. "
            "Bids cannot be opened."
        )

    # Reconstruct master key
    master_key = reconstruct_key(shares_b64)

    # Find all bid files for this tender
    results = []
    for fname in os.listdir(utils.BIDS_DIR):
        if fname.startswith(tender_id) and fname.endswith(".json"):
            bid_bundle = utils.read_json(os.path.join(utils.BIDS_DIR, fname))

            # Decrypt
            try:
                plaintext = aes_decrypt(master_key, bid_bundle["encrypted_bid"])
                bid_data = json.loads(plaintext.decode("utf-8"))
                decrypted = True
            except Exception as e:
                bid_data = {"error": str(e)}
                decrypted = False

            # Verify signature
            sig_valid = False
            if decrypted:
                try:
                    bidder_pub_path = os.path.join(
                        utils.KEYS_DIR, f"{bid_bundle['bidder']}_public.pem"
                    )
                    pub_key = load_public_key(bidder_pub_path)
                    sig_bytes = b64decode(bid_bundle["signature"])
                    sig_valid = verify_signature(pub_key, plaintext, sig_bytes)
                except Exception:
                    sig_valid = False

            # Verify payload hash
            hash_valid = False
            if decrypted:
                computed_hash = hash_data(plaintext)
                hash_valid = computed_hash == bid_bundle.get("payload_hash", "")

            result = {
                "bidder": bid_bundle["bidder"],
                "decrypted": decrypted,
                "signature_valid": sig_valid,
                "hash_valid": hash_valid,
                "bid_data": bid_data,
                "submitted_at": bid_bundle.get("submitted_at", "unknown"),
            }
            results.append(result)

            # Log
            ledger.add_entry(
                "BID_OPENED",
                json.dumps({
                    "tender_id": tender_id,
                    "bidder": bid_bundle["bidder"],
                    "sig_valid": sig_valid,
                    "hash_valid": hash_valid,
                }, sort_keys=True),
                {
                    "tender_id": tender_id,
                    "bidder": bid_bundle["bidder"],
                    "signature_valid": sig_valid,
                },
            )

    # Update tender status
    tender["status"] = "OPENED"
    utils.write_json(os.path.join(utils.TENDERS_DIR, f"{tender_id}.json"), tender)

    return results
>>>>>>> 3f9933bcf52c44ef351885c43cf19f66d0167f0f
