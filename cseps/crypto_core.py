"""
CSePS — Cryptographic Core
ECC key generation, ECIES encrypt/decrypt, ECDSA sign/verify, SHA-256 hashing.
"""

import os
import base64
import hashlib
import json

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# ── ECC Key Generation ──────────────────────────────────────────────────────

def generate_ecc_keypair():
    """Generate an ECC key pair on the SECP256R1 (P-256) curve."""
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    return private_key, public_key


# ── Key Serialization ────────────────────────────────────────────────────────

def save_private_key(private_key, filepath: str, password: str = None):
    """Save an ECC private key to PEM file."""
    encryption = serialization.BestAvailableEncryption(password.encode()) if password else serialization.NoEncryption()
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption,
    )
    with open(filepath, "wb") as f:
        f.write(pem)


def load_private_key(filepath: str, password: str = None):
    """Load an ECC private key from PEM file."""
    pwd_bytes = password.encode() if password else None
    with open(filepath, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=pwd_bytes)


def save_public_key(public_key, filepath: str):
    """Save an ECC public key to PEM file."""
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    with open(filepath, "wb") as f:
        f.write(pem)


def load_public_key(filepath: str):
    """Load an ECC public key from PEM file."""
    with open(filepath, "rb") as f:
        return serialization.load_pem_public_key(f.read())


def public_key_to_pem_str(public_key) -> str:
    """Serialize a public key to a PEM string."""
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")


def private_key_to_pem_str(private_key) -> str:
    """Serialize a private key to a PEM string."""
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")


# ── ECDSA Digital Signatures ────────────────────────────────────────────────

def sign_data(private_key, data: bytes) -> bytes:
    """Sign data with ECDSA using SHA-256."""
    return private_key.sign(data, ec.ECDSA(hashes.SHA256()))


def verify_signature(public_key, data: bytes, signature: bytes) -> bool:
    """Verify an ECDSA signature. Returns True if valid, False otherwise."""
    try:
        public_key.verify(signature, data, ec.ECDSA(hashes.SHA256()))
        return True
    except Exception:
        return False


# ── SHA-256 Hashing ─────────────────────────────────────────────────────────

def hash_data(data: bytes) -> str:
    """Return the SHA-256 hex digest of data."""
    return hashlib.sha256(data).hexdigest()


def hash_string(s: str) -> str:
    """Return the SHA-256 hex digest of a UTF-8 string."""
    return hash_data(s.encode("utf-8"))


# ── ECIES Encryption / Decryption ────────────────────────────────────────────
# ECIES: Ephemeral ECDH key agreement → HKDF → AES-256-GCM
# Output bundle: { ephemeral_pub, nonce, ciphertext }  (all base64-encoded)

def ecies_encrypt(recipient_public_key, plaintext: bytes) -> dict:
    """
    Encrypt plaintext for a recipient using ECIES:
      1. Generate ephemeral ECC key pair
      2. ECDH shared secret with recipient's public key
      3. Derive AES-256 key via HKDF
      4. Encrypt with AES-256-GCM
    Returns a dict with base64-encoded components.
    """
    # 1. Ephemeral key
    ephemeral_private = ec.generate_private_key(ec.SECP256R1())
    ephemeral_public = ephemeral_private.public_key()

    # 2. ECDH → shared secret
    shared_secret = ephemeral_private.exchange(ec.ECDH(), recipient_public_key)

    # 3. HKDF → AES key
    aes_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"cseps-ecies",
    ).derive(shared_secret)

    # 4. AES-256-GCM encrypt
    nonce = os.urandom(12)
    aesgcm = AESGCM(aes_key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)

    # Serialize ephemeral public key
    ephemeral_pub_bytes = ephemeral_public.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint,
    )

    return {
        "ephemeral_pub": base64.b64encode(ephemeral_pub_bytes).decode(),
        "nonce": base64.b64encode(nonce).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode(),
    }


def ecies_decrypt(recipient_private_key, bundle: dict) -> bytes:
    """
    Decrypt an ECIES bundle using the recipient's private key.
    """
    # Deserialize
    ephemeral_pub_bytes = base64.b64decode(bundle["ephemeral_pub"])
    nonce = base64.b64decode(bundle["nonce"])
    ciphertext = base64.b64decode(bundle["ciphertext"])

    # Reconstruct ephemeral public key
    ephemeral_public = ec.EllipticCurvePublicKey.from_encoded_point(
        ec.SECP256R1(), ephemeral_pub_bytes
    )

    # ECDH → shared secret
    shared_secret = recipient_private_key.exchange(ec.ECDH(), ephemeral_public)

    # HKDF → AES key
    aes_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"cseps-ecies",
    ).derive(shared_secret)

    # AES-256-GCM decrypt
    aesgcm = AESGCM(aes_key)
    return aesgcm.decrypt(nonce, ciphertext, None)


# ── Symmetric AES-256-GCM (used with tender master key) ─────────────────────

def aes_encrypt(key: bytes, plaintext: bytes) -> dict:
    """Encrypt with AES-256-GCM. Returns dict with base64 nonce + ciphertext."""
    nonce = os.urandom(12)
    aesgcm = AESGCM(key)
    ct = aesgcm.encrypt(nonce, plaintext, None)
    return {
        "nonce": base64.b64encode(nonce).decode(),
        "ciphertext": base64.b64encode(ct).decode(),
    }


def aes_decrypt(key: bytes, bundle: dict) -> bytes:
    """Decrypt an AES-256-GCM bundle."""
    nonce = base64.b64decode(bundle["nonce"])
    ct = base64.b64decode(bundle["ciphertext"])
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ct, None)


# ── Helpers ──────────────────────────────────────────────────────────────────

def b64encode(data: bytes) -> str:
    return base64.b64encode(data).decode()


def b64decode(s: str) -> bytes:
    return base64.b64decode(s)
