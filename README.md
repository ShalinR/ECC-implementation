# CSePS — Cryptographically Secure Government e-Procurement System

A command-line prototype demonstrating how modern cryptography can solve real-world procurement fraud, bid-tampering, and early-leak problems.

## Features

| Feature | Cryptographic Mechanism |
|---|---|
| **Bid Confidentiality** | AES-256-GCM encryption with Shamir-split master key |
| **Bidder Anonymity** (until deadline) | Encrypted bids; identities sealed |
| **Non-Repudiation** | ECDSA digital signatures (SECP256R1 / P-256) |
| **Tamper Detection** | SHA-256 hash-chain ledger (mini blockchain) |
| **Deadline Enforcement** | Threshold decryption — k-of-n evaluator shares required |
| **Public Auditability** | Append-only ledger verifiable by anyone |

## Quickstart

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Run the system
python -m cseps

# 3. Try the full demo (option 8)
#    This registers bidders, creates a tender, submits bids,
#    opens them after deadline, and runs a full audit — all automated.
```

## Architecture

```
cseps/
├── main.py          # Interactive CLI menu
├── crypto_core.py   # ECC keygen, ECIES, ECDSA, AES-256-GCM, SHA-256
├── threshold.py     # Shamir's Secret Sharing (key split/reconstruct)
├── ledger.py        # Hash-chain append-only ledger
├── bidder.py        # Bidder registration & bid submission
├── admin.py         # Tender creation & bid opening
├── verifier.py      # Audit & verification functions
└── utils.py         # Timestamps, colored output, file I/O

data/                # Created at runtime
├── keys/            # ECC key pairs (PEM)
├── bids/            # Encrypted bid bundles (JSON)
├── tenders/         # Tender metadata (JSON)
└── ledger.json      # Tamper-proof hash-chain log
```

## CLI Menu

```
1  Register as Bidder
2  Create New Tender               (Admin)
3  Submit a Bid
4  Open Bids After Deadline        (Admin)
5  Verify Ledger Integrity
6  Verify a Bid File
7  View Audit Log
8  Demo: Full End-to-End Workflow
0  Exit
```

## Workflow

1. **Admin** creates a tender → generates AES-256 master key → splits into shares via Shamir's Secret Sharing → distributes shares to evaluators
2. **Bidders** register (ECC keypair generated) → submit bids (signed with ECDSA, encrypted with master key, hashed, logged to ledger)
3. **After deadline**, evaluators combine ≥ k shares → master key reconstructed → bids decrypted → signatures verified
4. **Anyone** can verify the ledger's hash-chain integrity and confirm no bids were tampered with

## Dependencies

- `cryptography` — ECC, ECDSA, ECDH, AES-GCM, HKDF
- `pyshamir` — Shamir's Secret Sharing
