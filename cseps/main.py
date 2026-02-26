<<<<<<< HEAD
"""
CSePS — Main CLI Entry Point
Interactive menu for the Cryptographically Secure e-Procurement System.
"""

import sys
import os
import json
import base64
import getpass
from datetime import datetime, timezone, timedelta

from .utils import (
    header, section, info, success, warn, error, dim, bold,
    Color, ensure_dirs,
)
from . import bidder as bidder_mod
from . import admin as admin_mod
from . import verifier as verifier_mod
from . import ledger
from .threshold import reconstruct_key


# ── Helpers ──────────────────────────────────────────────────────────────────

def prompt(msg: str, default: str = "") -> str:
    """Prompt user for input with optional default."""
    suffix = f" [{default}]" if default else ""
    val = input(f"  {Color.YELLOW}>{Color.RESET} {msg}{suffix}: ").strip()
    return val if val else default


def prompt_password(msg: str) -> str:
    """Prompt user for hidden password input."""
    return getpass.getpass(f"  {Color.YELLOW}>{Color.RESET} {msg}: ").strip()


def confirm(msg: str) -> bool:
    return prompt(f"{msg} (y/n)", "y").lower() in ("y", "yes")


def pause():
    input(f"\n  {dim('Press Enter to continue...')}")


def print_menu():
    header("CSePS — Secure e-Procurement System")
    options = [
        ("1", "Register as Bidder"),
        ("2", "Register as Admin/User"),
        ("3", "Create New Tender               (Admin)"),
        ("4", "Submit a Bid"),
        ("5", "Open Bids After Deadline         (Admin)"),
        ("6", "Verify Ledger Integrity"),
        ("7", "Verify a Bid File"),
        ("8", "View Audit Log"),
        ("9", "Demo: Full End-to-End Workflow"),
        ("0", "Exit"),
    ]
    for num, label in options:
        print(f"    {Color.BOLD}{Color.CYAN}{num}{Color.RESET}  {label}")
    print()


# ── Menu Actions ─────────────────────────────────────────────────────────────

def action_register_bidder():
    section("Bidder Registration")
    name = prompt("Enter bidder name")
    if not name:
        error("Name cannot be empty.")
        return
    pwd = prompt_password("Enter new password")

    try:
        result = bidder_mod.register_bidder(name, pwd)
        success(f"Bidder '{result['name']}' registered successfully!")
        info(f"Private key: {result['private_key_path']}")
        info(f"Public key:  {result['public_key_path']}")
        info("Registered event logged to ledger.")
    except ValueError as e:
        warn(str(e))
    except Exception as e:
        error(f"Registration failed: {e}")


def action_register_admin():
    section("Admin/User Registration")
    name = prompt("Enter admin username")
    if not name:
        error("Name cannot be empty.")
        return
    pwd = prompt_password("Enter new password")

    try:
        result = admin_mod.register_admin(name, pwd)
        success(f"Admin '{result['name']}' registered successfully!")
        info("Registered event logged to ledger.")
    except ValueError as e:
        warn(str(e))
    except Exception as e:
        error(f"Registration failed: {e}")


def action_create_tender():
    section("Create New Tender")
    admin_name = prompt("Admin username")
    admin_pwd = prompt_password("Admin password")

    title = prompt("Tender title")
    if not title:
        error("Title cannot be empty.")
        return

    # Default deadline: 1 minute from now (for demo purposes)
    default_dl = (datetime.now(timezone.utc) + timedelta(minutes=1)).strftime("%Y-%m-%dT%H:%M:%S+00:00")
    deadline_str = prompt("Deadline (ISO format)", default_dl)

    num_eval = int(prompt("Number of evaluators", "3"))
    thresh = int(prompt("Threshold (min shares to open)", "2"))

    try:
        result = admin_mod.create_tender(title, deadline_str, num_eval, thresh, admin_name, admin_pwd)
        t = result["tender"]

        success(f"Tender created: {t['tender_id']}")
        info(f"Title:      {t['title']}")
        info(f"Deadline:   {t['deadline']}")
        info(f"Evaluators: {t['num_evaluators']} (threshold: {t['threshold']})")

        section("Evaluator Key Shares (DISTRIBUTE SECURELY)")
        print(f"  {Color.RED}{Color.BOLD}⚠  These shares are shown ONCE. Save them!{Color.RESET}\n")
        for i, share in enumerate(result["shares"]):
            print(f"    Share #{i+1}: {Color.GREEN}{share}{Color.RESET}")

        print(f"\n  {dim('Master key (demo only): ' + result['master_key_hex'])}")

        info("Tender creation logged to ledger.")
    except Exception as e:
        error(f"Failed to create tender: {e}")


def action_submit_bid():
    section("Submit a Bid")

    # List available bidders
    bidders = bidder_mod.list_bidders()
    if not bidders:
        warn("No bidders registered yet. Register first (option 1).")
        return
    info(f"Registered bidders: {', '.join(bidders)}")
    bidder_name = prompt("Your bidder name")
    pwd = prompt_password("Your password")

    # List available tenders
    tenders = admin_mod.list_tenders()
    if not tenders:
        warn("No tenders available. Create one first (option 2).")
        return
    info("Available tenders:")
    for t in tenders:
        status_color = Color.GREEN if t["status"] == "OPEN" else Color.RED
        print(f"    {t['tender_id']}  {t['title']}  [{status_color}{t['status']}{Color.RESET}]")

    tender_id = prompt("Tender ID")
    bid_amount = float(prompt("Bid amount (numeric)"))
    details = prompt("Bid details/description", "Standard bid submission")

    try:
        result = bidder_mod.submit_bid(bidder_name, tender_id, bid_amount, details, pwd)
        success("Bid submitted successfully!")
        info(f"Bid file:     {result['bid_file']}")
        info(f"Bundle hash:  {result['bundle_hash'][:32]}…")
        info(f"Payload hash: {result['payload_hash'][:32]}…")
        info("Submission logged to ledger with hash + timestamp.")
    except Exception as e:
        error(f"Submission failed: {e}")


def action_open_bids():
    section("Open Bids (Post-Deadline)")

    tenders = admin_mod.list_tenders()
    if not tenders:
        warn("No tenders available.")
        return

    info("Available tenders:")
    for t in tenders:
        dl = t["deadline"]
        passed = admin_mod.is_deadline_passed(t)
        status = f"{Color.GREEN}DEADLINE PASSED ✓{Color.RESET}" if passed else f"{Color.RED}STILL OPEN{Color.RESET}"
        print(f"    {t['tender_id']}  {t['title']}  [{status}]")

    tender_id = prompt("Tender ID to open")
    admin_name = prompt("Admin username")
    admin_pwd = prompt_password("Admin password")

    # Collect shares
    shares = []
    info("Enter evaluator shares (type 'done' when finished):")
    while True:
        s = prompt(f"Share #{len(shares)+1} (or 'done')")
        if s.lower() == "done":
            break
        shares.append(s)

    if len(shares) < 2:
        error("Need at least 2 shares to reconstruct the key.")
        return

    try:
        results = admin_mod.open_bids(tender_id, shares, admin_name, admin_pwd)

        if not results:
            warn("No bids found for this tender.")
            return

        section("Decrypted Bids")
        for r in results:
            sig_icon = "✓" if r["signature_valid"] else "✗"
            hash_icon = "✓" if r["hash_valid"] else "✗"
            sig_color = Color.GREEN if r["signature_valid"] else Color.RED
            hash_color = Color.GREEN if r["hash_valid"] else Color.RED

            print(f"  {Color.BOLD}Bidder: {r['bidder']}{Color.RESET}")
            print(f"    Decrypted:  {'Yes' if r['decrypted'] else 'FAILED'}")
            print(f"    Signature:  {sig_color}{sig_icon} {'VALID' if r['signature_valid'] else 'INVALID'}{Color.RESET}")
            print(f"    Hash:       {hash_color}{hash_icon} {'INTACT' if r['hash_valid'] else 'TAMPERED'}{Color.RESET}")
            if r["decrypted"] and isinstance(r["bid_data"], dict):
                print(f"    Amount:     {r['bid_data'].get('bid_amount', '?')}")
                print(f"    Details:    {r['bid_data'].get('details', '?')}")
                print(f"    Timestamp:  {r['bid_data'].get('timestamp', '?')}")
            print()

        success("All bid opening events logged to ledger.")
    except PermissionError as e:
        error(str(e))
    except Exception as e:
        error(f"Failed to open bids: {e}")


def action_verify_ledger():
    section("Ledger Integrity Verification")

    is_valid, errors = verifier_mod.verify_ledger_integrity()
    count = ledger.entry_count()

    info(f"Total entries in ledger: {count}")

    if is_valid:
        success(f"Ledger integrity: VALID ✓  ({count} entries verified)")
    else:
        error(f"Ledger integrity: COMPROMISED ✗  ({len(errors)} error(s))")
        for err in errors:
            print(f"    {Color.RED}✗ {err}{Color.RESET}")


def action_verify_bid():
    section("Verify Bid File")

    # List bid files
    ensure_dirs()
    from .utils import BIDS_DIR
    bid_files = [f for f in os.listdir(BIDS_DIR) if f.endswith(".json")]

    if not bid_files:
        warn("No bid files found.")
        return

    info("Available bid files:")
    for f in bid_files:
        print(f"    {f}")

    filename = prompt("Bid filename (from list above)")
    filepath = os.path.join(BIDS_DIR, filename)

    if not os.path.exists(filepath):
        error(f"File not found: {filepath}")
        return

    try:
        result = verifier_mod.verify_bid_file(filepath)
        print(f"\n  Bidder:      {result['bidder']}")
        print(f"  Tender:      {result['tender_id']}")
        print(f"  Submitted:   {result['submitted_at']}")
        print(f"  Payload hash: {result['payload_hash'][:32]}…")
        print(f"  Bundle hash:  {result['bundle_hash'][:32]}…")
        ledger_icon = "✓" if result["hash_recorded_in_ledger"] else "✗"
        ledger_color = Color.GREEN if result["hash_recorded_in_ledger"] else Color.RED
        print(f"  In ledger:   {ledger_color}{ledger_icon}{Color.RESET}")
    except Exception as e:
        error(f"Verification failed: {e}")


def action_audit_log():
    section("Public Audit Report")
    report = verifier_mod.generate_audit_report()
    print(report)


def action_demo_workflow():
    """Run a fully automated end-to-end demo workflow."""
    section("End-to-End Demo Workflow")
    info("This will automatically run through the entire procurement cycle.\n")

    # Step 1: Register bidders
    print(f"  {bold('STEP 1: Register Bidders')}")
    for name in ["Alice", "Bob", "Charlie"]:
        try:
            result = bidder_mod.register_bidder(name, "demopass")
            success(f"  Registered {result['name']}")
        except ValueError:
            warn(f"  {name} already registered, skipping")

    # Step 1.5: Register Admin
    print(f"\n  {bold('STEP 1.5: Register Admin')}")
    try:
        admin_mod.register_admin("admin_demo", "adminpass")
        success("  Registered admin_demo")
    except ValueError:
        warn("  admin_demo already registered, skipping")

    # Step 2: Create tender with a deadline in the past (for demo)
    print(f"\n  {bold('STEP 2: Create Tender')}")
    past_deadline = (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat()
    tender_result = admin_mod.create_tender(
        title="Office Supplies Procurement 2026",
        deadline_iso=past_deadline,
        num_evaluators=3,
        threshold=2,
        admin_name="admin_demo",
        admin_password="adminpass",
    )
    t = tender_result["tender"]
    success(f"  Tender created: {t['tender_id']}")
    info(f"  Deadline set to past for demo: {t['deadline']}")

    shares = tender_result["shares"]
    for i, s in enumerate(shares):
        trunc = s[:24] + "…"
        info(f"  Share #{i+1}: {trunc}")

    # Step 3: Submit bids
    print(f"\n  {bold('STEP 3: Submit Bids')}")
    bids = [
        ("alice", 45000, "Premium office supplies"),
        ("bob", 42500, "Standard office supplies"),
        ("charlie", 43800, "Eco-friendly office supplies"),
    ]
    for bidder_name, amount, details in bids:
        result = bidder_mod.submit_bid(bidder_name, t["tender_id"], amount, details, "demopass")
        success(f"  {bidder_name} submitted bid: ${amount:,.2f}")
        info(f"    Hash: {result['payload_hash'][:24]}…")

    # Step 4: Verify ledger
    print(f"\n  {bold('STEP 4: Verify Ledger Integrity')}")
    is_valid, errors = verifier_mod.verify_ledger_integrity()
    if is_valid:
        success(f"  Ledger integrity: VALID ✓  ({ledger.entry_count()} entries)")
    else:
        error("  Ledger integrity: COMPROMISED ✗")

    # Step 5: Open bids (using 2-of-3 shares)
    print(f"\n  {bold('STEP 5: Open Bids (2-of-3 Threshold)')}")
    info("  Using shares #1 and #2 to reconstruct master key…")
    results = admin_mod.open_bids(t["tender_id"], [shares[0], shares[1]], "admin_demo", "adminpass")

    for r in results:
        sig = f"{Color.GREEN}✓ VALID{Color.RESET}" if r["signature_valid"] else f"{Color.RED}✗ INVALID{Color.RESET}"
        hsh = f"{Color.GREEN}✓ INTACT{Color.RESET}" if r["hash_valid"] else f"{Color.RED}✗ TAMPERED{Color.RESET}"
        amount = r["bid_data"].get("bid_amount", "?") if r["decrypted"] else "?"
        print(f"    {bold(r['bidder']):20s}  ${amount:>10}  Sig: {sig}  Hash: {hsh}")

    # Step 6: Audit
    print(f"\n  {bold('STEP 6: Full Audit Report')}")
    report = verifier_mod.generate_audit_report()
    print(report)

    success("\n  Demo workflow complete!")
    info("  All cryptographic operations verified successfully.")


# ── Main Loop ────────────────────────────────────────────────────────────────

ACTIONS = {
    "1": action_register_bidder,
    "2": action_register_admin,
    "3": action_create_tender,
    "4": action_submit_bid,
    "5": action_open_bids,
    "6": action_verify_ledger,
    "7": action_verify_bid,
    "8": action_audit_log,
    "9": action_demo_workflow,
}


def main():
    ensure_dirs()

    while True:
        print_menu()
        choice = prompt("Select an option").strip()

        if choice == "0":
            print(f"\n  {dim('Goodbye! Stay secure. 🔒')}\n")
            sys.exit(0)

        action = ACTIONS.get(choice)
        if action:
            try:
                action()
            except KeyboardInterrupt:
                print("\n")
                warn("Action interrupted.")
            except Exception as e:
                error(f"Unexpected error: {e}")
            pause()
        else:
            warn("Invalid option. Try again.")


if __name__ == "__main__":
    main()
=======
"""
CSePS — Main CLI Entry Point
Interactive menu for the Cryptographically Secure e-Procurement System.
"""

import sys
import os
import json
import base64
from datetime import datetime, timezone, timedelta

from .utils import (
    header, section, info, success, warn, error, dim, bold,
    Color, ensure_dirs,
)
from . import bidder as bidder_mod
from . import admin as admin_mod
from . import verifier as verifier_mod
from . import ledger
from .threshold import reconstruct_key


# ── Helpers ──────────────────────────────────────────────────────────────────

def prompt(msg: str, default: str = "") -> str:
    """Prompt user for input with optional default."""
    suffix = f" [{default}]" if default else ""
    val = input(f"  {Color.YELLOW}>{Color.RESET} {msg}{suffix}: ").strip()
    return val if val else default


def confirm(msg: str) -> bool:
    return prompt(f"{msg} (y/n)", "y").lower() in ("y", "yes")


def pause():
    input(f"\n  {dim('Press Enter to continue...')}")


def print_menu():
    header("CSePS — Secure e-Procurement System")
    options = [
        ("1", "Register as Bidder"),
        ("2", "Create New Tender               (Admin)"),
        ("3", "Submit a Bid"),
        ("4", "Open Bids After Deadline         (Admin)"),
        ("5", "Verify Ledger Integrity"),
        ("6", "Verify a Bid File"),
        ("7", "View Audit Log"),
        ("8", "Demo: Full End-to-End Workflow"),
        ("0", "Exit"),
    ]
    for num, label in options:
        print(f"    {Color.BOLD}{Color.CYAN}{num}{Color.RESET}  {label}")
    print()


# ── Menu Actions ─────────────────────────────────────────────────────────────

def action_register_bidder():
    section("Bidder Registration")
    name = prompt("Enter bidder name")
    if not name:
        error("Name cannot be empty.")
        return

    try:
        result = bidder_mod.register_bidder(name)
        success(f"Bidder '{result['name']}' registered successfully!")
        info(f"Private key: {result['private_key_path']}")
        info(f"Public key:  {result['public_key_path']}")
        info("Registered event logged to ledger.")
    except ValueError as e:
        warn(str(e))
    except Exception as e:
        error(f"Registration failed: {e}")


def action_create_tender():
    section("Create New Tender")
    title = prompt("Tender title")
    if not title:
        error("Title cannot be empty.")
        return

    # Default deadline: 1 minute from now (for demo purposes)
    default_dl = (datetime.now(timezone.utc) + timedelta(minutes=1)).strftime("%Y-%m-%dT%H:%M:%S+00:00")
    deadline_str = prompt("Deadline (ISO format)", default_dl)

    num_eval = int(prompt("Number of evaluators", "3"))
    thresh = int(prompt("Threshold (min shares to open)", "2"))

    try:
        result = admin_mod.create_tender(title, deadline_str, num_eval, thresh)
        t = result["tender"]

        success(f"Tender created: {t['tender_id']}")
        info(f"Title:      {t['title']}")
        info(f"Deadline:   {t['deadline']}")
        info(f"Evaluators: {t['num_evaluators']} (threshold: {t['threshold']})")

        section("Evaluator Key Shares (DISTRIBUTE SECURELY)")
        print(f"  {Color.RED}{Color.BOLD}⚠  These shares are shown ONCE. Save them!{Color.RESET}\n")
        for i, share in enumerate(result["shares"]):
            print(f"    Share #{i+1}: {Color.GREEN}{share}{Color.RESET}")

        print(f"\n  {dim('Master key (demo only): ' + result['master_key_hex'])}")

        info("Tender creation logged to ledger.")
    except Exception as e:
        error(f"Failed to create tender: {e}")


def action_submit_bid():
    section("Submit a Bid")

    # List available bidders
    bidders = bidder_mod.list_bidders()
    if not bidders:
        warn("No bidders registered yet. Register first (option 1).")
        return
    info(f"Registered bidders: {', '.join(bidders)}")
    bidder_name = prompt("Your bidder name")

    # List available tenders
    tenders = admin_mod.list_tenders()
    if not tenders:
        warn("No tenders available. Create one first (option 2).")
        return
    info("Available tenders:")
    for t in tenders:
        status_color = Color.GREEN if t["status"] == "OPEN" else Color.RED
        print(f"    {t['tender_id']}  {t['title']}  [{status_color}{t['status']}{Color.RESET}]")

    tender_id = prompt("Tender ID")
    bid_amount = float(prompt("Bid amount (numeric)"))
    details = prompt("Bid details/description", "Standard bid submission")

    # Get master key (in real system, bidder wouldn't have this — they'd encrypt to evaluators' keys)
    # For this prototype demo, we pass the master key directly
    master_key_hex = prompt("Master key (hex, from tender creation)")
    try:
        master_key = bytes.fromhex(master_key_hex)
    except ValueError:
        error("Invalid master key hex string.")
        return

    try:
        result = bidder_mod.submit_bid(bidder_name, tender_id, bid_amount, details, master_key)
        success("Bid submitted successfully!")
        info(f"Bid file:     {result['bid_file']}")
        info(f"Bundle hash:  {result['bundle_hash'][:32]}…")
        info(f"Payload hash: {result['payload_hash'][:32]}…")
        info("Submission logged to ledger with hash + timestamp.")
    except Exception as e:
        error(f"Submission failed: {e}")


def action_open_bids():
    section("Open Bids (Post-Deadline)")

    tenders = admin_mod.list_tenders()
    if not tenders:
        warn("No tenders available.")
        return

    info("Available tenders:")
    for t in tenders:
        dl = t["deadline"]
        passed = admin_mod.is_deadline_passed(t)
        status = f"{Color.GREEN}DEADLINE PASSED ✓{Color.RESET}" if passed else f"{Color.RED}STILL OPEN{Color.RESET}"
        print(f"    {t['tender_id']}  {t['title']}  [{status}]")

    tender_id = prompt("Tender ID to open")

    # Collect shares
    shares = []
    info("Enter evaluator shares (type 'done' when finished):")
    while True:
        s = prompt(f"Share #{len(shares)+1} (or 'done')")
        if s.lower() == "done":
            break
        shares.append(s)

    if len(shares) < 2:
        error("Need at least 2 shares to reconstruct the key.")
        return

    try:
        results = admin_mod.open_bids(tender_id, shares)

        if not results:
            warn("No bids found for this tender.")
            return

        section("Decrypted Bids")
        for r in results:
            sig_icon = "✓" if r["signature_valid"] else "✗"
            hash_icon = "✓" if r["hash_valid"] else "✗"
            sig_color = Color.GREEN if r["signature_valid"] else Color.RED
            hash_color = Color.GREEN if r["hash_valid"] else Color.RED

            print(f"  {Color.BOLD}Bidder: {r['bidder']}{Color.RESET}")
            print(f"    Decrypted:  {'Yes' if r['decrypted'] else 'FAILED'}")
            print(f"    Signature:  {sig_color}{sig_icon} {'VALID' if r['signature_valid'] else 'INVALID'}{Color.RESET}")
            print(f"    Hash:       {hash_color}{hash_icon} {'INTACT' if r['hash_valid'] else 'TAMPERED'}{Color.RESET}")
            if r["decrypted"] and isinstance(r["bid_data"], dict):
                print(f"    Amount:     {r['bid_data'].get('bid_amount', '?')}")
                print(f"    Details:    {r['bid_data'].get('details', '?')}")
                print(f"    Timestamp:  {r['bid_data'].get('timestamp', '?')}")
            print()

        success("All bid opening events logged to ledger.")
    except PermissionError as e:
        error(str(e))
    except Exception as e:
        error(f"Failed to open bids: {e}")


def action_verify_ledger():
    section("Ledger Integrity Verification")

    is_valid, errors = verifier_mod.verify_ledger_integrity()
    count = ledger.entry_count()

    info(f"Total entries in ledger: {count}")

    if is_valid:
        success(f"Ledger integrity: VALID ✓  ({count} entries verified)")
    else:
        error(f"Ledger integrity: COMPROMISED ✗  ({len(errors)} error(s))")
        for err in errors:
            print(f"    {Color.RED}✗ {err}{Color.RESET}")


def action_verify_bid():
    section("Verify Bid File")

    # List bid files
    ensure_dirs()
    from .utils import BIDS_DIR
    bid_files = [f for f in os.listdir(BIDS_DIR) if f.endswith(".json")]

    if not bid_files:
        warn("No bid files found.")
        return

    info("Available bid files:")
    for f in bid_files:
        print(f"    {f}")

    filename = prompt("Bid filename (from list above)")
    filepath = os.path.join(BIDS_DIR, filename)

    if not os.path.exists(filepath):
        error(f"File not found: {filepath}")
        return

    try:
        result = verifier_mod.verify_bid_file(filepath)
        print(f"\n  Bidder:      {result['bidder']}")
        print(f"  Tender:      {result['tender_id']}")
        print(f"  Submitted:   {result['submitted_at']}")
        print(f"  Payload hash: {result['payload_hash'][:32]}…")
        print(f"  Bundle hash:  {result['bundle_hash'][:32]}…")
        ledger_icon = "✓" if result["hash_recorded_in_ledger"] else "✗"
        ledger_color = Color.GREEN if result["hash_recorded_in_ledger"] else Color.RED
        print(f"  In ledger:   {ledger_color}{ledger_icon}{Color.RESET}")
    except Exception as e:
        error(f"Verification failed: {e}")


def action_audit_log():
    section("Public Audit Report")
    report = verifier_mod.generate_audit_report()
    print(report)


def action_demo_workflow():
    """Run a fully automated end-to-end demo workflow."""
    section("End-to-End Demo Workflow")
    info("This will automatically run through the entire procurement cycle.\n")

    # Step 1: Register bidders
    print(f"  {bold('STEP 1: Register Bidders')}")
    for name in ["Alice", "Bob", "Charlie"]:
        try:
            result = bidder_mod.register_bidder(name)
            success(f"  Registered {result['name']}")
        except ValueError:
            warn(f"  {name} already registered, skipping")

    # Step 2: Create tender with a deadline in the past (for demo)
    print(f"\n  {bold('STEP 2: Create Tender')}")
    past_deadline = (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat()
    tender_result = admin_mod.create_tender(
        title="Office Supplies Procurement 2026",
        deadline_iso=past_deadline,
        num_evaluators=3,
        threshold=2,
    )
    t = tender_result["tender"]
    success(f"  Tender created: {t['tender_id']}")
    info(f"  Deadline set to past for demo: {t['deadline']}")

    shares = tender_result["shares"]
    master_key = bytes.fromhex(tender_result["master_key_hex"])
    for i, s in enumerate(shares):
        trunc = s[:24] + "…"
        info(f"  Share #{i+1}: {trunc}")

    # Step 3: Submit bids
    print(f"\n  {bold('STEP 3: Submit Bids')}")
    bids = [
        ("alice", 45000, "Premium office supplies"),
        ("bob", 42500, "Standard office supplies"),
        ("charlie", 43800, "Eco-friendly office supplies"),
    ]
    for bidder_name, amount, details in bids:
        result = bidder_mod.submit_bid(bidder_name, t["tender_id"], amount, details, master_key)
        success(f"  {bidder_name} submitted bid: ${amount:,.2f}")
        info(f"    Hash: {result['payload_hash'][:24]}…")

    # Step 4: Verify ledger
    print(f"\n  {bold('STEP 4: Verify Ledger Integrity')}")
    is_valid, errors = verifier_mod.verify_ledger_integrity()
    if is_valid:
        success(f"  Ledger integrity: VALID ✓  ({ledger.entry_count()} entries)")
    else:
        error("  Ledger integrity: COMPROMISED ✗")

    # Step 5: Open bids (using 2-of-3 shares)
    print(f"\n  {bold('STEP 5: Open Bids (2-of-3 Threshold)')}")
    info("  Using shares #1 and #2 to reconstruct master key…")
    results = admin_mod.open_bids(t["tender_id"], [shares[0], shares[1]])

    for r in results:
        sig = f"{Color.GREEN}✓ VALID{Color.RESET}" if r["signature_valid"] else f"{Color.RED}✗ INVALID{Color.RESET}"
        hsh = f"{Color.GREEN}✓ INTACT{Color.RESET}" if r["hash_valid"] else f"{Color.RED}✗ TAMPERED{Color.RESET}"
        amount = r["bid_data"].get("bid_amount", "?") if r["decrypted"] else "?"
        print(f"    {bold(r['bidder']):20s}  ${amount:>10}  Sig: {sig}  Hash: {hsh}")

    # Step 6: Audit
    print(f"\n  {bold('STEP 6: Full Audit Report')}")
    report = verifier_mod.generate_audit_report()
    print(report)

    success("\n  Demo workflow complete!")
    info("  All cryptographic operations verified successfully.")


# ── Main Loop ────────────────────────────────────────────────────────────────

ACTIONS = {
    "1": action_register_bidder,
    "2": action_create_tender,
    "3": action_submit_bid,
    "4": action_open_bids,
    "5": action_verify_ledger,
    "6": action_verify_bid,
    "7": action_audit_log,
    "8": action_demo_workflow,
}


def main():
    ensure_dirs()

    while True:
        print_menu()
        choice = prompt("Select an option").strip()

        if choice == "0":
            print(f"\n  {dim('Goodbye! Stay secure. 🔒')}\n")
            sys.exit(0)

        action = ACTIONS.get(choice)
        if action:
            try:
                action()
            except KeyboardInterrupt:
                print("\n")
                warn("Action interrupted.")
            except Exception as e:
                error(f"Unexpected error: {e}")
            pause()
        else:
            warn("Invalid option. Try again.")


if __name__ == "__main__":
    main()
>>>>>>> 3f9933bcf52c44ef351885c43cf19f66d0167f0f
