<<<<<<< HEAD
"""
CSePS — Utility helpers: timestamps, colored output, file I/O.
"""

import json
import os
from datetime import datetime, timezone

# ── Paths ────────────────────────────────────────────────────────────────────

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(BASE_DIR, "data")
KEYS_DIR = os.path.join(DATA_DIR, "keys")
BIDS_DIR = os.path.join(DATA_DIR, "bids")
TENDERS_DIR = os.path.join(DATA_DIR, "tenders")
LEDGER_FILE = os.path.join(DATA_DIR, "ledger.json")


def ensure_dirs():
    """Create data directories if they don't exist."""
    for d in [DATA_DIR, KEYS_DIR, BIDS_DIR, TENDERS_DIR]:
        os.makedirs(d, exist_ok=True)


# ── Timestamps ───────────────────────────────────────────────────────────────

def utc_now_iso() -> str:
    """Return current UTC time as ISO-8601 string."""
    return datetime.now(timezone.utc).isoformat()


def parse_iso(iso_str: str) -> datetime:
    """Parse an ISO-8601 timestamp string."""
    return datetime.fromisoformat(iso_str)


# ── JSON helpers ─────────────────────────────────────────────────────────────

def read_json(path: str) -> dict | list:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def write_json(path: str, data):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


# ── Colored terminal output ─────────────────────────────────────────────────

class Color:
    RESET  = "\033[0m"
    BOLD   = "\033[1m"
    RED    = "\033[91m"
    GREEN  = "\033[92m"
    YELLOW = "\033[93m"
    BLUE   = "\033[94m"
    CYAN   = "\033[96m"
    MAGENTA = "\033[95m"
    GRAY   = "\033[90m"


def info(msg: str):
    print(f"{Color.CYAN}[INFO]{Color.RESET}  {msg}")


def success(msg: str):
    print(f"{Color.GREEN}[  OK ]{Color.RESET}  {msg}")


def warn(msg: str):
    print(f"{Color.YELLOW}[WARN]{Color.RESET}  {msg}")


def error(msg: str):
    print(f"{Color.RED}[FAIL]{Color.RESET}  {msg}")


def header(title: str):
    width = 56
    print()
    print(f"{Color.BOLD}{Color.BLUE}╔{'═' * width}╗{Color.RESET}")
    print(f"{Color.BOLD}{Color.BLUE}║{Color.CYAN}  {title:^{width - 2}}  {Color.BLUE}║{Color.RESET}")
    print(f"{Color.BOLD}{Color.BLUE}╚{'═' * width}╝{Color.RESET}")
    print()


def section(title: str):
    print(f"\n{Color.BOLD}{Color.MAGENTA}── {title} {'─' * (50 - len(title))}{Color.RESET}\n")


def dim(msg: str) -> str:
    return f"{Color.GRAY}{msg}{Color.RESET}"


def bold(msg: str) -> str:
    return f"{Color.BOLD}{msg}{Color.RESET}"
=======
"""
CSePS — Utility helpers: timestamps, colored output, file I/O.
"""

import json
import os
from datetime import datetime, timezone

# ── Paths ────────────────────────────────────────────────────────────────────

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(BASE_DIR, "data")
KEYS_DIR = os.path.join(DATA_DIR, "keys")
BIDS_DIR = os.path.join(DATA_DIR, "bids")
TENDERS_DIR = os.path.join(DATA_DIR, "tenders")
LEDGER_FILE = os.path.join(DATA_DIR, "ledger.json")


def ensure_dirs():
    """Create data directories if they don't exist."""
    for d in [DATA_DIR, KEYS_DIR, BIDS_DIR, TENDERS_DIR]:
        os.makedirs(d, exist_ok=True)


# ── Timestamps ───────────────────────────────────────────────────────────────

def utc_now_iso() -> str:
    """Return current UTC time as ISO-8601 string."""
    return datetime.now(timezone.utc).isoformat()


def parse_iso(iso_str: str) -> datetime:
    """Parse an ISO-8601 timestamp string."""
    return datetime.fromisoformat(iso_str)


# ── JSON helpers ─────────────────────────────────────────────────────────────

def read_json(path: str) -> dict | list:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def write_json(path: str, data):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


# ── Colored terminal output ─────────────────────────────────────────────────

class Color:
    RESET  = "\033[0m"
    BOLD   = "\033[1m"
    RED    = "\033[91m"
    GREEN  = "\033[92m"
    YELLOW = "\033[93m"
    BLUE   = "\033[94m"
    CYAN   = "\033[96m"
    MAGENTA = "\033[95m"
    GRAY   = "\033[90m"


def info(msg: str):
    print(f"{Color.CYAN}[INFO]{Color.RESET}  {msg}")


def success(msg: str):
    print(f"{Color.GREEN}[  OK ]{Color.RESET}  {msg}")


def warn(msg: str):
    print(f"{Color.YELLOW}[WARN]{Color.RESET}  {msg}")


def error(msg: str):
    print(f"{Color.RED}[FAIL]{Color.RESET}  {msg}")


def header(title: str):
    width = 56
    print()
    print(f"{Color.BOLD}{Color.BLUE}╔{'═' * width}╗{Color.RESET}")
    print(f"{Color.BOLD}{Color.BLUE}║{Color.CYAN}  {title:^{width - 2}}  {Color.BLUE}║{Color.RESET}")
    print(f"{Color.BOLD}{Color.BLUE}╚{'═' * width}╝{Color.RESET}")
    print()


def section(title: str):
    print(f"\n{Color.BOLD}{Color.MAGENTA}── {title} {'─' * (50 - len(title))}{Color.RESET}\n")


def dim(msg: str) -> str:
    return f"{Color.GRAY}{msg}{Color.RESET}"


def bold(msg: str) -> str:
    return f"{Color.BOLD}{msg}{Color.RESET}"
>>>>>>> 3f9933bcf52c44ef351885c43cf19f66d0167f0f
