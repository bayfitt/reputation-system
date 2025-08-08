from dataclasses import dataclass, asdict
from typing import List, Optional
import json
import hashlib
import os

import hashlib

SK_PREFIX = "SK"
PK_PREFIX = "PK"
CHECKSUM_LENGTH = 4

def checksum(hex_str: str) -> str:
    h = hashlib.sha256(bytes.fromhex(hex_str.lower())).hexdigest()
    return h[:CHECKSUM_LENGTH]

def add_prefix_and_checksum(prefix: str, hex_key: str) -> str:
    cksum = checksum(hex_key)
    return prefix + hex_key + cksum

def validate_key_with_checksum(key_str: str, expected_prefix: str) -> bool:
    if not key_str.startswith(expected_prefix):
        print(f"Prefix mismatch: expected {expected_prefix}, got {key_str[:len(expected_prefix)]}")
        return False
    core_len = len(key_str) - len(expected_prefix) - CHECKSUM_LENGTH
    core = key_str[len(expected_prefix):len(expected_prefix)+core_len].lower()
    cksum = key_str[-CHECKSUM_LENGTH:].lower()
    computed_cksum = checksum(core)
    return computed_cksum == cksum

def generate_secret_key() -> str:
    import secrets
    raw = secrets.token_hex(32)
    return add_prefix_and_checksum(SK_PREFIX, raw)

def derive_pubkey_from_secret(secret_key: str) -> str:
    if not validate_key_with_checksum(secret_key, SK_PREFIX):
        raise ValueError("Invalid secret key prefix or checksum")
    raw_secret = secret_key[len(SK_PREFIX):-CHECKSUM_LENGTH]
    private_bytes = bytes.fromhex(raw_secret)
    pubkey_hash = hashlib.sha256(private_bytes).hexdigest()
    pubkey_raw = "03" + pubkey_hash[:64]
    return add_prefix_and_checksum(PK_PREFIX, pubkey_raw)

REPORTS_FILE = os.path.expanduser("~/Documents/reports.json")

@dataclass
class Report:
    report_type: str  # "positive" or "negative"
    fee_btc: float
    message: Optional[str]
    reporter_pubkey: str
    target_pubkey: str  # The pubkey of the person being reported on
    reporter_alias: Optional[str] = None

    def to_dict(self):
        return asdict(self)

@dataclass
class ReputationProfile:
    pubkey: str
    alias: Optional[str]
    reports: List[Report]

    def summary(self):
        pos_count = sum(1 for r in self.reports if r.report_type == "positive")
        neg_count = sum(1 for r in self.reports if r.report_type == "negative")
        pos_total = sum(r.fee_btc for r in self.reports if r.report_type == "positive")
        neg_total = sum(r.fee_btc for r in self.reports if r.report_type == "negative")

        print(f"\nReputation Report for PubKey: {self.pubkey}")
        if self.alias:
            print(f"Alias: {self.alias}")
        print(f"\nPositive Reports: {pos_count} (₿{pos_total:.4f})")
        print(f"Negative Reports: {neg_count} (₿{neg_total:.4f})")

    def list_reports(self):
        print("\n--- All Reports ---")
        # helper function to shorten pubkey
        def shorten_pubkey(pubkey: str) -> str:
            return f"{pubkey[:6]}...{pubkey[-6:]}"
        # Sort: self-assigned "name" reports come first, sorted by descending fee
        def report_sort_key(r):
            # Self-assigned "name" reports come first, sorted by descending fee
            if r.report_type == "name" and r.reporter_pubkey == r.target_pubkey:
                return (0, -r.fee_btc)
            # All other reports sorted by descending fee
            else:
                return (1, -r.fee_btc)
        sorted_reports = sorted(self.reports, key=report_sort_key)
        for i, r in enumerate(sorted_reports, start=1):
            if r.report_type == "name":
                indicator = "[N]"
                if r.reporter_pubkey == r.target_pubkey:
                    indicator += "[*SELF*]"
            elif r.report_type == "positive":
                indicator = "[+]"
            else:
                indicator = "[-]"

            reporter = r.reporter_alias if r.reporter_alias else shorten_pubkey(r.reporter_pubkey)
            target = shorten_pubkey(r.target_pubkey)
            msg = f' "{r.message}"' if r.message else ""
            timestamp = getattr(r, "timestamp", None)
            if timestamp is not None:
                print(f"{i}. {indicator}{msg} - ₿{r.fee_btc:.4f} (from {reporter} → {target}) [{timestamp}]")
            else:
                print(f"{i}. {indicator}{msg} - ₿{r.fee_btc:.4f} (from {reporter} → {target})")
        # Calculate and print total positive and negative fees from sorted_reports
        total_positive = sum(r.fee_btc for r in sorted_reports if r.report_type == "positive")
        total_negative = sum(r.fee_btc for r in sorted_reports if r.report_type == "negative")
        print(f"\nTotal Positive Fees: ₿{total_positive:.4f}")
        print(f"Total Negative Fees: ₿{total_negative:.4f}")

def prompt_fee_and_confirm() -> float:
    while True:
        fee_input = input("Enter fee (BTC): ").strip()
        try:
            fee_btc = float(fee_input)
        except ValueError:
            print("Invalid fee format.")
            continue
        print(f"Fee: ₿{fee_btc:.4f}")
        print("Proceed?")
        print("1. Yes")
        print("2. No")
        print("3. Back")
        confirm = ""
        while confirm not in ("1", "2", "3"):
            confirm = input("Choose 1, 2 or 3: ").strip()
        if confirm == "3":
            return None
        if confirm == "1":
            return fee_btc
        else:
            print("Re-enter fee.")

def create_report_from_input_with_fee(reporter_pubkey: str, reporter_alias: Optional[str]) -> Optional[Report]:
    while True:
        target_pubkey = input("Enter target pubkey: ").strip()
        if validate_key_with_checksum(target_pubkey, PK_PREFIX):
            break
        else:
            print("Invalid target pubkey format or checksum.")

    print("Select report type:")
    print("1. Positive")
    print("2. Negative")
    print("3. Back")
    report_type_choice = ""
    while report_type_choice not in ("1", "2", "3"):
        report_type_choice = input("Choose 1, 2 or 3: ").strip()
    if report_type_choice == "3":
        return None
    report_type = "positive" if report_type_choice == "1" else "negative"

    message = input("Enter message (optional): ").strip()
    if message == "":
        message = None

    while True:
        fee_input = input("Enter fee (BTC): ").strip()
        try:
            fee_btc = float(fee_input)
            if fee_btc <= 0:
                print("Fee must be positive.")
                continue
        except ValueError:
            print("Invalid fee format.")
            continue

        print(f"\nTotal fee: ₿{fee_btc:.8f}")
        print("Proceed?")
        print("1. Yes")
        print("2. No")
        print("3. Back")
        confirm = ""
        while confirm not in ("1", "2", "3"):
            confirm = input("Choose 1, 2 or 3: ").strip()

        if confirm == "3":
            return None
        if confirm == "1":
            break
        else:
            print("Re-enter fee?")
            print("1. Yes")
            print("2. No")
            print("3. Back")
            retry = ""
            while retry not in ("1", "2", "3"):
                retry = input("Choose 1, 2 or 3: ").strip()
            if retry == "3":
                return None
            if retry == "2":
                print("Transaction cancelled.")
                return None

    return Report(
        report_type=report_type,
        fee_btc=fee_btc,
        message=message,
        reporter_pubkey=reporter_pubkey,
        target_pubkey=target_pubkey,
        reporter_alias=reporter_alias
    )

def load_all_reports() -> dict:
    if os.path.exists(REPORTS_FILE):
        with open(REPORTS_FILE, "r") as f:
            data = json.load(f)
        return {
            pubkey: [Report(**{**r, 'target_pubkey': r.get('target_pubkey', None)}) for r in reports]
            for pubkey, reports in data.items()
        }
    return {}

def save_all_reports(all_reports: dict):
    to_save = {
        pubkey: [r.to_dict() for r in reports]
        for pubkey, reports in all_reports.items()
    }
    with open(REPORTS_FILE, "w") as f:
        json.dump(to_save, f, indent=2)

def main():
    print("Reputation System")

    all_reports = load_all_reports()

    while True:
        print("\nOptions:")
        print("1. File a report")
        print("2. View reports")
        print("3. Back")

        choice = ""
        while choice not in ("1", "2", "3"):
            choice = input("Choose 1, 2 or 3: ").strip()

        if choice == "3":
            print("Exiting program.")
            break

        elif choice == "2":
            # View reports by pubkey
            pubkey = input("Enter pubkey: ").strip()
            reports = all_reports.get(pubkey, [])
            if not reports:
                print("No reports found for that pubkey.")
            else:
                profile = ReputationProfile(pubkey=pubkey, alias=None, reports=reports)
                profile.summary()
                profile.list_reports()
            # Loop back to main menu

        elif choice == "1":
            # File report flow
            while True:
                print("\nFile a report:")
                print("1. Generate new secret key")
                print("2. Input existing secret key")
                print("3. Back")

                sk_choice = ""
                while sk_choice not in ("1", "2", "3"):
                    sk_choice = input("Choose 1, 2 or 3: ").strip()

                if sk_choice == "3":
                    break

                if sk_choice == "1":
                    secret_key = generate_secret_key()
                    print(f"Generated secret key: {secret_key}")
                    print("Save this secret key. It will not be shown again.")
                else:
                    secret_key = input("Enter secret key: ").strip()
                    while not validate_key_with_checksum(secret_key, SK_PREFIX):
                        print("Invalid secret key prefix or checksum.")
                        secret_key = input("Enter secret key: ").strip()

                try:
                    pubkey = derive_pubkey_from_secret(secret_key)
                except ValueError as e:
                    print(str(e))
                    continue
                print(f"Derived PubKey: {pubkey}")

                my_reports = all_reports.get(pubkey, [])
                profile = ReputationProfile(pubkey=pubkey, alias=None, reports=my_reports)

                while True:
                    print("\nCreate a new report:")
                    new_report = create_report_from_input_with_fee(profile.pubkey, profile.alias)
                    if new_report is None:
                        break
                    profile.reports.append(new_report)
                    all_reports[pubkey] = profile.reports

                    profile.summary()
                    profile.list_reports()

                    save_all_reports(all_reports)

                    print("\nFile another report?")
                    print("1. Yes")
                    print("2. No")
                    print("3. Back")
                    cont = ""
                    while cont not in ("1", "2", "3"):
                        cont = input("Choose 1, 2 or 3: ").strip()
                    if cont in ("2", "3"):
                        break
                # after finishing filing reports, go back to main menu

if __name__ == "__main__":
    main()