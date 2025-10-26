from verifier import verify_batch
import re, logging, sys

# ---------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------
logging.basicConfig(
    stream=sys.stdout,
    level=logging.DEBUG,
    format="%(asctime)s [%(levelname)s] %(message)s"
)

# ---------------------------------------------------------------------
# Pattern Generators
# ---------------------------------------------------------------------
def generate_person_patterns(first, last, domain):
    f, l = first.lower().strip(), last.lower().strip()
    patterns = [
        f"{f}@{domain}",
        f"{l}@{domain}",
        f"{f}{l}@{domain}",
        f"{f}.{l}@{domain}",
        f"{f}_{l}@{domain}",
        f"{f}-{l}@{domain}",
        f"{f[0]}{l}@{domain}",
        f"{f[0]}.{l}@{domain}",
        f"{l}{f[0]}@{domain}",
        f"{l}.{f[0]}@{domain}",
        f"{f}{l[0]}@{domain}",
        f"{f}.{l[0]}@{domain}",
        f"{f[0]}{l[0]}@{domain}"
    ]
    return list(dict.fromkeys(patterns))  # deduplicate


def generate_generic_patterns(domain):
    prefixes = ["info", "support", "contact", "help", "sales", "team", "hello", "hi", "admin"]
    return [f"{p}@{domain}" for p in prefixes]


# ---------------------------------------------------------------------
# Finder Logic
# ---------------------------------------------------------------------
def find_valid_email(first, last, domain):
    """
    Generates person + generic patterns, verifies all with timing analysis,
    and returns best candidate (plus full diagnostic info).
    """
    domain = domain.strip().lower()
    if not re.match(r"^[A-Za-z0-9.-]+\.[A-Za-z]{2,}$", domain):
        return {"status": "invalid_domain", "valid": False, "email": None}

    # 1️⃣ Generate candidates
    person_emails = generate_person_patterns(first, last, domain)
    generic_emails = generate_generic_patterns(domain)
    all_candidates = person_emails + generic_emails

    logging.info(f"🧩 Generated {len(all_candidates)} patterns for {first} {last} @ {domain}")

    # 2️⃣ Verify all in batch using verifier logic
    batch = verify_batch(all_candidates)
    results = batch["results"]
    chosen = batch["chosen"]

    # 3️⃣ Prepare debug data
    debug_info = [
        {
            "email": r["email"],
            "code": r.get("smtp_code"),
            "latency": r.get("latency"),
            "deliverable": r.get("deliverable"),
            "reason": r.get("reason"),
            "mx": r.get("mx")
        }
        for r in results
    ]

    # 4️⃣ Decision
    if chosen:
        found = {
            "status": "found",
            "valid": True,
            "email": chosen["email"],
            "smtp_code": chosen.get("smtp_code"),
            "latency": chosen.get("latency"),
            "reason": chosen.get("reason"),
            "mx": chosen.get("mx"),
            "debug": debug_info
        }
        logging.info(f"✅ Found probable valid email: {chosen['email']}")
        return found

    # 5️⃣ Fallback
    logging.warning("❌ No valid or likely candidate found.")
    return {
        "status": "not_found",
        "valid": False,
        "email": None,
        "debug": debug_info
    }
