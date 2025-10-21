from verifier import verify_email
import concurrent.futures

# ============================
# PERSON-BASED PATTERNS
# ============================
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
    return list(dict.fromkeys(patterns))  # dedup


# ============================
# GENERIC COMPANY EMAILS
# ============================
def generate_generic_patterns(domain):
    generic_prefixes = ["info", "support", "contact", "help", "hi", "hello", "team", "sales", "admin"]
    return [f"{p}@{domain}" for p in generic_prefixes]


# ============================
# VERIFY CANDIDATES
# ============================
def verify_candidates(emails, max_workers=10):
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(verify_email, e): e for e in emails}
        for f in concurrent.futures.as_completed(futures):
            res = f.result()
            if res.get("deliverable") and not res["details"].get("is_catch_all"):
                return res
    return None


# ============================
# MAIN FINDER
# ============================
def find_valid_email(first, last, domain, max_workers=10):
    # 1️⃣ Try person-based patterns
    person_emails = generate_person_patterns(first, last, domain)
    found = verify_candidates(person_emails, max_workers)

    # 2️⃣ If not found → fallback to generic
    if not found:
        generic_emails = generate_generic_patterns(domain)
        found = verify_candidates(generic_emails, max_workers)

    return found
