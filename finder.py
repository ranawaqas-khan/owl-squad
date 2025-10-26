from verifier import verify_email
import time

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


def generate_generic_patterns(domain):
    prefixes = ["info", "support", "contact", "help", "sales", "team", "hello", "hi", "admin"]
    return [f"{p}@{domain}" for p in prefixes]


def find_valid_email(first, last, domain):
    all_candidates = generate_person_patterns(first, last, domain) + generate_generic_patterns(domain)
    debug_log = []

    for email in all_candidates:
        res = verify_email(email)
        debug_log.append(res)
        print(f"🔍 Testing {email} → {res['status']} | catch_all={res['details'].get('is_catch_all')}")

        if res["deliverable"] and not res["details"].get("is_catch_all"):
            print(f"✅ Found valid: {email}")
            return {
                "status": "found",
                "valid": True,
                "email": email,
                "mx_provider": res.get("mx_provider"),
                "reason": res["details"].get("reasoning"),
                "debug": debug_log
            }

        time.sleep(0.2)  # Prevent SMTP flood

    # If nothing found
    return {
        "status": "not_found",
        "valid": False,
        "email": None,
        "debug": debug_log
    }
