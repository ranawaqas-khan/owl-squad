import re, dns.resolver, smtplib, random, string, time
from statistics import mean

# ============================
# CONFIGURATION
# ============================
EMAIL_REGEX = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")
TIMEOUT = 5
FAKE_PROBES = 3      # how many fake addresses to test alongside real
PAUSE_BETWEEN = 0.1  # seconds between probes

FREE_PROVIDERS = {
    "gmail.com", "yahoo.com", "outlook.com", "hotmail.com",
    "icloud.com", "aol.com", "zoho.com", "yandex.com"
}
DISPOSABLE_PROVIDERS = {
    "tempmail.com", "mailinator.com", "guerrillamail.com", "10minutemail.com"
}
ROLE_PREFIXES = {"info", "admin", "sales", "support", "contact", "hr", "help", "team", "hello"}


# ============================
# HELPER UTILITIES
# ============================
def random_local(k=8):
    """Generate random local-part for fake probes."""
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=k))


def detect_mx_provider(mx_host: str) -> str:
    """Detects email provider by MX hostname."""
    h = mx_host.lower()
    if "google" in h or "aspmx" in h:
        return "google"
    if "outlook" in h or "protection" in h:
        return "microsoft365"
    if "pphosted" in h:
        return "proofpoint"
    if "mimecast" in h:
        return "mimecast"
    if "barracuda" in h:
        return "barracuda"
    if "secureserver" in h:
        return "godaddy"
    if "zoho" in h:
        return "zoho"
    return "unknown"


def classify_email(local: str, domain: str):
    d = domain.lower()
    if d in FREE_PROVIDERS:
        return "free"
    if any(d.endswith(dp) for dp in DISPOSABLE_PROVIDERS):
        return "disposable"
    if any(local.lower().startswith(p) for p in ROLE_PREFIXES):
        return "role"
    if d.endswith(".gov") or d.endswith(".gov.pk"):
        return "government"
    return "business"


# ============================
# SMTP MULTI-PROBE TEST
# ============================
def smtp_probe(mx_host: str, target_email: str):
    """
    Sends FAKE_PROBES + REAL address to detect catch-all and timing variance.
    """
    domain = target_email.split("@")[1]
    sequence = [f"{random_local()}@{domain}" for _ in range(FAKE_PROBES // 2)]
    sequence.insert(len(sequence)//2, target_email)
    while len(sequence) < FAKE_PROBES + 1:
        sequence.append(f"{random_local()}@{domain}")

    results = []

    try:
        server = smtplib.SMTP(timeout=TIMEOUT)
        server.connect(mx_host)
        server.helo("gmail.com")
        server.mail("probe@bounso.com")

        for addr in sequence:
            start = time.perf_counter()
            try:
                code, msg = server.rcpt(addr)
            except Exception as e:
                code, msg = None, str(e)
            latency = round((time.perf_counter() - start) * 1000, 2)
            msg = msg.decode() if isinstance(msg, bytes) else str(msg)
            results.append((addr, code, msg, latency))
            time.sleep(PAUSE_BETWEEN)

        server.quit()

    except Exception as e:
        results.append(("__connect__", None, f"connect_error:{e}", None))

    return results


# ============================
# CATCH-ALL & TIMING ANALYSIS
# ============================
def analyze_probes(sequence):
    """
    Analyze SMTP responses for catch-all detection.
    """
    codes = [c for _, c, _, _ in sequence if c is not None]
    messages = [m[-80:] for _, _, m, _ in sequence if isinstance(m, str)]
    latencies = [t for *_, t in sequence if isinstance(t, (int, float))]

    entropy = len(set(messages))
    delta = int(max(latencies) - min(latencies)) if latencies else 0
    avg_latency = int(mean(latencies)) if latencies else None

    # Find real email response (middle one)
    real_code = sequence[len(sequence)//2][1] if len(sequence) >= 3 else None

    # Catch-all heuristic
    fake_codes = [sequence[i][1] for i in range(len(sequence)) if i != len(sequence)//2]
    all_fake_ok = all(fc == 250 for fc in fake_codes if fc is not None)
    flat_entropy = entropy == 1
    low_delta = delta < 20  # very small difference

    is_catch_all = all_fake_ok or (flat_entropy and low_delta and real_code == 250)

    return {
        "entropy": entropy,
        "delta": delta,
        "avg_latency": avg_latency,
        "is_catch_all": is_catch_all,
        "real_code": real_code
    }


# ============================
# MAIN VERIFICATION FUNCTION
# ============================
def verify_email(email: str):
    result = {
        "email": email,
        "status": "undeliverable",
        "deliverable": False,
        "verification_score": 0.0,
        "mx_provider": "unknown",
        "mx_records": {"mx": []},
        "smtp": {"code": None, "message": None, "latency_ms": None},
        "details": {
            "email_type": None,
            "is_free_provider": None,
            "is_disposable": None,
            "is_role_based": None,
            "is_government": None,
            "is_catch_all": None,
            "reasoning": None
        }
    }

    if not EMAIL_REGEX.match(email or ""):
        result["details"]["reasoning"] = "bad_syntax"
        return result

    local, domain = email.split("@", 1)
    email_type = classify_email(local, domain)
    result["details"]["email_type"] = email_type
    result["details"]["is_free_provider"] = email_type == "free"
    result["details"]["is_disposable"] = email_type == "disposable"
    result["details"]["is_role_based"] = email_type == "role"
    result["details"]["is_government"] = email_type == "government"

    # MX Lookup
    try:
        mx_records = [str(r.exchange).rstrip('.') for r in dns.resolver.resolve(domain, "MX")]
        result["mx_records"]["mx"] = mx_records
        result["mx_provider"] = detect_mx_provider(mx_records[0])
    except Exception as e:
        result["details"]["reasoning"] = f"no_mx | {e}"
        return result

    # SMTP multi-probe
    seq = smtp_probe(mx_records[0], email)
    analysis = analyze_probes(seq)
    real_code = analysis["real_code"]

    result["details"]["is_catch_all"] = analysis["is_catch_all"]
    result["smtp"]["code"] = real_code
    result["smtp"]["latency_ms"] = analysis["avg_latency"]
    result["smtp"]["message"] = seq[len(seq)//2][2] if len(seq) >= 3 else None

    # Decision logic
    if real_code == 250:
        result["status"] = "deliverable"
        result["deliverable"] = True
        result["verification_score"] = 0.98 if not analysis["is_catch_all"] else 0.85
        result["details"]["reasoning"] = "250_ok"
    elif real_code == 550:
        result["status"] = "undeliverable"
        result["details"]["reasoning"] = "550_hard_fail"
    else:
        result["details"]["reasoning"] = "smtp_error"

    return result
