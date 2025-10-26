import re, dns.resolver, smtplib, time, random, string, logging
from statistics import mean
from concurrent.futures import ThreadPoolExecutor, as_completed

# =========================
# CONFIG
# =========================
EMAIL_REGEX = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")
TIMEOUT = 5
PAUSE_BETWEEN_PROBES = 0.1
MAX_WORKERS_DEFAULT = 20

FREE_PROVIDERS = {
    "gmail.com","yahoo.com","outlook.com","hotmail.com",
    "icloud.com","aol.com","zoho.com","yandex.com"
}
DISPOSABLE_PROVIDERS = {
    "tempmail.com","mailinator.com","guerrillamail.com","10minutemail.com"
}
ROLE_PREFIXES = {"info","admin","sales","support","contact","hr","help","team"}

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

# =========================
# UTILITIES
# =========================
def random_local(k=8):
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=k))

def detect_mx_provider(mx_host:str)->str:
    h = mx_host.lower()
    if "outlook" in h or "protection" in h:  return "microsoft365"
    if "google" in h or "aspmx" in h:        return "google"
    if "pphosted" in h:                      return "proofpoint"
    if "mimecast" in h:                      return "mimecast"
    if "barracuda" in h:                     return "barracuda"
    return "unknown"

def classify_email(local:str, domain:str):
    d = domain.lower()
    if d in FREE_PROVIDERS: return "free"
    if any(d.endswith(dp) for dp in DISPOSABLE_PROVIDERS): return "disposable"
    if d.endswith(".gov") or d.endswith(".gov.pk"): return "government"
    if any(local.lower().startswith(p) for p in ROLE_PREFIXES): return "role"
    return "business"

# =========================
# SMTP MULTI-PROBE
# =========================
def smtp_multi_probe(mx:str, target_email:str):
    """Sends 3 probes → fake1, real, fake2 to detect catch-all & timing"""
    domain = target_email.split("@")[1]
    seq = [
        f"{random_local()}@{domain}",
        target_email,
        f"{random_local()}@{domain}"
    ]
    results = []
    try:
        s = smtplib.SMTP(timeout=TIMEOUT)
        s.connect(mx)
        s.helo("gmail.com")
        s.mail("verify@bounso.com")

        for addr in seq:
            start = time.perf_counter()
            try:
                code, msg = s.rcpt(addr)
            except Exception as e:
                code, msg = None, str(e)
            latency = round((time.perf_counter() - start) * 1000, 2)
            msg = msg.decode() if isinstance(msg, bytes) else str(msg)
            results.append((addr, code, msg, latency))
            time.sleep(PAUSE_BETWEEN_PROBES)

        s.quit()
    except Exception as e:
        results.append(("__connect__", None, f"connect_error:{e}", None))
    return results

# =========================
# ANALYSIS
# =========================
def analyze_entropy_and_catchall(seq):
    codes = [c for _, c, *_ in seq if c is not None]
    msgs = [m[-80:] for *_, m, _ in seq if isinstance(m, str)]
    latencies = [t for *_, t in seq if isinstance(t, (int, float))]
    entropy = len(set(msgs))
    delta = int(max(latencies) - min(latencies)) if latencies else 0

    if len(codes) < 3:
        return {"entropy": entropy, "delta": delta, "is_catch_all": None, "real_code": None, "avg_latency": None}

    fake1, real, fake2 = codes[0], codes[1], codes[2]
    catch_all = (fake1 == 250 and fake2 == 250)
    flat_entropy = (entropy == 1)
    is_catch_all = catch_all or (flat_entropy and real == 250)

    return {
        "entropy": entropy,
        "delta": delta,
        "is_catch_all": is_catch_all,
        "real_code": real,
        "avg_latency": int(mean(latencies)) if latencies else None
    }

# =========================
# MAIN VERIFY FUNCTION
# =========================
def verify_email(email:str):
    result = {
        "email": email,
        "status": "undeliverable",
        "deliverable": False,
        "verification_score": 0.0,
        "mx_provider": "unknown",
        "smtp": {},
        "details": {}
    }

    try:
        if not EMAIL_REGEX.match(email or ""):
            result["details"]["reasoning"] = "bad_syntax"
            return result

        local, domain = email.split("@", 1)
        email_type = classify_email(local, domain)
        result["details"]["email_type"] = email_type

        # MX lookup
        mx_records = [str(r.exchange).rstrip('.') for r in dns.resolver.resolve(domain, "MX")]
        result["mx_provider"] = detect_mx_provider(mx_records[0])

        seq = smtp_multi_probe(mx_records[0], email)
        analysis = analyze_entropy_and_catchall(seq)

        result["smtp"]["seq"] = seq
        result["smtp"]["analysis"] = analysis

        code = analysis.get("real_code")
        if code == 250:
            result["status"] = "deliverable"
            result["deliverable"] = True
            result["verification_score"] = 0.98 if not analysis.get("is_catch_all") else 0.85
        elif code == 550:
            result["status"] = "undeliverable"
        else:
            result["status"] = "unknown"

        result["details"]["is_catch_all"] = analysis.get("is_catch_all")
        result["details"]["reasoning"] = f"smtp_code={code}"

        return result

    except Exception as e:
        result["details"]["reasoning"] = f"error:{e}"
        return result
